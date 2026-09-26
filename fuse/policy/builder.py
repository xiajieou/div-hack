"""Canonical Payment construction. The reader never touches this; the signer daemon checks it against the intent."""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal

from xrpl.models.transactions import Memo, Payment

from ..config import SOURCE_TAG, VendorRecord, xrp_to_drops

MEMO_TYPE_HEX = "fuse/audit".encode().hex().upper()
FORBIDDEN_FIELDS = ("Paths", "SendMax", "DeliverMin", "CredentialIDs", "DomainID", "AccountTxnID", "TicketSequence")


def invoice_id_hash(invoice_id: str) -> str:
    return hashlib.sha256(invoice_id.encode()).hexdigest().upper()


def memo_data(commitment: str, policy_hash: str) -> str:
    return json.dumps({"h": commitment, "p": policy_hash}, separators=(",", ":")).encode().hex().upper()


def decode_memo_commitment(tx: dict) -> str | None:
    for m in tx.get("Memos", []):
        memo = m.get("Memo", {})
        if memo.get("MemoType") == MEMO_TYPE_HEX:
            try:
                return json.loads(bytes.fromhex(memo["MemoData"]).decode())["h"]
            except Exception:
                return None
    return None


def build_payment(*, treasury: str, desk: str | None, vendor: VendorRecord, amount_xrp: Decimal, invoice_id: str,
                  commitment: str, policy_hash: str, fee_drops: int, sequence: int, last_ledger_sequence: int) -> dict:
    """Return the canonical transaction as XRPL JSON. desk=None means the multisig-only fallback (no delegation)."""
    kwargs = dict(
        account=treasury,
        destination=vendor.address,
        amount=xrp_to_drops(amount_xrp),
        invoice_id=invoice_id_hash(invoice_id),
        memos=[Memo(memo_type=MEMO_TYPE_HEX, memo_data=memo_data(commitment, policy_hash))],
        source_tag=SOURCE_TAG,
        fee=str(fee_drops),
        sequence=sequence,
        last_ledger_sequence=last_ledger_sequence,
        flags=0,
        signing_pub_key="",
    )
    if desk:
        kwargs["delegate"] = desk
    if vendor.destination_tag is not None:
        kwargs["destination_tag"] = vendor.destination_tag
    return Payment(**kwargs).to_xrpl()


def strip_signatures(tx: dict) -> dict:
    return {k: v for k, v in tx.items() if k not in ("Signers", "TxnSignature")}


def same_transaction(built: dict, returned: dict) -> tuple[bool, str]:
    """Field-by-field equality of the signing payload (everything except signatures)."""
    a, b = strip_signatures(built), strip_signatures(returned)
    if a == b:
        return True, "identical"
    diff = sorted(set(a) ^ set(b)) + [k for k in a if k in b and a[k] != b[k]]
    return False, f"fields differ: {diff}"
