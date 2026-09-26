"""SignerDaemon: the agent's trusted signer.

It is the reader's only interface. It never runs a model. It holds the agent key, remembers every intent the reader
created (keyed by a random nonce), forwards each intent to the policy service, and signs a transaction only when
that transaction matches an outstanding intent field by field. A compromised policy service can hand it anything it
likes; it will sign only what the reader actually asked for.

The daemon has its own read-only vendor directory (name -> address). The policy service has the authoritative
allowlist. Both must agree for a payment to happen: that is the point of two boundaries.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable, Dict, Optional

from xrpl.models.transactions import Payment
from xrpl.transaction import sign
from xrpl.wallet import Wallet

from ..config import xrp_to_drops
from ..policy.builder import FORBIDDEN_FIELDS, invoice_id_hash
from ..policy.rules import Intent


@dataclass
class Refusal(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass
class IntentRecord:
    intent: Intent
    settled: bool = False
    signatures_issued: int = 0


class SignerDaemon:
    def __init__(self, agent_wallet: Wallet, treasury: str, desk: Optional[str], vendor_directory: Dict[str, str],
                 fee_cap_drops: int, forward: Callable[[Intent], object]) -> None:
        self._wallet = agent_wallet                     # never leaves this object
        self.address = agent_wallet.classic_address
        self.treasury = treasury
        self.desk = desk
        self.directory = dict(vendor_directory)         # read-only copy
        self.fee_cap_drops = fee_cap_drops
        self._forward = forward
        self.intents: Dict[str, IntentRecord] = {}
        self.refusals: list = []

    # ----- reader-facing -----
    def register(self, intent: Intent) -> str:
        """Store the intent under a fresh nonce, forward it to the policy service, return the nonce."""
        nonce = secrets.token_hex(8)
        intent.nonce = nonce
        self.intents[nonce] = IntentRecord(intent)
        self._forward(intent)
        return nonce

    def add_vendor(self, name: str, address: str) -> None:
        """Admin path only: the daemon's directory is updated alongside the policy allowlist, and logged there."""
        self.directory[name] = address

    # ----- policy-facing -----
    def sign(self, tx: dict, nonce: str) -> dict:
        rec = self.intents.get(nonce)
        if rec is None:
            self._refuse(nonce, "unknown nonce")
        if rec.settled:
            self._refuse(nonce, "intent already settled")
        it = rec.intent
        checks = [
            (tx.get("TransactionType") == "Payment", "not a Payment"),
            (tx.get("Account") == self.treasury, "Account is not the treasury"),
            (tx.get("Delegate") == self.desk, "Delegate is not the desk account"),
            (tx.get("Destination") == self.directory.get(it.vendor), f"Destination does not match my record for {it.vendor}"),
            (tx.get("Amount") == xrp_to_drops(Decimal(it.amount)), f"Amount {tx.get('Amount')} != intent {it.amount} XRP"),
            (tx.get("InvoiceID") == invoice_id_hash(it.invoice_id), "InvoiceID does not hash the intent's invoice"),
            (tx.get("Flags", 0) == 0, f"Flags must be 0, got {tx.get('Flags')}"),
            (int(tx.get("Fee", "0")) <= self.fee_cap_drops, f"Fee {tx.get('Fee')} over cap {self.fee_cap_drops}"),
            (tx.get("SigningPubKey", "") == "", "SigningPubKey must be empty for multisign"),
            (not any(f in tx for f in FORBIDDEN_FIELDS), f"forbidden field present: {[f for f in FORBIDDEN_FIELDS if f in tx]}"),
            (not tx.get("Signers"), "transaction already carries signatures"),
        ]
        for ok, why in checks:
            if not ok:
                self._refuse(nonce, why)
        rec.signatures_issued += 1
        signed = sign(Payment.from_xrpl(tx), self._wallet, multisign=True)
        return signed.to_xrpl()

    def settle(self, nonce: str) -> None:
        if nonce in self.intents:
            self.intents[nonce].settled = True

    def _refuse(self, nonce: str, why: str) -> None:
        self.refusals.append({"nonce": nonce, "reason": why})
        raise Refusal(f"signer daemon refused: {why}")
