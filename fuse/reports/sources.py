"""Where the reports get their data: account facts and transaction history, from the local ledger or from testnet/devnet.

Both modes return the same shapes, so the report logic never knows which ledger it read.

    facts   = {"address", "balance_drops", "regular_key", "master_disabled", "quorum", "signers", "delegations"}
    history = [{"type", "account", "delegate", "destination", "result", "hash", "amount_drops", "amount"}, ...]

The local ledger lives in memory, so local mode builds a fresh one: setup, the three clean invoices through the
policy service, and optionally the stolen-keys attack (both keys, paying the attacker straight to the ledger).
"""
from __future__ import annotations

import json
import os
from decimal import Decimal
from typing import Dict, List, Optional, Set

from xrpl.models.transactions import Payment
from xrpl.transaction import multisign, sign
from xrpl.wallet import Wallet

from ..audit import AuditChain
from ..config import VendorRecord, default_policy, drops_to_xrp
from ..ledger.local import LocalLedger
from ..policy.builder import build_payment
from ..policy.service import MULTISIGN_FEE_DROPS, PolicyService
from ..reader.reader import INVOICES, naive_extract
from ..setup import KeyRing, run_setup
from ..signer.daemon import SignerDaemon

LSF_DISABLE_MASTER = 0x00100000
ACCOUNTS_FILE = os.path.join("env", "accounts.json")
CLEAN_INVOICES = ["inv_2201_verdant.txt", "inv_7734_harbor.txt", "inv_0092_lumen.txt"]


def show_amount(amount) -> str:
    if isinstance(amount, str):
        return f"{drops_to_xrp(amount)} XRP"
    if isinstance(amount, dict):
        return f"{amount.get('value')} {amount.get('currency')}"
    return "-"


def _entry(type_, account, delegate, destination, result, hash_, amount) -> dict:
    return {"type": type_, "account": account, "delegate": delegate, "destination": destination or "",
            "result": result, "hash": hash_, "amount_drops": int(amount) if isinstance(amount, str) else 0,
            "amount": show_amount(amount)}


def log_hashes(audit_rows: List[dict]) -> Set[str]:
    """Transaction hashes the audit log has a result row for. Accepts AuditChain.dump() rows."""
    return {r["tx_hash"] for r in audit_rows if r.get("kind") == "result" and r.get("tx_hash")}


# ----- local -----
class LocalWorld:
    def __init__(self, attack: bool) -> None:
        policy = default_policy()
        self.ledger = LocalLedger()
        ring = KeyRing.local(self.ledger, policy)
        run_setup(self.ledger, ring)
        # the prototype pays from the account it calls treasury, so that account plays the spend role here,
        # next to a separate treasury that nothing is delegated from
        spend, desk = ring.treasury.classic_address, ring.desk.classic_address
        treasury = Wallet.create().classic_address
        self.ledger.fund(treasury, 1_000_000_000)
        self.addresses = {"treasury": treasury, "spend": spend, "desk": desk}
        self.audit = AuditChain(policy.hash())
        service = PolicyService(policy, ring.policy, self.ledger, spend, desk, self.audit)
        daemon = SignerDaemon(ring.agent, spend, desk, {n: v.address for n, v in policy.allowlist.items()},
                              policy.fee_cap_drops, forward=service.handle_intent)
        service.attach_daemon(daemon)
        for name in CLEAN_INVOICES:
            daemon.register(naive_extract(INVOICES[name])[0])
        if attack:
            self._stolen_keys(ring, spend, desk, policy.hash())

    def _stolen_keys(self, ring: KeyRing, spend: str, desk: str, policy_hash: str) -> None:
        attacker = VendorRecord("attacker", ring.attacker.classic_address, "??")
        for n in range(1, 4):
            tx = Payment.from_xrpl(build_payment(
                treasury=spend, desk=desk, vendor=attacker, amount_xrp=Decimal("100"), invoice_id=f"STOLEN-{n}",
                commitment="00" * 32, policy_hash=policy_hash, fee_drops=MULTISIGN_FEE_DROPS,
                sequence=self.ledger.next_sequence(spend), last_ledger_sequence=self.ledger.current_ledger_index() + 40))
            signed = multisign(tx, [sign(tx, ring.agent, multisign=True), sign(tx, ring.policy, multisign=True)])
            if not self.ledger.submit(signed.to_xrpl()).ok:
                break

    def facts(self, address: str) -> dict:
        a = self.ledger.account(address)
        return {"address": address, "balance_drops": a.balance_drops, "regular_key": None,
                "master_disabled": a.master_disabled, "quorum": a.signer_quorum, "signers": dict(a.signer_entries),
                "delegations": {d: sorted(p) for d, p in a.delegations.items()}}

    def history(self, address: str) -> List[dict]:
        return [_entry(h["type"], h["account"], h["delegate"], h["destination"], h["result"], h["hash"], h["amount"])
                for h in self.ledger.history if address in (h["account"], h["destination"])]

    def log_hashes(self) -> Set[str]:
        return log_hashes(self.audit.dump())


# ----- testnet / devnet -----
def load_addresses(overrides: Dict[str, Optional[str]]) -> Dict[str, str]:
    """env/accounts.json holds {"treasury": "r...", "spend": "r...", "desk": "r..."}; flags override it."""
    found = {}
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE) as f:
            found = json.load(f)
    found.update({k: v for k, v in overrides.items() if v})
    missing = [k for k in ("treasury", "spend", "desk") if not found.get(k)]
    if missing:
        raise SystemExit(f"missing addresses for {missing}: run setup (writes {ACCOUNTS_FILE}) or pass --{missing[0]}")
    return found


class Network:
    """XRPL testnet or devnet. Permission Delegation is enabled on devnet and, as of Sep 26 2026, not on testnet."""

    def __init__(self, mode: str) -> None:
        from xrpl.clients import JsonRpcClient
        from ..ledger.testnet import DEVNET_RPC, EXPLORER, TESTNET_RPC
        rpc = {"testnet": TESTNET_RPC, "devnet": DEVNET_RPC}[mode]
        self.client = JsonRpcClient(rpc)
        self.explorer = EXPLORER[rpc]

    def _request(self, req) -> dict:
        result = self.client.request(req).result
        if "error" in result:
            raise SystemExit(f"{req.method} {getattr(req, 'account', '')}: {result['error']} {result.get('error_message', '')}")
        return result

    def facts(self, address: str) -> dict:
        from xrpl.models.requests import AccountInfo, AccountObjects
        data = self._request(AccountInfo(account=address, ledger_index="validated"))["account_data"]
        facts = {"address": address, "balance_drops": int(data["Balance"]), "regular_key": data.get("RegularKey"),
                 "master_disabled": bool(data.get("Flags", 0) & LSF_DISABLE_MASTER), "quorum": 0, "signers": {},
                 "delegations": {}}
        marker = None
        while True:
            r = self._request(AccountObjects(account=address, ledger_index="validated", marker=marker))
            for o in r.get("account_objects", []):
                if o.get("LedgerEntryType") == "SignerList":
                    facts["quorum"] = o["SignerQuorum"]
                    facts["signers"] = {e["SignerEntry"]["Account"]: e["SignerEntry"]["SignerWeight"] for e in o["SignerEntries"]}
                elif o.get("LedgerEntryType") == "Delegate" and o.get("Account") == address:
                    facts["delegations"][o["Authorize"]] = sorted(p["Permission"]["PermissionValue"] for p in o.get("Permissions", []))
            marker = r.get("marker")
            if not marker:
                return facts

    def history(self, address: str) -> List[dict]:
        from xrpl.models.requests import AccountTx
        out, marker = [], None
        while True:
            r = self._request(AccountTx(account=address, forward=True, marker=marker))
            for e in r.get("transactions", []):
                if not e.get("validated"):
                    continue
                tx, meta = e.get("tx_json") or e.get("tx", {}), e.get("meta", {})
                amount = meta.get("delivered_amount", tx.get("DeliverMax", tx.get("Amount")))
                out.append(_entry(tx.get("TransactionType"), tx.get("Account"), tx.get("Delegate"), tx.get("Destination"),
                                  meta.get("TransactionResult"), e.get("hash") or tx.get("hash"), amount))
            marker = r.get("marker")
            if not marker:
                return out
