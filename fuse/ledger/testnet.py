"""TestnetLedger: the same interface as LocalLedger, backed by a public XRP Ledger test network via xrpl-py.

Defaults to devnet: PermissionDelegationV1_1 is enabled there and not on testnet (a DelegateSet on testnet returns
temDISABLED, checked Sep 26 2026). Credentials are enabled on both.

Fallback if the delegation amendment is not enabled on the network you point at: pass delegation=False to
the demo. The desk account then holds the funds itself (Account = desk, no Delegate field). You lose the
type restriction and keep everything else; say so on stage.
"""
from __future__ import annotations

import time
from typing import Dict, Optional

from xrpl.clients import JsonRpcClient
from xrpl.models.requests import AccountInfo, AccountObjects, Ledger, Tx
from xrpl.models.transactions import (AccountSet, CredentialAccept, CredentialCreate, DelegateSet, Payment,
                                      SignerListSet, TicketCreate)
from xrpl.models.transactions.transaction import Transaction
from xrpl.transaction import submit as submit_signed
from xrpl.wallet import Wallet, generate_faucet_wallet

from .local import Result

TESTNET_RPC = "https://s.altnet.rippletest.net:51234"
DEVNET_RPC = "https://s.devnet.rippletest.net:51234"
EXPLORER = {TESTNET_RPC: "https://testnet.xrpl.org", DEVNET_RPC: "https://devnet.xrpl.org"}

_MODELS = {"Payment": Payment, "DelegateSet": DelegateSet, "SignerListSet": SignerListSet, "AccountSet": AccountSet,
           "TicketCreate": TicketCreate, "CredentialCreate": CredentialCreate, "CredentialAccept": CredentialAccept}


def model_from_dict(tx: dict) -> Transaction:
    cls = _MODELS.get(tx["TransactionType"])
    if cls is None:
        raise ValueError(f"unsupported transaction type {tx['TransactionType']}")
    return cls.from_xrpl(tx)


class TestnetLedger:
    def __init__(self, rpc_url: str = DEVNET_RPC) -> None:
        self.client = JsonRpcClient(rpc_url)
        self.rpc_url = rpc_url
        self.explorer = EXPLORER.get(rpc_url, "")
        self.history = []

    def faucet_wallet(self) -> Wallet:
        w = generate_faucet_wallet(self.client, debug=False)
        time.sleep(1)  # the faucet is rate limited; be polite
        return w

    def fund(self, address: str, drops: int) -> None:
        # Funding on testnet happens through faucet_wallet(); this keeps the interface identical.
        return None

    def next_sequence(self, address: str) -> int:
        r = self.client.request(AccountInfo(account=address, ledger_index="current")).result
        return r["account_data"]["Sequence"]

    def current_ledger_index(self) -> int:
        r = self.client.request(Ledger(ledger_index="validated")).result
        return r["ledger_index"]

    def balance_xrp(self, address: str) -> str:
        r = self.client.request(AccountInfo(account=address, ledger_index="validated")).result
        return f"{int(r['account_data']['Balance']) / 1_000_000:.6f}"

    def submit(self, tx: dict, wait_s: int = 60) -> Result:
        """Submit an already signed transaction (single or multisigned) and return the ledger's result code.

        tef, tem, tel and ter results never reach a validated ledger (the spike saw tefBAD_QUORUM, temINVALID and
        terNO_DELEGATE_PERMISSION), so the server's answer is returned at once. tes and tec results are recorded:
        wait until validated, until LastLedgerSequence passes, or for wait_s seconds if there is none.
        """
        model = model_from_dict(tx)
        h = model.get_hash()
        res = submit_signed(model, self.client).result
        code = res.get("engine_result") or res.get("error", "unknown")
        if code[:3] in ("tes", "tec"):
            r = self._wait_validated(h, code, tx.get("LastLedgerSequence"), wait_s)
        else:
            r = Result(code, h, False, res.get("engine_result_message") or res.get("error_message", ""))
        self.history.append({"result": r.engine_result, "hash": r.hash, "type": tx.get("TransactionType"),
                             "account": tx.get("Account"), "delegate": tx.get("Delegate")})
        return r

    def _wait_validated(self, h: str, prelim: str, last_ledger: Optional[int], wait_s: int) -> Result:
        link = f"{self.explorer}/transactions/{h}"
        deadline = time.time() + wait_s
        while True:
            time.sleep(1)
            t = self.client.request(Tx(transaction=h)).result
            if t.get("validated"):
                return Result(t["meta"]["TransactionResult"], h, True, link)
            if last_ledger is not None:
                if self.current_ledger_index() > last_ledger:
                    return Result(prelim, h, False, f"not validated before LastLedgerSequence {last_ledger}")
            elif time.time() > deadline:
                return Result(prelim, h, False, f"not validated after {wait_s}s; check {link}")

    def credentials(self, address: str) -> list:
        """Credential entries on this account, the same shape LocalLedger.credentials returns. Every page."""
        found = []
        marker = None
        while True:
            kwargs = {"marker": marker} if marker else {}
            result = self.client.request(AccountObjects(account=address, ledger_index="validated", type="credential", **kwargs)).result
            found.extend(o for o in result["account_objects"] if o.get("LedgerEntryType") == "Credential")
            marker = result.get("marker")
            if not marker:
                return found

    def describe(self, address: str) -> str:
        info = self.client.request(AccountInfo(account=address, ledger_index="validated")).result["account_data"]
        flags = info.get("Flags", 0)
        master_disabled = bool(flags & 0x00100000)  # lsfDisableMaster
        lines = [f"{address}  balance {int(info['Balance']) / 1_000_000:.6f} XRP  sequence {info['Sequence']}  master {'DISABLED' if master_disabled else 'enabled'}"]
        objs = self.client.request(AccountObjects(account=address, ledger_index="validated")).result.get("account_objects", [])
        for o in objs:
            t = o.get("LedgerEntryType")
            if t == "SignerList":
                entries = ", ".join(f"{e['SignerEntry']['Account'][:8]}… (w{e['SignerEntry']['SignerWeight']})" for e in o.get("SignerEntries", []))
                lines.append(f"  signer list: quorum {o.get('SignerQuorum')}, entries {entries}")
            elif t == "Delegate":
                # the same entry is listed for the granting account and the delegate; only the granter owns it
                perms = sorted(p["Permission"]["PermissionValue"] for p in o.get("Permissions", []))
                if o.get("Account") == address:
                    lines.append(f"  delegation → {o.get('Authorize', '')[:8]}…: {perms}")
                else:
                    lines.append(f"  acts for {o.get('Account', '')[:8]}… (delegate): {perms}")
        lines.append(f"  explorer: {self.explorer}/accounts/{address}")
        return "\n".join(lines)
