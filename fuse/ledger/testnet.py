"""TestnetLedger: the same interface as LocalLedger, backed by the XRP Ledger test network via xrpl-py.

This file was written against xrpl-py 5.2 but could not be executed in the sandbox that produced it (no network),
so the first run IS the S0 spike from the roadmap: get one delegated, multisigned Payment to tesSUCCESS, and record
the exact result codes the ledger returns for the failure beats.

Fallback if the delegation amendment is not enabled on the network you point at: pass delegation=False to
the demo. The desk account then holds the funds itself (Account = desk, no Delegate field). You lose the
type restriction and keep everything else; say so on stage.
"""
from __future__ import annotations

import time
from typing import Dict

from xrpl.clients import JsonRpcClient
from xrpl.models.requests import AccountInfo, AccountObjects, Ledger
from xrpl.models.transactions import AccountSet, DelegateSet, Payment, SignerListSet
from xrpl.models.transactions.transaction import Transaction
from xrpl.transaction import submit_and_wait
from xrpl.transaction import XRPLReliableSubmissionException
from xrpl.wallet import Wallet, generate_faucet_wallet

from .local import Result

TESTNET_RPC = "https://s.altnet.rippletest.net:51234"
DEVNET_RPC = "https://s.devnet.rippletest.net:51234"
EXPLORER = {TESTNET_RPC: "https://testnet.xrpl.org", DEVNET_RPC: "https://devnet.xrpl.org"}

_MODELS = {"Payment": Payment, "DelegateSet": DelegateSet, "SignerListSet": SignerListSet, "AccountSet": AccountSet}


def model_from_dict(tx: dict) -> Transaction:
    cls = _MODELS.get(tx["TransactionType"])
    if cls is None:
        raise ValueError(f"unsupported transaction type {tx['TransactionType']}")
    return cls.from_xrpl(tx)


class TestnetLedger:
    def __init__(self, rpc_url: str = TESTNET_RPC) -> None:
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

    def submit(self, tx: dict) -> Result:
        """Submit an already signed transaction (single or multisigned) and wait for a validated result."""
        model = model_from_dict(tx)
        try:
            resp = submit_and_wait(model, self.client, autofill=False, check_fee=False)
            res = resp.result
            code = res.get("meta", {}).get("TransactionResult", res.get("engine_result", "unknown"))
            h = res.get("hash", "")
            r = Result(code, h, bool(res.get("validated", False)), f"{self.explorer}/transactions/{h}" if h else "")
        except XRPLReliableSubmissionException as e:
            # tem/tef/tel results never reach a ledger; the exception message carries the engine result
            msg = str(e)
            code = next((tok for tok in msg.replace(":", " ").split() if tok[:3] in ("tef", "tem", "tel", "ter", "tec")), "tefFAILURE")
            r = Result(code, "", False, msg)
        self.history.append({"result": r.engine_result, "hash": r.hash, "type": tx.get("TransactionType"),
                             "account": tx.get("Account"), "delegate": tx.get("Delegate")})
        return r

    def credentials(self, address: str) -> list:
        """Credential entries with this account as subject, the same shape LocalLedger.credentials returns."""
        objs = self.client.request(AccountObjects(account=address, ledger_index="validated", type="credential")).result.get("account_objects", [])
        return [o for o in objs if o.get("LedgerEntryType") == "Credential"]

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
                perms = sorted(p["Permission"]["PermissionValue"] for p in o.get("Permissions", []))
                lines.append(f"  delegation → {o.get('Authorize', '')[:8]}…: {perms}")
        lines.append(f"  explorer: {self.explorer}/accounts/{address}")
        return "\n".join(lines)
