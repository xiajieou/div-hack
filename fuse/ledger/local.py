"""LocalLedger: an in-process stand-in for the XRP Ledger.

It is not a simulation of intent; it checks real signatures. Every submitted transaction is verified with
xrpl-py's binary codec and keypair verification exactly the way a validator would check it:
  - a multisigned transaction must carry valid signatures from signer-list members whose weights reach the quorum
  - a single-signed transaction must be signed by the account's master key, and that key must not be disabled
  - a transaction carrying a Delegate field must match a permission the delegating account granted
  - sequence numbers, balances and fees behave like the real thing (tec results still claim the fee)

Result codes use the real XRPL names where they exist (tesSUCCESS, tefBAD_QUORUM, tefBAD_SIGNATURE, tefMASTER_DISABLED,
tefPAST_SEQ, tecUNFUNDED_PAYMENT) and the XLS-75 draft's name for a delegated transaction outside its permission
(tecNO_DELEGATE_PERMISSION). Confirm the last one against the test network in the S0 spike.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from xrpl.core.binarycodec import encode, encode_for_multisigning, encode_for_signing
from xrpl.core.keypairs import derive_classic_address, is_valid_message

RESERVE_DROPS = 1_000_000  # 1 XRP base reserve, kept simple


@dataclass
class Account:
    address: str
    balance_drops: int = 0
    sequence: int = 1
    master_disabled: bool = False
    signer_quorum: int = 0
    signer_entries: Dict[str, int] = field(default_factory=dict)      # signer address -> weight
    delegations: Dict[str, Set[str]] = field(default_factory=dict)    # delegate address -> permission values


@dataclass
class Result:
    engine_result: str
    hash: str
    validated: bool
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.engine_result == "tesSUCCESS"


def tx_hash(tx: dict) -> str:
    blob = encode(tx)
    return hashlib.sha512(b"TXN\x00" + bytes.fromhex(blob)).digest()[:32].hex().upper()


class LocalLedger:
    def __init__(self) -> None:
        self.accounts: Dict[str, Account] = {}
        self.ledger_index = 1000
        self.history: List[dict] = []

    # ----- setup helpers (funding is the only thing that does not go through a signed transaction) -----
    def fund(self, address: str, drops: int) -> None:
        acct = self.accounts.setdefault(address, Account(address))
        acct.balance_drops += drops

    def account(self, address: str) -> Account:
        if address not in self.accounts:
            raise KeyError(f"unknown account {address}")
        return self.accounts[address]

    def next_sequence(self, address: str) -> int:
        return self.account(address).sequence

    def current_ledger_index(self) -> int:
        return self.ledger_index

    def balance_xrp(self, address: str) -> str:
        return f"{self.account(address).balance_drops / 1_000_000:.6f}"

    # ----- submission -----
    def submit(self, tx: dict) -> Result:
        """tx is a fully signed transaction in XRPL JSON form (as produced by xrpl-py's to_xrpl())."""
        self.ledger_index += 1
        try:
            h = tx_hash(tx)
        except Exception as e:  # unencodable transaction never reaches a ledger
            return self._record(Result("temMALFORMED", "", False, f"could not serialize: {e}"), tx)

        account_addr = tx.get("Account")
        delegate_addr = tx.get("Delegate")
        if account_addr not in self.accounts:
            return self._record(Result("terNO_ACCOUNT", h, False, "unknown Account"), tx)
        account = self.accounts[account_addr]
        signing_addr = delegate_addr or account_addr
        if signing_addr not in self.accounts:
            return self._record(Result("terNO_ACCOUNT", h, False, "unknown Delegate"), tx)
        signing_account = self.accounts[signing_addr]
        fee_payer = signing_account

        # 1. signatures: who actually signed, and does that satisfy the signing account's rules?
        self._last_note = "signature check failed"
        sig_check = self._check_signatures(tx, signing_account)
        if sig_check is not None:
            return self._record(Result(sig_check, h, False, self._last_note), tx)

        # 2. sequence and last ledger
        seq = tx.get("Sequence")
        if seq != account.sequence:
            code = "tefPAST_SEQ" if (seq or 0) < account.sequence else "terPRE_SEQ"
            return self._record(Result(code, h, False, f"expected sequence {account.sequence}, got {seq}"), tx)
        lls = tx.get("LastLedgerSequence")
        if lls is not None and lls < self.ledger_index:
            return self._record(Result("tefMAX_LEDGER", h, False, "LastLedgerSequence already passed"), tx)

        fee = int(tx.get("Fee", "0"))
        if fee_payer.balance_drops < fee:
            return self._record(Result("terINSUF_FEE_B", h, False, "fee payer cannot cover the fee"), tx)

        # 3. delegation scope: a Delegate may only do what the Account granted
        if delegate_addr:
            granted = account.delegations.get(delegate_addr, set())
            if tx.get("TransactionType") not in granted:
                # tec: the transaction is in a validated ledger, the fee is claimed, the intent failed
                fee_payer.balance_drops -= fee
                account.sequence += 1
                return self._record(Result("tecNO_DELEGATE_PERMISSION", h, True,
                                           f"delegation to {delegate_addr[:8]} covers {sorted(granted) or 'nothing'}"), tx)

        # 4. apply
        fee_payer.balance_drops -= fee
        account.sequence += 1
        code = self._apply(tx, account)
        return self._record(Result(code, h, True), tx)

    # ----- internals -----
    def _check_signatures(self, tx: dict, signing_account: Account) -> Optional[str]:
        if tx.get("Signers"):
            if signing_account.signer_quorum == 0:
                return "tefNOT_MULTI_SIGNING"
            base = {k: v for k, v in tx.items() if k != "Signers"}
            weight = 0
            seen = set()
            for entry in tx["Signers"]:
                s = entry["Signer"]
                acct = s["Account"]
                if acct in seen:
                    return "tefBAD_SIGNATURE"
                seen.add(acct)
                if acct not in signing_account.signer_entries:
                    return "tefBAD_SIGNATURE"
                if derive_classic_address(s["SigningPubKey"]) != acct:
                    return "tefBAD_SIGNATURE"
                payload = encode_for_multisigning(base, acct)
                if not is_valid_message(bytes.fromhex(payload), bytes.fromhex(s["TxnSignature"]), s["SigningPubKey"]):
                    return "tefBAD_SIGNATURE"
                weight += signing_account.signer_entries[acct]
            if weight < signing_account.signer_quorum:
                self._last_note = f"{weight} of {signing_account.signer_quorum} required signature weight"
                return "tefBAD_QUORUM"
            return None
        # single signature: must be the account's master key, and it must be enabled
        pub = tx.get("SigningPubKey", "")
        sig = tx.get("TxnSignature")
        if not pub or not sig:
            return "tefBAD_SIGNATURE"
        if derive_classic_address(pub) != signing_account.address:
            return "tefBAD_AUTH"
        if signing_account.master_disabled:
            return "tefMASTER_DISABLED"
        payload = encode_for_signing({k: v for k, v in tx.items() if k != "TxnSignature"})
        if not is_valid_message(bytes.fromhex(payload), bytes.fromhex(sig), pub):
            return "tefBAD_SIGNATURE"
        return None

    def _apply(self, tx: dict, account: Account) -> str:
        t = tx["TransactionType"]
        if t == "Payment":
            amount = tx.get("Amount")
            if not isinstance(amount, str):
                return "tecPATH_DRY"  # issued currencies are not modeled locally
            drops = int(amount)
            if account.balance_drops - drops < RESERVE_DROPS:
                return "tecUNFUNDED_PAYMENT"
            dest = self.accounts.setdefault(tx["Destination"], Account(tx["Destination"]))
            account.balance_drops -= drops
            dest.balance_drops += drops
            return "tesSUCCESS"
        if t == "DelegateSet":
            perms = {p["Permission"]["PermissionValue"] for p in tx.get("Permissions", [])}
            if perms:
                account.delegations[tx["Authorize"]] = perms
            else:
                account.delegations.pop(tx["Authorize"], None)
            return "tesSUCCESS"
        if t == "SignerListSet":
            quorum = tx.get("SignerQuorum", 0)
            if quorum == 0:
                account.signer_quorum = 0
                account.signer_entries = {}
            else:
                account.signer_quorum = quorum
                account.signer_entries = {e["SignerEntry"]["Account"]: e["SignerEntry"]["SignerWeight"] for e in tx["SignerEntries"]}
            return "tesSUCCESS"
        if t == "AccountSet":
            if tx.get("SetFlag") == 4:  # asfDisableMaster
                if account.signer_quorum == 0:
                    return "tecNO_ALTERNATIVE_KEY"
                account.master_disabled = True
            return "tesSUCCESS"
        return "temUNKNOWN"

    def _record(self, r: Result, tx: dict) -> Result:
        self.history.append({"result": r.engine_result, "hash": r.hash, "type": tx.get("TransactionType"),
                             "account": tx.get("Account"), "delegate": tx.get("Delegate"), "ledger": self.ledger_index})
        return r

    # ----- explorer-style view -----
    def describe(self, address: str) -> str:
        a = self.account(address)
        lines = [f"{address}  balance {self.balance_xrp(address)} XRP  sequence {a.sequence}  master {'DISABLED' if a.master_disabled else 'enabled'}"]
        if a.signer_quorum:
            lines.append(f"  signer list: quorum {a.signer_quorum}, entries " + ", ".join(f"{k[:8]}… (w{v})" for k, v in a.signer_entries.items()))
        for d, perms in a.delegations.items():
            lines.append(f"  delegation → {d[:8]}…: {sorted(perms)}")
        return "\n".join(lines)
