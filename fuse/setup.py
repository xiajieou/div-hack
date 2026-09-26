"""Account setup: the one-time transactions that give Fuse its shape.

  treasury --DelegateSet(Payment)--> desk
  desk: SignerListSet(agent w1, policy w1, quorum 2), then AccountSet(asfDisableMaster)

Every step is a real signed transaction on the chosen ledger (local or testnet), so the same code proves the setup
in both modes. The treasury's master key is used here and then never again.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from xrpl.models.transactions import AccountSet, AccountSetAsfFlag, DelegateSet, SignerListSet
from xrpl.models.transactions.delegate_set import Permission
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import sign
from xrpl.wallet import Wallet

from .config import Policy
from .ledger.local import LocalLedger, Result

SETUP_FEE = "12"


@dataclass
class KeyRing:
    treasury: Wallet
    desk: Wallet
    agent: Wallet          # lives inside the signer daemon
    policy: Wallet         # lives inside the policy service
    vendors: Dict[str, Wallet] = field(default_factory=dict)
    attacker: Wallet | None = None
    northwind: Wallet | None = None     # a vendor not on the allowlist yet (beat 7)
    setup_log: List[str] = field(default_factory=list)

    @classmethod
    def local(cls, ledger: LocalLedger, policy: Policy) -> "KeyRing":
        ring = cls(Wallet.create(), Wallet.create(), Wallet.create(), Wallet.create())
        ring.attacker = Wallet.create()
        ring.northwind = Wallet.create()
        ledger.fund(ring.treasury.classic_address, 250_000_000)   # 250 XRP
        ledger.fund(ring.desk.classic_address, 20_000_000)        # 20 XRP for reserves and fees
        ledger.fund(ring.attacker.classic_address, 5_000_000)
        ledger.fund(ring.northwind.classic_address, 5_000_000)
        for name in policy.allowlist:
            w = Wallet.create()
            ring.vendors[name] = w
            ledger.fund(w.classic_address, 5_000_000)
            policy.allowlist[name].address = w.classic_address
        return ring

    @classmethod
    def testnet(cls, ledger, policy: Policy) -> "KeyRing":
        ring = cls(ledger.faucet_wallet(), ledger.faucet_wallet(), Wallet.create(), Wallet.create())
        ring.attacker = ledger.faucet_wallet()
        ring.northwind = ledger.faucet_wallet()
        for name in policy.allowlist:
            w = ledger.faucet_wallet()
            ring.vendors[name] = w
            policy.allowlist[name].address = w.classic_address
        return ring


def _single_sign(tx_model, wallet: Wallet, sequence: int, last_ledger: int) -> dict:
    tx = tx_model.__class__.from_dict({**tx_model.to_dict(), "fee": SETUP_FEE, "sequence": sequence, "last_ledger_sequence": last_ledger})
    return sign(tx, wallet).to_xrpl()


def run_setup(ledger, ring: KeyRing, delegation: bool = True) -> List[Result]:
    """Perform the setup transactions. Returns the results in order so the demo can print them."""
    results: List[Result] = []
    lls = ledger.current_ledger_index() + 200

    if delegation:
        ds = DelegateSet(account=ring.treasury.classic_address, authorize=ring.desk.classic_address,
                         permissions=[Permission(permission_value="Payment")])
        r = ledger.submit(_single_sign(ds, ring.treasury, ledger.next_sequence(ring.treasury.classic_address), lls))
        ring.setup_log.append(f"DelegateSet treasury→desk (Payment only): {r.engine_result}")
        results.append(r)

    sls = SignerListSet(account=ring.desk.classic_address, signer_quorum=2,
                        signer_entries=[SignerEntry(account=ring.agent.classic_address, signer_weight=1),
                                        SignerEntry(account=ring.policy.classic_address, signer_weight=1)])
    r = ledger.submit(_single_sign(sls, ring.desk, ledger.next_sequence(ring.desk.classic_address), lls))
    ring.setup_log.append(f"SignerListSet on desk (agent + policy, quorum 2): {r.engine_result}")
    results.append(r)

    aset = AccountSet(account=ring.desk.classic_address, set_flag=AccountSetAsfFlag.ASF_DISABLE_MASTER)
    r = ledger.submit(_single_sign(aset, ring.desk, ledger.next_sequence(ring.desk.classic_address), lls))
    ring.setup_log.append(f"AccountSet disable desk master key: {r.engine_result}")
    results.append(r)
    return results


def revoke_delegation(ledger, ring: KeyRing) -> Result:
    """The kill switch: one DelegateSet with no permissions removes the desk's authority."""
    lls = ledger.current_ledger_index() + 200
    ds = DelegateSet(account=ring.treasury.classic_address, authorize=ring.desk.classic_address, permissions=[])
    r = ledger.submit(_single_sign(ds, ring.treasury, ledger.next_sequence(ring.treasury.classic_address), lls))
    ring.setup_log.append(f"DelegateSet revoke: {r.engine_result}")
    return r
