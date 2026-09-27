"""PolicyService: holds the policy key, builds every transaction, countersigns, submits. Contains no model."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Dict, List, Optional, Set

from xrpl.core.addresscodec import is_valid_classic_address
from xrpl.core.binarycodec import encode_for_multisigning
from xrpl.core.keypairs import derive_classic_address, is_valid_message
from xrpl.models.transactions import Payment
from xrpl.transaction import multisign, sign
from xrpl.wallet import Wallet

from ..audit import AuditChain, public_text
from ..budget import Budget, BudgetError
from ..config import Policy, VendorRecord, drops_to_xrp, xrp_to_drops
from .builder import build_payment, same_transaction, strip_signatures
from .credentials import vendor_has_accepted_credential
from .rules import Evaluation, Intent, evaluate

MULTISIGN_FEE_DROPS = 36        # base fee x (1 + 2 signers), rounded up
LAST_LEDGER_WINDOW = 40


@dataclass
class Outcome:
    status: str                       # paid | refused | parked | rejected_by_ledger | error
    intent: dict
    rules: List[dict] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    tx_hash: str = ""
    engine_result: str = ""
    message: str = ""
    commitment: str = ""


class PolicyService:
    def __init__(self, policy: Policy, policy_wallet: Wallet, ledger, treasury: str, desk: Optional[str], audit: AuditChain, registry: Optional[str] = None) -> None:
        self.policy = policy
        self._wallet = policy_wallet                    # never leaves this object
        self.address = policy_wallet.classic_address
        self.ledger = ledger
        self.treasury = treasury
        self.desk = desk                                # None = multisig-only fallback
        self.registry = registry
        self.audit = audit
        self.budget = Budget(int(xrp_to_drops(policy.daily_cap_xrp)), policy.per_hour_max_payments)
        self.paid_invoices: Set[str] = set()
        self.in_flight: Set[str] = set()
        self.parked: Dict[str, Intent] = {}            # nonce -> intent
        self.outcomes: Dict[str, Outcome] = {}         # nonce -> outcome
        self.memos_by_tx_hash: Dict[str, str] = {}
        self.daemon = None
        self._submit_lock = threading.Lock()

    def attach_daemon(self, daemon) -> None:
        self.daemon = daemon

    # ----- the pipeline -----
    def handle_intent(self, intent: Intent) -> Outcome:
        ev = evaluate(intent, self.policy, self.paid_invoices, self.in_flight,
                      drops_to_xrp(self.budget.committed_drops()), self.budget.payments_last_hour())
        rules = [{"rule": r.name, "ok": r.ok, "soft": r.soft, "note": r.note} for r in ev.rules]

        if ev.decision == "refuse":
            self.audit.refused(intent.public(), ev.failed)
            return self._done(intent, Outcome("refused", intent.public(), rules, ev.failed, message="No signature exists; nothing to submit."))

        if ev.decision == "park":
            self.parked[intent.nonce] = intent
            self.audit.parked(intent.public(), "unknown destination; waiting for a human to add the vendor")
            return self._done(intent, Outcome("parked", intent.public(), rules, message="Parked. A human must add the vendor; the intent then reruns."))

        amount = Decimal(intent.amount)
        vendor: VendorRecord = self.policy.allowlist[intent.vendor]
        if not vendor_has_accepted_credential(self.ledger, vendor.address, self.registry):
            failed = ["vendor holds an accepted registry credential"]
            rules.append({"rule": failed[0], "ok": False, "soft": False, "note": ""})
            self.audit.refused(intent.public(), failed)
            return self._done(intent, Outcome("refused", intent.public(), rules, failed, message="No signature exists; nothing to submit."))

        try:
            reservation = self.budget.reserve(int(xrp_to_drops(amount)))
        except BudgetError as e:
            failed = [f"atomic budget reservation: {e}"]
            self.audit.refused(intent.public(), failed)
            return self._done(intent, Outcome("refused", intent.public(), rules, failed, message="Refused at reservation time."))

        settled = False
        try:
            with self._submit_lock:                      # sequence assignment through submission, one at a time
                if intent.invoice_id in self.paid_invoices:
                    failed = ["duplicate invoice"]
                    self.audit.refused(intent.public(), failed)
                    return self._done(intent, Outcome("refused", intent.public(), rules, failed,
                                                      message="No signature exists; nothing to submit."))
                self.in_flight.add(intent.invoice_id)
                try:
                    sequence = self.ledger.next_sequence(self.treasury)
                    lls = self.ledger.current_ledger_index() + LAST_LEDGER_WINDOW
                    proposal = {"intent": intent.public(), "destination": vendor.address, "amount_drops": xrp_to_drops(amount),
                                "sequence": sequence, "rules": rules}
                    commitment = self.audit.commit_proposal(proposal)
                    built = build_payment(treasury=self.treasury, desk=self.desk, vendor=vendor, amount_xrp=amount,
                                          invoice_id=intent.invoice_id, commitment=commitment, policy_hash=self.policy.hash(),
                                          fee_drops=MULTISIGN_FEE_DROPS, sequence=sequence, last_ledger_sequence=lls)

                    # 1. the agent's signature, over exactly this transaction
                    try:
                        agent_signed = self.daemon.sign(built, intent.nonce)
                    except Exception as e:
                        failed = [public_text(str(e))]
                        self.audit.refused(intent.public(), failed, {"commitment": commitment})
                        return self._done(intent, Outcome("refused", intent.public(), rules, failed, commitment=commitment,
                                                          message="The signer daemon would not sign."))
                    same, why = same_transaction(built, agent_signed)
                    if not same or not self._agent_signature_valid(agent_signed):
                        failed = [f"returned transaction is not the one built: {why}"]
                        self.audit.refused(intent.public(), failed, {"commitment": commitment})
                        return self._done(intent, Outcome("refused", intent.public(), rules, failed, commitment=commitment))

                    # 2. our signature, then submit
                    base = Payment.from_xrpl(built)
                    policy_signed = sign(base, self._wallet, multisign=True)
                    combined = multisign(base, [Payment.from_xrpl(agent_signed), policy_signed]).to_xrpl()
                    result = self.ledger.submit(combined)
                    self.audit.append_result(commitment, result.hash, result.engine_result, public_text(result.message))

                    if result.ok:
                        self.budget.settle(reservation)
                        settled = True
                        self.paid_invoices.add(intent.invoice_id)
                        self.memos_by_tx_hash[result.hash] = commitment
                        self.daemon.settle(intent.nonce)
                        return self._done(intent, Outcome("paid", intent.public(), rules, tx_hash=result.hash, engine_result=result.engine_result,
                                                          commitment=commitment, message=f"Validated. {vendor.name} paid {amount} XRP."))
                    return self._done(intent, Outcome("rejected_by_ledger", intent.public(), rules, [f"ledger: {result.engine_result}"],
                                                      tx_hash=result.hash, engine_result=result.engine_result, commitment=commitment,
                                                      message=f"Both signatures were valid; the ledger said {result.engine_result}. {public_text(result.message)}"))
                finally:
                    self.in_flight.discard(intent.invoice_id)
        finally:
            if not settled:
                self.budget.release(reservation)

    # ----- admin path (logged, human-only) -----
    def admin_add_vendor(self, name: str, address: str, jurisdiction: str, actor: str = "human") -> List[Outcome]:
        if name in self.policy.allowlist:
            raise ValueError("vendor already listed; adding a vendor never replaces a record")
        if not is_valid_classic_address(address):
            raise ValueError(f"invalid classic address: {address}")
        self.policy.allowlist[name] = VendorRecord(name, address, jurisdiction)
        self.audit.admin("add_vendor", {"actor": actor, "vendor": name, "address": address, "jurisdiction": jurisdiction,
                                         "new_policy_hash": self.policy.hash()})
        reruns = []
        for nonce, intent in list(self.parked.items()):
            if intent.vendor == name:
                del self.parked[nonce]
                reruns.append(self.handle_intent(intent))
        return reruns

    # ----- helpers -----
    def _agent_signature_valid(self, agent_signed: dict) -> bool:
        signers = agent_signed.get("Signers") or []
        if len(signers) != 1:
            return False
        s = signers[0]["Signer"]
        if s["Account"] != self.daemon.address:
            return False
        if derive_classic_address(s["SigningPubKey"]) != self.daemon.address:
            return False
        payload = encode_for_multisigning(strip_signatures(agent_signed), s["Account"])
        return is_valid_message(bytes.fromhex(payload), bytes.fromhex(s["TxnSignature"]), s["SigningPubKey"])

    def _done(self, intent: Intent, outcome: Outcome) -> Outcome:
        self.outcomes[intent.nonce] = outcome
        return outcome
