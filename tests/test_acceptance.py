"""Acceptance-criteria tests. Names carry the criterion from planning/SPEC.md."""
import threading
from decimal import Decimal

import pytest
from xrpl.models.transactions import Payment, SignerListSet
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import multisign, sign

from fuse.audit import AuditChain
from fuse.budget import Budget, BudgetError
from fuse.config import VendorRecord, default_policy, xrp_to_drops
from fuse.ledger.local import LocalLedger
from fuse.policy.builder import build_payment, decode_memo_commitment, invoice_id_hash
from fuse.policy.rules import Intent, evaluate
from fuse.policy.service import MULTISIGN_FEE_DROPS, PolicyService
from fuse.setup import KeyRing, revoke_delegation, run_setup
from fuse.signer.daemon import Refusal, SignerDaemon
from fastapi.testclient import TestClient
from fuse.policy.api import create_app  


# ---------- fixtures ----------
@pytest.fixture(params=["direct", "http"])
def world(request):
    policy = default_policy()
    ledger = LocalLedger()
    ring = KeyRing.local(ledger, policy)
    run_setup(ledger, ring, delegation=True)
    audit = AuditChain(policy.hash())
    service = PolicyService(policy, ring.policy, ledger, ring.treasury.classic_address, ring.desk.classic_address, audit)
    daemon = SignerDaemon(ring.agent, ring.treasury.classic_address, ring.desk.classic_address,
                          {n: v.address for n, v in policy.allowlist.items()}, policy.fee_cap_drops, forward=service.handle_intent)
    service.attach_daemon(daemon)
    if request.param == "http":
        client = TestClient(create_app(service))

        def forward(intent):
            response = client.post("/intent", json=intent.public())
            response.raise_for_status()
        daemon._forward = forward

    return dict(policy=policy, ledger=ledger, ring=ring, audit=audit, service=service, daemon=daemon)


def run_intent(w, **kw):
    it = Intent(**kw)
    nonce = w["daemon"].register(it)
    return w["service"].outcomes[nonce]


# ---------- AC3: a valid intent produces a validated payment with the canonical fields ----------
def test_ac03_paid_payment_has_canonical_fields(world):
    o = run_intent(world, vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201")
    assert o.status == "paid" and o.engine_result == "tesSUCCESS"
    tx = next(h for h in world["ledger"].history if h["hash"] == o.tx_hash)
    assert tx["account"] == world["ring"].treasury.classic_address
    assert tx["delegate"] == world["ring"].desk.classic_address
    assert world["service"].memos_by_tx_hash[o.tx_hash] == o.commitment


# ---------- AC4: over the per-payment cap is refused with no signature and no submission ----------
def test_ac04_over_cap_refused(world):
    before = len(world["ledger"].history)
    o = run_intent(world, vendor="Lumen Legal", amount="48", invoice_id="INV-9001")
    assert o.status == "refused"
    assert any("per-payment cap" in f for f in o.failed)
    assert len(world["ledger"].history) == before
    assert world["daemon"].intents[o.intent["nonce"]].signatures_issued == 0


# ---------- AC5: two concurrent intents that together exceed the budget -> exactly one approval ----------
def test_ac05_atomic_budget_under_concurrency():
    budget = Budget(daily_cap_drops=int(xrp_to_drops(Decimal("25"))), per_hour_max=100)
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            results.append(("ok", budget.reserve(int(xrp_to_drops(Decimal("15"))))))
        except BudgetError as e:
            results.append(("refused", str(e)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(1 for r in results if r[0] == "ok") == 1
    assert budget.committed_drops() == int(xrp_to_drops(Decimal("15")))


# ---------- AC6: duplicate invoice refused regardless of amount ----------
def test_ac06_duplicate_invoice_refused(world):
    assert run_intent(world, vendor="Harbor Cloud Hosting", amount="8.90", invoice_id="INV-7734").status == "paid"
    o = run_intent(world, vendor="Harbor Cloud Hosting", amount="1.00", invoice_id="INV-7734")
    assert o.status == "refused" and any("already paid" in f for f in o.failed)


# ---------- AC7: unknown destination parks; admin add-vendor reruns through the normal flow ----------
def test_ac07_unknown_vendor_parked_then_rerun(world):
    o = run_intent(world, vendor="Northwind Freight", amount="6.40", invoice_id="INV-5510")
    assert o.status == "parked"
    reruns = world["service"].admin_add_vendor("Northwind Freight", world["ring"].northwind.classic_address, "US")
    assert len(reruns) == 1 and reruns[0].status == "paid"
    assert any(r.kind == "admin" for r in world["audit"].rows)


# ---------- AC8: the signer daemon refuses every mutation of the built transaction ----------
MUTATIONS = {
    "changed destination": lambda tx, w: tx.update(Destination=w["ring"].attacker.classic_address),
    "changed amount": lambda tx, w: tx.update(Amount=str(int(tx["Amount"]) + 1)),
    "changed invoice hash": lambda tx, w: tx.update(InvoiceID=invoice_id_hash("INV-OTHER")),
    "wrong account": lambda tx, w: tx.update(Account=w["ring"].attacker.classic_address),
    "wrong delegate": lambda tx, w: tx.update(Delegate=w["ring"].attacker.classic_address),
    "Paths present": lambda tx, w: tx.update(Paths=[[{"account": w["ring"].attacker.classic_address}]]),
    "SendMax present": lambda tx, w: tx.update(SendMax="1"),
    "DeliverMin present": lambda tx, w: tx.update(DeliverMin="1"),
    "partial payment flag": lambda tx, w: tx.update(Flags=131072),
    "fee over cap": lambda tx, w: tx.update(Fee="999"),
    "not a Payment": lambda tx, w: tx.update(TransactionType="AccountSet"),
}


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_ac08_signer_refuses_mutations(world, name):
    it = Intent(vendor="Lumen Legal", amount="21.00", invoice_id="INV-0092")
    # register without forwarding so we can hand-feed the daemon
    world["daemon"]._forward = lambda intent: None
    nonce = world["daemon"].register(it)
    vendor = world["policy"].allowlist["Lumen Legal"]
    tx = build_payment(treasury=world["ring"].treasury.classic_address, desk=world["ring"].desk.classic_address, vendor=vendor,
                       amount_xrp=Decimal("21.00"), invoice_id="INV-0092", commitment="00" * 32, policy_hash="p",
                       fee_drops=MULTISIGN_FEE_DROPS, sequence=1, last_ledger_sequence=9999)
    signed_ok = world["daemon"].sign(dict(tx), nonce)
    assert signed_ok["Signers"][0]["Signer"]["Account"] == world["ring"].agent.classic_address
    bad = dict(tx)
    MUTATIONS[name](bad, world)
    with pytest.raises(Refusal):
        world["daemon"].sign(bad, nonce)


def test_ac08_unknown_and_settled_nonce_refused(world):
    world["daemon"]._forward = lambda intent: None
    it = Intent(vendor="Lumen Legal", amount="21.00", invoice_id="INV-0092")
    nonce = world["daemon"].register(it)
    vendor = world["policy"].allowlist["Lumen Legal"]
    tx = build_payment(treasury=world["ring"].treasury.classic_address, desk=world["ring"].desk.classic_address, vendor=vendor,
                       amount_xrp=Decimal("21.00"), invoice_id="INV-0092", commitment="00" * 32, policy_hash="p",
                       fee_drops=MULTISIGN_FEE_DROPS, sequence=1, last_ledger_sequence=9999)
    with pytest.raises(Refusal):
        world["daemon"].sign(tx, "deadbeef")
    world["daemon"].settle(nonce)
    with pytest.raises(Refusal):
        world["daemon"].sign(tx, nonce)


# ---------- AC9: a non-Payment from the desk on the treasury is rejected by the ledger ----------
def test_ac09_non_payment_rejected_by_delegation_scope(world):
    ring, ledger = world["ring"], world["ledger"]
    tx = SignerListSet(account=ring.treasury.classic_address, delegate=ring.desk.classic_address, signer_quorum=1,
                       signer_entries=[SignerEntry(account=ring.attacker.classic_address, signer_weight=1)],
                       fee=str(MULTISIGN_FEE_DROPS), sequence=ledger.next_sequence(ring.treasury.classic_address),
                       last_ledger_sequence=9999, signing_pub_key="")
    both = multisign(tx, [sign(tx, ring.agent, multisign=True), sign(tx, ring.policy, multisign=True)]).to_xrpl()
    r = ledger.submit(both)
    assert r.engine_result == "tecNO_DELEGATE_PERMISSION"
    assert ledger.account(ring.treasury.classic_address).signer_quorum == 0


# ---------- AC10: after revocation, a valid double-signed payment is rejected by the ledger ----------
def test_ac10_revocation_rejects_valid_payment(world):
    assert run_intent(world, vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201").status == "paid"
    assert revoke_delegation(world["ledger"], world["ring"]).ok
    o = run_intent(world, vendor="Harbor Cloud Hosting", amount="5.00", invoice_id="INV-3300")
    assert o.status == "rejected_by_ledger" and o.engine_result == "tecNO_DELEGATE_PERMISSION"


# ---------- AC11: the audit chain verifies, and detects an edited row ----------
def test_ac11_audit_chain_verifies_and_detects_tamper(world):
    run_intent(world, vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201")
    run_intent(world, vendor="Lumen Legal", amount="48", invoice_id="INV-9001")   # refused row
    ok, msg = world["audit"].verify(world["service"].memos_by_tx_hash)
    assert ok, msg
    world["audit"].rows[0].record["intent"]["amount"] = "0.01"
    ok, msg = world["audit"].verify(world["service"].memos_by_tx_hash)
    assert not ok and "altered" in msg


def test_ac11_memo_carries_commitment_made_before_submission(world):
    o = run_intent(world, vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201")
    vendor = world["policy"].allowlist["Verdant Print Co"]
    rebuilt = build_payment(treasury=world["ring"].treasury.classic_address, desk=world["ring"].desk.classic_address, vendor=vendor,
                            amount_xrp=Decimal("12.40"), invoice_id="INV-2201", commitment=o.commitment, policy_hash=world["policy"].hash(),
                            fee_drops=MULTISIGN_FEE_DROPS, sequence=1, last_ledger_sequence=1)
    assert decode_memo_commitment(rebuilt) == o.commitment
    proposal_rows = [r for r in world["audit"].rows if r.kind == "proposal"]
    assert proposal_rows[0].hash == o.commitment


# ---------- AC13: malformed intents refused before any reservation ----------
@pytest.mark.parametrize("amount", ["-5", "0", "abc", "1.2345678", ""])
def test_ac13_malformed_amount_refused(world, amount):
    o = run_intent(world, vendor="Verdant Print Co", amount=amount, invoice_id="INV-2201")
    assert o.status == "refused"
    assert world["service"].budget.committed_drops() == 0


def test_ac13_missing_invoice_id_refused(world):
    o = run_intent(world, vendor="Verdant Print Co", amount="1", invoice_id="")
    assert o.status == "refused" and world["service"].budget.committed_drops() == 0


# ---------- AC15: allowlisted vendor in a disallowed jurisdiction is refused ----------
def test_ac15_jurisdiction_refused(world):
    world["policy"].open_purchase_orders["INV-RU1"] = "PO-999"
    o = run_intent(world, vendor="Baltic Freight", amount="3", invoice_id="INV-RU1")
    assert o.status == "refused" and any("jurisdiction" in f for f in o.failed)
    assert world["service"].budget.committed_drops() == 0


# ---------- AC16: a payment signed with the agent key alone is rejected by the ledger ----------
def test_ac16_single_signature_rejected_for_quorum(world):
    ring, ledger = world["ring"], world["ledger"]
    attacker = VendorRecord("attacker", ring.attacker.classic_address, "??")
    tx = build_payment(treasury=ring.treasury.classic_address, desk=ring.desk.classic_address, vendor=attacker,
                       amount_xrp=Decimal("50"), invoice_id="FAKE", commitment="00" * 32, policy_hash="p",
                       fee_drops=MULTISIGN_FEE_DROPS, sequence=ledger.next_sequence(ring.treasury.classic_address), last_ledger_sequence=9999)
    r = ledger.submit(sign(Payment.from_xrpl(tx), ring.agent, multisign=True).to_xrpl())
    assert r.engine_result == "tefBAD_QUORUM"
    assert ledger.balance_xrp(ring.attacker.classic_address) == "5.000000"


# ---------- the ledger itself: forged and tampered signatures never pass ----------
def test_ledger_rejects_tampered_transaction_after_signing(world):
    ring, ledger = world["ring"], world["ledger"]
    vendor = world["policy"].allowlist["Verdant Print Co"]
    tx = build_payment(treasury=ring.treasury.classic_address, desk=ring.desk.classic_address, vendor=vendor,
                       amount_xrp=Decimal("1"), invoice_id="X", commitment="00" * 32, policy_hash="p",
                       fee_drops=MULTISIGN_FEE_DROPS, sequence=ledger.next_sequence(ring.treasury.classic_address), last_ledger_sequence=9999)
    base = Payment.from_xrpl(tx)
    both = multisign(base, [sign(base, ring.agent, multisign=True), sign(base, ring.policy, multisign=True)]).to_xrpl()
    both["Amount"] = str(int(both["Amount"]) * 10)     # tamper after signing
    assert ledger.submit(both).engine_result == "tefBAD_SIGNATURE"


def test_ledger_rejects_signer_not_on_list(world):
    ring, ledger = world["ring"], world["ledger"]
    vendor = world["policy"].allowlist["Verdant Print Co"]
    tx = build_payment(treasury=ring.treasury.classic_address, desk=ring.desk.classic_address, vendor=vendor,
                       amount_xrp=Decimal("1"), invoice_id="X", commitment="00" * 32, policy_hash="p",
                       fee_drops=MULTISIGN_FEE_DROPS, sequence=ledger.next_sequence(ring.treasury.classic_address), last_ledger_sequence=9999)
    base = Payment.from_xrpl(tx)
    both = multisign(base, [sign(base, ring.agent, multisign=True), sign(base, ring.attacker, multisign=True)]).to_xrpl()
    assert ledger.submit(both).engine_result == "tefBAD_SIGNATURE"
