from fuse.reports.audit_completeness import unlogged_payments


SPEND = "rSpend"
HISTORY = [
    {"type": "DelegateSet", "account": SPEND, "delegate": None, "destination": "", "result": "tesSUCCESS", "hash": "H1", "amount_drops": 0},
    {"type": "Payment", "account": "rTreasury", "delegate": None, "destination": SPEND, "result": "tesSUCCESS", "hash": "H2", "amount_drops": 30_000_000},   # top-up, incoming
    {"type": "Payment", "account": SPEND, "delegate": "rDesk", "destination": "rVendorA", "result": "tesSUCCESS", "hash": "H3", "amount_drops": 12_400_000},  # logged
    {"type": "Payment", "account": SPEND, "delegate": "rDesk", "destination": "rAttacker", "result": "tesSUCCESS", "hash": "H4", "amount_drops": 9_000_000},  # attacker, unlogged
    {"type": "Payment", "account": SPEND, "delegate": "rDesk", "destination": "rAttacker", "result": "tecUNFUNDED_PAYMENT", "hash": "H5", "amount_drops": 9_000_000},  # failed, ignored
    {"type": "SignerListSet", "account": SPEND, "delegate": "rDesk", "destination": "", "result": "tecNO_DELEGATE_PERMISSION", "hash": "H6", "amount_drops": 0},
    {"type": "Payment", "account": SPEND, "delegate": "rDesk", "destination": "rVendorB", "result": "tesSUCCESS", "hash": "H7", "amount_drops": 5_000_000},   # unlogged (log lost it)
]
LOG = {"H3"}


def test_flags_only_outgoing_successful_unlogged_payments():
    missing = unlogged_payments(HISTORY, LOG, SPEND)
    assert [m["hash"] for m in missing] == ["H4", "H7"]


def test_complete_log_reports_nothing():
    assert unlogged_payments(HISTORY, {"H3", "H4", "H7"}, SPEND) == []


def test_incoming_topup_is_never_flagged():
    assert all(m["hash"] != "H2" for m in unlogged_payments(HISTORY, set(), SPEND))


def test_failed_attempts_are_never_flagged():
    assert all(m["hash"] not in ("H5", "H6") for m in unlogged_payments(HISTORY, set(), SPEND))


def test_order_is_history_order():
    missing = unlogged_payments(HISTORY, set(), SPEND)
    assert [m["hash"] for m in missing] == ["H3", "H4", "H7"]


def test_local_ledger_flags_exactly_the_attackers_payments():
    from fuse.reports.sources import LocalWorld
    world = LocalWorld(attack=True)
    spend = world.addresses["spend"]
    missing = unlogged_payments(world.history(spend), world.log_hashes(), spend)
    assert len(missing) == 2
    assert all(m["amount_drops"] == 100_000_000 and m["delegate"] == world.addresses["desk"] for m in missing)
