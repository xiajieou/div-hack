import queue
import time

import pytest
from fastapi.testclient import TestClient

from dashboard.flow import Flow, create_app


def run(flow, name):
    q = queue.Queue()
    flow.subscribers.append(q)
    assert flow.run(name, throttle=False)
    while flow.run_lock.locked():
        time.sleep(0.01)
    time.sleep(0.05)
    flow.subscribers.remove(q)
    events = []
    while not q.empty():
        events.append(q.get())
    return events, [e for e in events if e["type"] == "end"][-1]


def stopped(events):
    return {e["box"] for e in events if e["type"] == "state" and e["state"] == "stop"}


@pytest.fixture
def flow():
    return Flow()


@pytest.mark.parametrize("name, kind, box", [
    ("normal", "paid", None),
    ("overcap", "stop", "policy"),
    ("poisoned", "stop", "policy"),
    ("unknown", "park", None),
    ("forged", "stop", "daemon"),
    ("hacked_policy", "stop", "daemon"),
    ("corrupt", "stop", "policy"),
    ("agent_key", "stop", "desk"),
    ("take_over", "stop", "desk"),
    ("kill", "stop", "desk"),
])
def test_each_scenario_is_stopped_where_the_design_says(flow, name, kind, box):
    events, end = run(flow, name)
    assert end["kind"] == kind, end
    assert stopped(events) == ({box} if box else set())


def test_both_keys_lose_at_most_the_float_and_the_audit_sees_it(flow):
    float_drops = flow.world.ledger.account(flow.world.addresses["spend"]).balance_drops
    _, end = run(flow, "drain")
    assert end["kind"] == "capped"
    snap = flow.snapshot()
    taken = float_drops - flow.world.ledger.account(flow.world.addresses["spend"]).balance_drops
    assert 0 < taken <= float_drops
    assert snap["balances"]["treasury"] == "1000"
    assert len(snap["audit"]["unlogged"]) == len([t for t in snap["audit"]["unlogged"] if t["destination"] == flow.world.ring.attacker.classic_address]) > 0


def test_hacked_policy_service_never_reaches_the_ledger(flow):
    before = len(flow.world.ledger.history)
    run(flow, "hacked_policy")
    assert len(flow.world.ledger.history) == before


def test_one_scenario_at_a_time_and_page_holds_no_keys(flow):
    c = TestClient(create_app(flow))
    page = c.get("/").text
    for w in (flow.world.ring.agent, flow.world.ring.policy, flow.world.ring.treasury, flow.world.ring.desk, flow.world.treasury_wallet):
        assert w.seed not in page
    assert c.post("/flow/run", json={"scenario": "nope"}).status_code == 409
    assert "scenarios" in c.get("/flow/state").json()
