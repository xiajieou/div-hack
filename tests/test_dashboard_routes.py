from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from fuse.policy.api import create_app
from fuse.reader.reader import write_fixtures
from fuse.reports.api import add_routes
from fuse.reports.sources import LocalWorld


@pytest.fixture
def client(tmp_path):
    world = LocalWorld(invoices=["inv_2201_verdant.txt", "inv_2201_verdant_REISSUE.txt"])
    world.stolen_keys(Decimal("50"), 2)
    write_fixtures(str(tmp_path), world.ring.attacker.classic_address)
    app = create_app(world.service)
    add_routes(app, world.service, world.addresses, str(tmp_path))
    return TestClient(app), world


def test_reports_carry_blast_radius_and_flag_the_attackers_payments(client):
    c, world = client
    r = c.get("/reports").json()
    assert r["network"] == "local" and r["break_glass_file"] is False
    assert r["blast"]["findings"] == []
    loss = {row["part"]: row["max_loss_drops"] for row in r["blast"]["rows"]}
    assert loss["agent key"] == 0 and loss["policy key"] == 0
    assert r["audit"]["outgoing"] == 3
    assert [t["amount_drops"] for t in r["audit"]["unlogged"]] == [50_000_000, 50_000_000]


def test_invoices_expose_hidden_text_only_for_the_poisoned_one(client):
    c, world = client
    hidden = {i["file"]: i["hidden"] for i in c.get("/invoices").json()}
    assert world.ring.attacker.classic_address in hidden["inv_2201_verdant_REISSUE.txt"]
    assert hidden["inv_2201_verdant.txt"] is None


def test_dashboard_page_is_served_and_holds_no_keys(client):
    c, world = client
    page = c.get("/dashboard").text
    assert "<title>Fuse Dashboard</title>" in page
    for w in (world.ring.agent, world.ring.policy, world.ring.treasury, world.ring.desk):
        assert w.seed not in page and w.private_key not in page
