from decimal import Decimal

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from fuse.policy.builder import build_payment
from fuse.policy.rules import Intent
from fuse.policy.service import MULTISIGN_FEE_DROPS
from fuse.signer.api import create_app
from tests.test_acceptance import MUTATIONS, world


def _client_and_tx(world):
    daemon = world["daemon"]
    daemon._forward = lambda intent: None
    client = TestClient(create_app(daemon))
    intent = Intent(vendor="Lumen Legal", amount="21.00", invoice_id="INV-0092")
    nonce = daemon.register(intent)
    vendor = world["policy"].allowlist["Lumen Legal"]
    tx = build_payment(
        treasury=world["ring"].treasury.classic_address,
        desk=world["ring"].desk.classic_address,
        vendor=vendor,
        amount_xrp=Decimal("21.00"),
        invoice_id="INV-0092",
        commitment="00" * 32,
        policy_hash="p",
        fee_drops=MULTISIGN_FEE_DROPS,
        sequence=1,
        last_ledger_sequence=9999,
    )
    return client, daemon, nonce, tx


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_sign_refuses_mutations(world, name):
    client, daemon, nonce, tx = _client_and_tx(world)
    bad = dict(tx)
    MUTATIONS[name](bad, world)
    response = client.post("/sign", json={"tx": bad, "nonce": nonce})
    assert response.status_code == 403
    assert "signer daemon refused" in response.json()["reason"]
    assert world["ring"].agent.seed not in response.text


def test_unknown_and_settled_nonce_refused(world):
    client, daemon, nonce, tx = _client_and_tx(world)
    unknown = client.post("/sign", json={"tx": tx, "nonce": "deadbeef"})
    assert unknown.status_code == 403
    assert "unknown nonce" in unknown.json()["reason"]
    daemon.settle(nonce)
    settled = client.post("/sign", json={"tx": tx, "nonce": nonce})
    assert settled.status_code == 403
    assert "already settled" in settled.json()["reason"]
    seed = world["ring"].agent.seed
    assert seed not in unknown.text
    assert seed not in settled.text


def test_address_hides_seed(world):
    client, _, _, _ = _client_and_tx(world)
    response = client.get("/address")
    assert response.status_code == 200
    assert response.json()["address"] == world["ring"].agent.classic_address
    assert world["ring"].agent.seed not in response.text
    assert world["ring"].agent.private_key not in response.text


def test_vendor_route_removed(world):
    client, _, _, _ = _client_and_tx(world)
    paths = {route.path for route in client.app.routes if isinstance(route, APIRoute)}
    assert paths == {"/register", "/sign", "/settle", "/address"}
    response = client.post("/vendor", json={"name": "x", "address": "y"})
    assert response.status_code == 404
