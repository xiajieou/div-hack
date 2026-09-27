import json
from decimal import Decimal

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from fuse.policy.builder import build_payment
from fuse.policy.rules import Intent
from fuse.policy.service import MULTISIGN_FEE_DROPS
from fuse.signer.api import build_daemon_from_env, create_app
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
    assert daemon.intents[nonce].signatures_issued == 0
    assert response.json()["reason"]
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


def test_sign_refuses_non_canonical_destination(world):
    client, daemon, nonce, tx = _client_and_tx(world)
    bad = dict(tx)
    bad["destination"] = world["ring"].attacker.classic_address
    response = client.post("/sign", json={"tx": bad, "nonce": nonce})
    assert response.status_code == 403
    assert response.json()["reason"] == "transaction is not in canonical form"
    assert daemon.intents[nonce].signatures_issued == 0


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


def test_vendors_file_reloaded_on_sign(world, tmp_path):
    lumen_addr = world["policy"].allowlist["Lumen Legal"].address
    path = tmp_path / "vendors.json"
    path.write_text(json.dumps({"Lumen Legal": lumen_addr}))
    daemon = world["daemon"]
    daemon._forward = lambda intent: None
    client = TestClient(create_app(daemon, str(path)))
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
    ok = client.post("/sign", json={"tx": tx, "nonce": nonce})
    assert ok.status_code == 200
    assert "Signers" in ok.json()
    assert world["ring"].agent.seed not in ok.text
    path.write_text(json.dumps({"Lumen Legal": world["ring"].attacker.classic_address}))
    refused = client.post("/sign", json={"tx": tx, "nonce": nonce})
    assert refused.status_code == 403
    assert "Destination does not match my record" in refused.json()["reason"]


def test_build_daemon_from_env_ignores_accounts_vendors(world, tmp_path, monkeypatch):
    lumen_addr = world["policy"].allowlist["Lumen Legal"].address
    spend = world["ring"].treasury.classic_address
    treasury = world["ring"].attacker.classic_address  # different from spend
    accounts = {
        "treasury": treasury,
        "spend": spend,
        "desk": world["ring"].desk.classic_address,
        "vendors": {"Lumen Legal": world["ring"].attacker.classic_address},
    }
    vendors = {"Lumen Legal": lumen_addr}
    accounts_path = tmp_path / "accounts.json"
    vendors_path = tmp_path / "vendors.json"
    accounts_path.write_text(json.dumps(accounts))
    vendors_path.write_text(json.dumps(vendors))
    monkeypatch.setenv("ACCOUNTS_FILE", str(accounts_path))
    monkeypatch.setenv("VENDORS_FILE", str(vendors_path))
    monkeypatch.setenv("AGENT_SEED", world["ring"].agent.seed)
    daemon = build_daemon_from_env()
    assert daemon.directory == vendors
    assert daemon.address == world["ring"].agent.classic_address
    assert daemon.treasury == accounts["spend"]
    assert daemon.treasury != accounts["treasury"]
