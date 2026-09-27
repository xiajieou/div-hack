import dataclasses
import json

from fastapi.testclient import TestClient
from xrpl.core.addresscodec import is_valid_classic_address
from xrpl.models.transactions import DelegateSet

from fuse.policy.api import DaemonClient, _service_from_env, create_app
from fuse.policy.rules import Intent
from fuse.setup import _single_sign
from tests.test_acceptance import world


def test_status(world):
    service = world["service"]
    client = TestClient(create_app(service))
    response = client.get("/status")
    body = response.json()
    assert response.status_code == 200
    assert body["policy_hash"] == service.policy.hash()
    assert body["accounts"] == {"treasury": service.treasury, "desk": service.desk}
    assert body["balances"] == {
        "treasury": service.ledger.balance_xrp(service.treasury),
        "desk": service.ledger.balance_xrp(service.desk),
    }
    assert body["outcomes"] == [dataclasses.asdict(o) for o in service.outcomes.values()]
    assert body["audit"] == service.audit.dump()
    assert body["history"] == service.ledger.history
    text = response.text
    assert service._wallet.seed not in text
    assert service._wallet.private_key not in text


def test_admin_add_vendor_reruns_parked(world):
    service = world["service"]
    client = TestClient(create_app(service))
    intent = Intent(vendor="Northwind Freight", amount="6.40", invoice_id="INV-5510")
    world["daemon"]._forward = lambda intent: None
    world["daemon"].register(intent)
    parked = client.post("/intent", json=intent.public())
    assert parked.json()["status"] == "parked"
    world["daemon"].add_vendor("Northwind Freight", world["ring"].northwind.classic_address)
    response = client.post("/admin/vendor", json={
        "name": "Northwind Freight",
        "address": world["ring"].northwind.classic_address,
        "jurisdiction": "US",
        "actor": "cfo@company",
    })
    body = response.json()
    assert response.status_code == 200
    assert len(body) == 1 and body[0]["status"] == "paid"
    assert any(row["kind"] == "admin" for row in service.audit.dump())


def test_submit_file_revokes_then_payment_rejected(world, tmp_path, monkeypatch):
    service = world["service"]
    ring = world["ring"]
    ledger = world["ledger"]
    client = TestClient(create_app(service))
    lls = ledger.current_ledger_index() + 200
    blob = _single_sign(
        DelegateSet(account=ring.treasury.classic_address, authorize=ring.desk.classic_address, permissions=[]),
        ring.treasury,
        ledger.next_sequence(ring.treasury.classic_address),
        lls,
    )
    path = tmp_path / "revoke.json"
    path.write_text(json.dumps(blob))
    monkeypatch.setenv("BREAK_GLASS_FILE", str(path))
    submitted = client.post("/submit-file")
    assert submitted.status_code == 200
    assert submitted.json()["engine_result"] == "tesSUCCESS"
    intent = Intent(vendor="Harbor Cloud Hosting", amount="5.00", invoice_id="INV-3300")
    world["daemon"]._forward = lambda intent: None
    world["daemon"].register(intent)
    body = client.post("/intent", json=intent.public()).json()
    assert body["status"] == "rejected_by_ledger"
    assert body["engine_result"] == "tecNO_DELEGATE_PERMISSION"


def test_missing_credential_refuses_before_reservation(world, monkeypatch):
    monkeypatch.setattr("fuse.policy.service.vendor_has_accepted_credential", lambda ledger, address, registry: False)
    intent = Intent(vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201", nonce="cred")
    outcome = world["service"].handle_intent(intent)
    assert outcome.status == "refused"
    assert any("accepted registry credential" in f for f in outcome.failed)
    assert world["service"].budget.committed_drops() == 0


def test_known_seed_absent_from_status_and_intent(world):
    seed = world["ring"].policy.seed
    client = TestClient(create_app(world["service"]))
    status = client.get("/status")
    assert seed not in status.text
    intent = Intent(vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201")
    world["daemon"]._forward = lambda intent: None
    world["daemon"].register(intent)
    posted = client.post("/intent", json=intent.public())
    assert seed not in posted.text
    assert "TxnSignature" not in posted.text
    after = client.get("/status")
    assert seed not in after.text and "TxnSignature" not in after.text


def test_sign_exception_is_redacted_before_it_is_returned(world):
    service = world["service"]
    secret = f"sign failed {service._wallet.seed} {service._wallet.private_key}"

    def explode(tx, nonce):
        raise RuntimeError(secret)

    service.daemon.sign = explode
    outcome = service.handle_intent(Intent(vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201"))
    assert outcome.status == "refused"
    published = json.dumps(outcome.failed) + json.dumps(service.audit.dump())
    assert service._wallet.seed not in published
    assert service._wallet.private_key not in published
    assert "[redacted]" in published


def test_local_mode_with_daemon_url_publishes_facts_and_no_seed(tmp_path, monkeypatch):
    agent = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NETWORK", raising=False)
    monkeypatch.setenv("DAEMON_URL", "http://localhost:8002")
    monkeypatch.setenv("AGENT_ADDRESS", agent)
    service = _service_from_env()
    assert isinstance(service.daemon, DaemonClient)
    assert service.daemon.address == agent
    assert service.ledger.accounts[service.desk].signer_entries == {agent: 1, service._wallet.classic_address: 1}
    accounts = json.loads((tmp_path / "env" / "accounts.json").read_text())
    vendors = json.loads((tmp_path / "env" / "vendors.json").read_text())
    assert accounts["treasury"] == service.treasury and accounts["desk"] == service.desk
    assert vendors == {name: v.address for name, v in service.policy.allowlist.items()}
    # public facts only: a fixed key set, and every value is a classic address, never a seed or key
    assert set(accounts) == {"network", "treasury", "desk", "policy", "registry", "attacker", "northwind"}
    assert accounts["registry"] == service.registry
    for value in [v for k, v in accounts.items() if k != "network"] + list(vendors.values()):
        assert is_valid_classic_address(value)
