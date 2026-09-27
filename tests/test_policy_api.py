import dataclasses
import json

import pytest
from fastapi.testclient import TestClient
from xrpl.core.addresscodec import is_valid_classic_address
from xrpl.models.transactions import DelegateSet
from xrpl.wallet import Wallet

from fuse.ledger.local import LocalLedger
from fuse.ledger.testnet import DEVNET_RPC, TESTNET_RPC
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


def test_admin_add_vendor_refuses_replace_and_invalid_address(world):
    service = world["service"]
    client = TestClient(create_app(service))
    existing = service.policy.allowlist["Baltic Freight"]
    before = (existing.address, existing.jurisdiction)
    replace = client.post("/admin/vendor", json={
        "name": "Baltic Freight",
        "address": world["ring"].northwind.classic_address,
        "jurisdiction": "US",
        "actor": "cfo@company",
    })
    assert replace.status_code == 400
    assert "never replaces" in replace.json()["detail"]
    assert (service.policy.allowlist["Baltic Freight"].address,
            service.policy.allowlist["Baltic Freight"].jurisdiction) == before
    bad = client.post("/admin/vendor", json={
        "name": "Brand New Co",
        "address": "not-an-address",
        "jurisdiction": "US",
    })
    assert bad.status_code == 400
    assert "invalid classic address" in bad.json()["detail"]
    assert "Brand New Co" not in service.policy.allowlist


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
    assert body["engine_result"] == "terNO_DELEGATE_PERMISSION"


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


def test_public_text_redacts_secp256k1_seed_and_key():
    from xrpl.constants import CryptoAlgorithm
    from fuse.policy.service import public_text

    w = Wallet.create(algorithm=CryptoAlgorithm.SECP256K1)
    redacted = public_text(f"leak {w.seed} {w.private_key}")
    assert w.seed not in redacted
    assert w.private_key not in redacted
    # no character run from either secret survives
    for secret in (w.seed, w.private_key):
        for i in range(len(secret)):
            for length in range(8, len(secret) + 1):
                if i + length <= len(secret):
                    assert secret[i:i + length] not in redacted


def _network_service(tmp_path, monkeypatch, network, accounts):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "env").mkdir(exist_ok=True)
    (tmp_path / "env" / "accounts.json").write_text(json.dumps(accounts))
    monkeypatch.setenv("NETWORK", network)
    monkeypatch.setenv("POLICY_SEED", Wallet.create().seed)
    monkeypatch.delenv("DAEMON_URL", raising=False)
    return _service_from_env()


NETWORK_ACCOUNTS = {"treasury": "rTreasury", "spend": "rSpend", "desk": "rDesk", "registry": "rRegistry"}


def test_network_devnet_uses_the_devnet_rpc(tmp_path, monkeypatch):
    service = _network_service(tmp_path, monkeypatch, "devnet", NETWORK_ACCOUNTS)
    assert service.ledger.rpc_url == DEVNET_RPC
    assert service.desk == "rDesk" and service.registry == "rRegistry"
    assert _network_service(tmp_path, monkeypatch, "testnet", NETWORK_ACCOUNTS).ledger.rpc_url == TESTNET_RPC


def test_network_mode_pays_from_the_spend_account_never_the_treasury(tmp_path, monkeypatch):
    assert _network_service(tmp_path, monkeypatch, "devnet", NETWORK_ACCOUNTS).treasury == "rSpend"
    without_spend = {k: v for k, v in NETWORK_ACCOUNTS.items() if k != "spend"}
    with pytest.raises(KeyError, match="spend"):
        _network_service(tmp_path, monkeypatch, "devnet", without_spend)


@pytest.mark.parametrize("value", [None, "local"])
def test_network_unset_or_local_is_the_local_ledger(tmp_path, monkeypatch, value):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DAEMON_URL", raising=False)
    if value is None:
        monkeypatch.delenv("NETWORK", raising=False)
    else:
        monkeypatch.setenv("NETWORK", value)
    assert isinstance(_service_from_env().ledger, LocalLedger)


def test_network_typo_refuses_to_start_instead_of_running_the_mini_ledger(tmp_path, monkeypatch):
    with pytest.raises(KeyError, match="Devnet"):
        _network_service(tmp_path, monkeypatch, "Devnet", NETWORK_ACCOUNTS)


def test_network_mode_refuses_an_accounts_file_written_for_another_network(tmp_path, monkeypatch):
    stale = {**NETWORK_ACCOUNTS, "network": "local"}
    with pytest.raises(SystemExit, match="written for local, NETWORK is devnet"):
        _network_service(tmp_path, monkeypatch, "devnet", stale)
    assert _network_service(tmp_path, monkeypatch, "devnet", {**NETWORK_ACCOUNTS, "network": "devnet"}).ledger.rpc_url == DEVNET_RPC


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
    assert set(accounts) == {"network", "treasury", "spend", "desk", "policy", "registry", "attacker", "northwind"}
    assert accounts["spend"] == service.treasury
    assert accounts["registry"] == service.registry
    for value in [v for k, v in accounts.items() if k != "network"] + list(vendors.values()):
        assert is_valid_classic_address(value)
