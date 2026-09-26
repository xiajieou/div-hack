import dataclasses

from fastapi.testclient import TestClient

from fuse.policy.api import create_app
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
