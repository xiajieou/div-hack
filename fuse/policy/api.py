"""Policy service over HTTP. Phase 2, owner: Core.

Boundary: the existing acceptance tests pass unchanged through an HTTP test client:
    pytest tests/test_acceptance.py -q -k "ac04 or ac05 or ac06 or ac07 or ac13 or ac15"

Endpoints to build (FastAPI):
    POST /intent          body: intent from the daemon (vendor, amount, invoice_id, reason, claimed_destination, nonce)
    POST /admin/vendor    logged admin path: name, address, jurisdiction; reruns parked intents
    POST /submit-file     submits a pre-signed transaction file (the break-glass file); holds no keys
    GET  /status          outcomes, audit rows, ledger history for the dashboard
The rules module (fuse/policy/rules.py) is called, never modified. The credential hook is fuse/policy/credentials.py.
"""
from __future__ import annotations
import dataclasses # which turns an Outcome dataclass into a plain dict 
from fastapi import Body, FastAPI 
from .rules import Intent
from .service import PolicyService
import json 
import os 
from pathlib import Path
from xrpl.wallet import Wallet

from ..audit import AuditChain 
from ..config import default_policy
from ..ledger.local import LocalLedger
from ..ledger.testnet import TestnetLedger
from ..setup import KeyRing, run_setup
from ..signer.daemon import SignerDaemon



def create_app(service: PolicyService) -> FastAPI:
    app = FastAPI()

    @app.get("/status")
    def status():
        return {
            "policy_hash": service.policy.hash(),
            "accounts": {"treasury": service.treasury, "desk": service.desk},
            "balances": {
                "treasury": service.ledger.balance_xrp(service.treasury),
                "desk": service.ledger.balance_xrp(service.desk),
            },
            "outcomes": [dataclasses.asdict(o) for o in service.outcomes.values()],
            "audit": service.audit.dump(),
            "history": service.ledger.history,
        }
    
    @app.post("/intent")
    def intent(body: dict = Body()):
        outcome = service.handle_intent(Intent(**body))
        return dataclasses.asdict(outcome)

    @app.post("/admin/vendor")
    def admin_vendor(body: dict = Body()):
        reruns = service.admin_add_vendor(body["name"], body["address"], body["jurisdiction"], body.get("actor", "human"))
        return [dataclasses.asdict(o) for o in reruns]

    @app.post("/submit-file")
    def submit_file():
        path = Path(os.environ.get("BREAK_GLASS_FILE", "break-glass/revoke.json"))
        blob = json.loads(path.read_text())
        result = service.ledger.submit(blob)
        return {"engine_result": result.engine_result, "hash": result.hash}

    return app 


def _local_service() -> PolicyService:
    policy = default_policy()
    ledger = LocalLedger()
    ring = KeyRing.local(ledger, policy)
    run_setup(ledger, ring, delegation=True)
    audit = AuditChain(policy.hash())
    service = PolicyService(policy, ring.policy, ledger, ring.treasury.classic_address, ring.desk.classic_address, audit)
    daemon = SignerDaemon(ring.agent, ring.treasury.classic_address, ring.desk.classic_address,
                          {name: w.classic_address for name, w in ring.vendors.items()}, policy.fee_cap_drops, forward=service.handle_intent)
    service.attach_daemon(daemon)
    return service 

def _service_from_env() -> PolicyService:
    if os.environ.get("NETWORK") == "testnet":
        accounts = json.loads(Path("env/accounts.json").read_text())
        wallet = Wallet.from_seed(os.environ["POLICY_SEED"])
        policy = default_policy()
        audit = AuditChain(policy.hash())
        return PolicyService(policy, wallet, TestnetLedger(), accounts["treasury"], accounts["desk"], audit, accounts.get("registry"))
    return _local_service()

app = create_app(_service_from_env())