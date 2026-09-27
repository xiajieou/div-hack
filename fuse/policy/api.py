"""Policy service over HTTP.

POST /intent          intent from the daemon
POST /admin/vendor    logged admin path; reruns parked intents
POST /submit-file     submits a pre-signed transaction file; holds no keys
GET  /status          outcomes, audit rows, ledger history
The rules module is called, never modified.
"""
from __future__ import annotations
import dataclasses # which turns an Outcome dataclass into a plain dict 
import httpx
from fastapi import Body, FastAPI 
from .rules import Intent
from .service import PolicyService
import json 
import os 
from pathlib import Path
from types import SimpleNamespace
from xrpl.wallet import Wallet

from ..audit import AuditChain 
from ..config import default_policy
from ..ledger.local import LocalLedger
from ..ledger.testnet import DEVNET_RPC, TESTNET_RPC, TestnetLedger
from ..reports.api import add_routes
from ..registry import setup_local_registry
from ..setup import KeyRing, run_setup
from ..signer.daemon import Refusal, SignerDaemon


class DaemonClient:
    """The policy side's view of a daemon in another process. Address, sign, settle; no vendor path (D18)."""

    def __init__(self, base_url: str, address: str, http=None):
        self.base_url = base_url.rstrip("/")
        self.address = address
        self.http = http or httpx.Client(timeout=60)

    def sign(self, tx: dict, nonce: str) -> dict:
        response = self.http.post(self.base_url + "/sign", json={"tx": tx, "nonce": nonce})
        if response.status_code == 403:
            raise Refusal(response.json()["reason"])
        response.raise_for_status()
        return response.json()

    def settle(self, nonce: str) -> None:
        self.http.post(self.base_url + "/settle", json={"nonce": nonce}).raise_for_status()



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


def _local_service(agent_address: str | None = None) -> PolicyService:
    policy = default_policy()
    ledger = LocalLedger()
    ring = KeyRing.local(ledger, policy)
    if agent_address:
        # the agent key lives in the daemon process; only its address goes on the desk signer list (D17)
        ring.agent = SimpleNamespace(classic_address=agent_address)
    run_setup(ledger, ring, delegation=True)
    registry = setup_local_registry(ledger, [*ring.vendors.values(), ring.northwind])
    audit = AuditChain(policy.hash())
    service = PolicyService(policy, ring.policy, ledger, ring.treasury.classic_address, ring.desk.classic_address, audit,
                            registry.classic_address)
    vendors = {name: w.classic_address for name, w in ring.vendors.items()}
    if agent_address:
        _write_public_facts(ring, vendors, registry.classic_address)
        return service
    daemon = SignerDaemon(ring.agent, ring.treasury.classic_address, ring.desk.classic_address,
                          vendors, policy.fee_cap_drops, forward=service.handle_intent)
    service.attach_daemon(daemon)
    return service 


def _write_public_facts(ring: KeyRing, vendors: dict, registry: str) -> None:
    """Same shape the testnet setup script writes, so the daemon and reader read one format. Addresses only."""
    env = Path("env")
    env.mkdir(exist_ok=True)
    accounts = {
        "network": "local",
        "treasury": ring.treasury.classic_address,
        "spend": ring.treasury.classic_address,
        "desk": ring.desk.classic_address,
        "policy": ring.policy.classic_address,
        "registry": registry,
        "attacker": ring.attacker.classic_address,
        "northwind": ring.northwind.classic_address,
    }
    (env / "accounts.json").write_text(json.dumps(accounts, indent=2))
    (env / "vendors.json").write_text(json.dumps(vendors, indent=2))


RPC_BY_NETWORK = {"devnet": DEVNET_RPC, "testnet": TESTNET_RPC}


def _service_from_env() -> PolicyService:
    daemon_url = os.environ.get("DAEMON_URL")
    network = os.environ.get("NETWORK", "local")
    if network != "local":
        rpc = RPC_BY_NETWORK[network]
        accounts = json.loads(Path("env/accounts.json").read_text())
        if accounts.get("network", network) != network:
            raise SystemExit(f"env/accounts.json was written for {accounts['network']}, NETWORK is {network}")
        wallet = Wallet.from_seed(os.environ["POLICY_SEED"])
        policy = default_policy()
        audit = AuditChain(policy.hash())
        service = PolicyService(policy, wallet, TestnetLedger(rpc), accounts["spend"], accounts["desk"], audit, accounts.get("registry"))
    elif daemon_url:
        service = _local_service(os.environ["AGENT_ADDRESS"])
    else:
        return _local_service()
    if daemon_url:
        service.attach_daemon(DaemonClient(daemon_url, os.environ["AGENT_ADDRESS"]))
    return service

service = _service_from_env()
app = create_app(service)
add_routes(app, service)