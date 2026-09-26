"""Signer daemon over HTTP. Phase 3, owner: Core.

The agent key is loaded from AGENT_SEED and never returned by any endpoint.
The verifier in fuse/signer/daemon.py is called, not modified.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse
from xrpl.wallet import Wallet

from ..config import default_policy
from ..policy.rules import Intent
from .daemon import Refusal, SignerDaemon


def create_app(daemon: SignerDaemon, vendors_file: str | None = None) -> FastAPI:
    app = FastAPI()
    outcomes: dict = {}
    previous = daemon._forward

    # register() sets intent.nonce before forwarding, so concurrent requests never share a slot
    def forward(intent):
        outcomes[intent.nonce] = previous(intent)

    daemon._forward = forward

    @app.post("/register")
    def register(body: dict = Body()):
        intent = Intent(
            vendor=body["vendor"],
            amount=str(body["amount"]),
            invoice_id=body["invoice_id"],
            reason=body.get("reason") or "",
            claimed_destination=body.get("claimed_destination") or None,
        )
        nonce = daemon.register(intent)
        return {"nonce": nonce, "outcome": outcomes.pop(nonce, None)}

    @app.post("/sign")
    def sign(body: dict = Body()):
        if vendors_file is not None:
            daemon.directory = json.loads(Path(vendors_file).read_text())
        try:
            return daemon.sign(body["tx"], body["nonce"])
        except Refusal as exc:
            return JSONResponse(status_code=403, content={"reason": str(exc)})

    @app.post("/settle")
    def settle(body: dict = Body()):
        daemon.settle(body["nonce"])
        return {}

    @app.get("/address")
    def address():
        return {"address": daemon.address}

    return app


def build_daemon_from_env() -> SignerDaemon:
    accounts_path = os.environ.get("ACCOUNTS_FILE", "env/accounts.json")
    vendors_path = os.environ.get("VENDORS_FILE", "env/vendors.json")
    accounts = json.loads(Path(accounts_path).read_text())
    vendors = json.loads(Path(vendors_path).read_text())
    wallet = Wallet.from_seed(os.environ["AGENT_SEED"])
    policy_url = os.environ.get("POLICY_URL", "http://localhost:8001")

    def forward(intent):
        response = httpx.post(policy_url + "/intent", json=intent.public(), timeout=60)
        response.raise_for_status()
        return response.json()

    return SignerDaemon(
        wallet,
        accounts["treasury"],
        accounts.get("desk"),
        vendors,
        default_policy().fee_cap_drops,
        forward,
    )
