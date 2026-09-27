"""Signer daemon over HTTP.

The agent key is loaded from AGENT_SEED and never returned by any endpoint.
The verifier in fuse/signer/daemon.py is called, not modified.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx
import uvicorn
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args()
    vendors_file = os.environ.get("VENDORS_FILE", "env/vendors.json")
    holder = {"daemon": None}

    def loader() -> SignerDaemon:
        if holder["daemon"] is None:
            holder["daemon"] = build_daemon_from_env()
        return holder["daemon"]

    # env/accounts.json is read on the first request, so this process can start before policy writes it.
    uvicorn.run(_lazy_app(loader, vendors_file), host="127.0.0.1", port=args.port)


def _lazy_app(loader, vendors_file=None):
    holder = {"app": None}

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            # answer startup/shutdown ourselves so the loader waits for the first real request
            while True:
                message = await receive()
                await send({"type": message["type"] + ".complete"})
                if message["type"] == "lifespan.shutdown":
                    return
        if holder["app"] is None:
            holder["app"] = create_app(loader(), vendors_file)
        await holder["app"](scope, receive, send)

    return app


if __name__ == "__main__":
    main()
