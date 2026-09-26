"""Signer daemon over HTTP. Phase 3, owner: Core.

The agent key never appears in any response.
The verifier in fuse/signer/daemon.py is called, not modified.
"""
from __future__ import annotations

from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse

from ..policy.rules import Intent
from .daemon import Refusal, SignerDaemon


def create_app(daemon: SignerDaemon) -> FastAPI:
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
