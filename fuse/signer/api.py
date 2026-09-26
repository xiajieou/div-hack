"""Signer daemon over HTTP. Phase 3, owner: Core.

Boundary: three processes running locally (reader, daemon, policy); drop the three clean fixtures into inbox/
and see three tesSUCCESS results; pytest tests/test_acceptance.py -q -k ac08 still green.

Endpoints:
    POST /register   intent -> {nonce}; the daemon forwards the intent to the policy service
    POST /sign       {tx, nonce} -> signed transaction, or 403 with the refusal reason
    POST /settle     {nonce}
The agent key is loaded from AGENT_SEED and never returned by any endpoint. The verifier in fuse/signer/daemon.py
is human-owned; call it, do not modify it.
"""
raise NotImplementedError("Phase 3: expose fuse.signer.daemon.SignerDaemon over HTTP")
