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
raise NotImplementedError("Phase 2: wrap fuse.policy.service.PolicyService in a FastAPI app")
