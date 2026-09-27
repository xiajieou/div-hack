.PHONY: install test demo-local spike setup-testnet topup kill policy daemon reader blast audit-check dashboard flow

MODE ?= local

install:        ; pip install -r requirements.txt
test:           ; pytest -q
demo-local:     ; python -m fuse.demo
spike:          ; python scripts/spike/run.py
setup-testnet:  ; python scripts/setup_testnet.py
topup:          ; python scripts/topup.py
kill:           ; python scripts/kill_switch.py
env = set -a; [ -f .env ] && . ./.env; set +a;
policy:         ; $(env) env -u AGENT_SEED -u TREASURY_SEED -u SPEND_SEED -u REGISTRY_SEED -u OPENROUTER_API_KEY uvicorn fuse.policy.api:app --port 8001
daemon:         ; $(env) env -u POLICY_SEED -u TREASURY_SEED -u SPEND_SEED -u REGISTRY_SEED -u OPENROUTER_API_KEY python -m fuse.signer.api --port 8002
reader:         ; $(env) env -u AGENT_SEED -u POLICY_SEED -u TREASURY_SEED -u SPEND_SEED -u REGISTRY_SEED python -m fuse.reader.reader --inbox inbox/
blast:          ; python -m fuse.reports.blast_radius --mode $(MODE)
audit-check:    ; python -m fuse.reports.audit_completeness --mode $(MODE)
dashboard:      ; python -m dashboard.serve
flow:           ; python -m dashboard.flow
