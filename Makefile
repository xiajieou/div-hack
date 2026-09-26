.PHONY: install test demo-local spike setup-testnet topup kill policy daemon reader blast audit-check

install:        ; pip install -r requirements.txt
test:           ; pytest -q
demo-local:     ; python -m fuse.demo
spike:          ; python scripts/spike/run.py
setup-testnet:  ; python scripts/setup_testnet.py
topup:          ; python scripts/topup.py
kill:           ; python scripts/kill_switch.py
policy:         ; uvicorn fuse.policy.api:app --port 8001
daemon:         ; python -m fuse.signer.api --port 8002
reader:         ; python -m fuse.reader.reader --inbox inbox/
blast:          ; python -m fuse.reports.blast_radius --mode testnet
audit-check:    ; python -m fuse.reports.audit_completeness --mode testnet
