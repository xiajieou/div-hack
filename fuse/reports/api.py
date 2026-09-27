"""Read-only routes for the dashboard, added to the policy service's app. Nothing here holds or asks for a key.

    GET /dashboard   the dashboard page
    GET /reports     blast radius and audit completeness, read from the ledger the service uses
    GET /invoices    the invoice files in the inbox, with any hidden text pulled out
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse

from ..reader.reader import hidden_text
from .audit_completeness import unlogged_payments
from .blast_radius import blast_radius, read_snapshot
from .sources import load_addresses, log_hashes, source_for

PAGE = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"


def service_addresses(service) -> Dict[str, str]:
    """The service pays from the account it calls treasury. A separate treasury comes from env/accounts.json when
    setup wrote a distinct spend account; otherwise the paying account is the treasury, and the report says so."""
    paying = service.treasury
    try:
        accounts = load_addresses({})
    except SystemExit:
        accounts = {}
    treasury = accounts["treasury"] if accounts.get("spend") == paying else paying
    return {"spend": paying, "desk": service.desk, "treasury": treasury}


def build_reports(service, where: Dict[str, str]) -> dict:
    """Blast radius and audit completeness for a running service, read from the ledger it uses."""
    source = source_for(service.ledger)
    try:
        snapshot = read_snapshot(source, where)
        history = source.history(where["spend"])
    except SystemExit as e:
        return {"error": str(e)}
    rows, findings = blast_radius(snapshot)
    outgoing = [t for t in history if t["type"] == "Payment" and t["account"] == where["spend"] and t["result"] == "tesSUCCESS"]
    missing = unlogged_payments(history, log_hashes(service.audit.dump()), where["spend"])
    return {
        "network": "local" if not source.explorer else source.explorer.split("//")[1].split(".")[0],
        "explorer": source.explorer,
        "break_glass_file": os.path.exists(os.environ.get("BREAK_GLASS_FILE", "break-glass/revoke.json")),
        "blast": {"accounts": {k: snapshot[k] for k in ("spend", "desk", "treasury")},
                  "rows": [r.__dict__ for r in rows], "findings": [f.text for f in findings]},
        "audit": {"spend": where["spend"], "outgoing": len(outgoing), "unlogged": missing},
    }


def add_routes(app: FastAPI, service, addresses: Optional[Dict[str, str]] = None, inbox: str = "inbox") -> None:
    @app.get("/dashboard")
    def dashboard():
        return FileResponse(PAGE)

    @app.get("/reports")
    def reports():
        return build_reports(service, addresses or service_addresses(service))

    @app.get("/invoices")
    def invoices():
        out = []
        for path in sorted(Path(inbox).glob("*.txt")):
            text = path.read_text()
            m = re.search(r"INVOICE\s+(INV-\d+)", text)
            out.append({"file": path.name, "invoice_id": m.group(1) if m else "", "text": text, "hidden": hidden_text(text)})
        return out
