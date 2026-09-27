"""Interactive flow view: run one scenario at a time through the real services and watch each part act.

    python -m dashboard.flow [--port 8001] [--net local|devnet]      then open http://localhost:8001/

local (the default) builds a fresh local ledger every reset. devnet uses the accounts scripts/setup_testnet.py created
(env/accounts.json, keys from the environment or .env) and submits real transactions. Either way it runs the real
policy service, signer daemon and ledger checks in this one process, as a demo harness. It holds the agent, policy
and spend keys (the spend key only to pull and restore the kill switch), never the treasury key: a top-up on devnet
is `make topup`, run by a person. This module only
watches: it wraps the functions each part calls, reports what happened to the page as a stream of events, and
can slow each step down so a person can follow it. It never changes a decision, except in the one scenario that
simulates a hacked policy service, which swaps the destination after the payment is built and says so.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional

import httpx
import uvicorn
from xrpl.models.requests import AccountInfo, AccountObjects, AccountTx
from xrpl.models.transactions import DelegateSet, TicketCreate
from xrpl.models.transactions.delegate_set import Permission
from xrpl.transaction import autofill_and_sign, multisign, sign
from xrpl.wallet import Wallet
from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

import fuse.policy.service as policy_service
from fuse.audit import AuditChain
from fuse.breakglass import sign_break_glass
from fuse.config import default_policy, drops_to_xrp
from fuse.ledger.testnet import TestnetLedger
from fuse.policy.builder import invoice_id_hash
from fuse.policy.service import PolicyService
from fuse.setup import _single_sign
from fuse.policy.rules import Intent
from fuse.reader.reader import PROMPT, hidden_text, naive_extract
from fuse.reports.api import build_reports
from fuse.reports.sources import CLEAN_INVOICES, LocalWorld, Network
from fuse.signer.daemon import Refusal, SignerDaemon

ROOT = Path(__file__).resolve().parents[1]
PAGE = Path(__file__).resolve().parent / "flow.html"
BREAK_GLASS = Path(os.environ.get("BREAK_GLASS_FILE", ROOT / "break-glass" / "revoke.json"))
STEP = 0.7          # seconds between steps when the throttle is on
TICK = 0.22         # seconds between checklist items

DAEMON_CHECKS = [
    ("unknown nonce", "the request ID matches a request the reader filed"),
    ("already settled", "that request has not been paid already"),
    ("not a Payment", "it is a Payment"),
    ("Account is not", "it pays from the paying account"),
    ("Delegate is not", "it is sent through the desk"),
    ("Destination does not match", "the destination matches my own vendor record"),
    ("Amount", "the amount is exactly what was requested"),
    ("InvoiceID", "the invoice ID is the one requested"),
    ("Flags", "no special flags (no partial payment)"),
    ("Fee", "the fee is under the cap"),
    ("SigningPubKey", "it is set up for two signatures"),
    ("forbidden field", "no routing tricks (Paths, SendMax, ...)"),
    ("already carries signatures", "nobody has signed it yet"),
]
LEDGER_FAILS = {
    "tefBAD_QUORUM": 0, "tefBAD_SIGNATURE": 0, "tefNOT_MULTI_SIGNING": 0, "tefBAD_AUTH": 0, "tefMASTER_DISABLED": 0,
    "tefPAST_SEQ": 1, "terPRE_SEQ": 1, "tefMAX_LEDGER": 1,
    "terNO_DELEGATE_PERMISSION": 2, "temINVALID": 2,
    "tecUNFUNDED_PAYMENT": 3,
}
MEANING = {
    "tesSUCCESS": "applied",
    "tefBAD_QUORUM": "not enough signatures: the desk needs both keys",
    "tefBAD_SIGNATURE": "a signature is not from the desk's signer list",
    "terNO_DELEGATE_PERMISSION": "the desk has no permission for this",
    "temINVALID": "the ledger refuses this through a delegate",
    "tecUNFUNDED_PAYMENT": "the paying account does not have the money",
}


def _short(addr: str) -> str:
    return addr[:6] + "…" + addr[-4:] if addr else ""


GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
READER_MODEL = os.environ.get("READER_MODEL", "gemini-3.1-flash-lite")
PDF_LABEL = "[hidden text, white on white in the PDF]\n"


def model_extract(invoice_text: str, key: str):
    """Ask a real model, with the reader's own prompt. Returns the intent and the model's raw answer.
    Room for thinking models to finish; 300 tokens cuts them off before the JSON."""
    body = {"model": READER_MODEL, "temperature": 0, "max_tokens": 2000,
            "messages": [{"role": "user", "content": PROMPT + invoice_text}]}
    r = httpx.post(GEMINI_URL, json=body, headers={"Authorization": "Bearer " + key}, timeout=60)
    if r.status_code != 200:
        err = r.json()
        err = err[0] if isinstance(err, list) else err
        raise RuntimeError(f"HTTP {r.status_code}: {err.get('error', {}).get('message', r.text)[:120]}")
    raw = r.json()["choices"][0]["message"]["content"] or ""
    data = json.loads(raw[raw.find("{"): raw.rfind("}") + 1])
    return Intent(vendor=data["vendor"], amount=str(data["amount"]), invoice_id=data["invoice_id"],
                  reason=data.get("reason", ""), claimed_destination=data.get("destination") or None), raw.strip()


def _keys(*names: str) -> Dict[str, str]:
    """Seeds from the environment, else from the .env the setup script wrote."""
    found = {n: os.environ[n] for n in names if os.environ.get(n)}
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            key, _, value = line.partition("=")
            value = value.split("#")[0].strip()
            if key.strip() in names and value:
                found.setdefault(key.strip(), value)
    missing = [n for n in names if n not in found]
    if missing:
        raise SystemExit(f"missing {missing}: run scripts/setup_testnet.py first")
    return found


class NetworkWorld(LocalWorld):
    """The accounts setup_testnet.py created, with the policy service and signer daemon wired in this process."""

    def __init__(self) -> None:
        accounts = json.loads((ROOT / "env" / "accounts.json").read_text())
        keys = _keys("AGENT_SEED", "POLICY_SEED", "SPEND_SEED")
        agent, policy_key, spend = (Wallet.from_seed(keys[k]) for k in ("AGENT_SEED", "POLICY_SEED", "SPEND_SEED"))
        for wallet, name in ((agent, "agent"), (policy_key, "policy"), (spend, "spend")):
            if wallet.classic_address != accounts[name]:
                raise SystemExit(f"the {name} key in .env does not match env/accounts.json; re-run setup")
        self.network = accounts["network"]
        self.ledger = TestnetLedger(accounts["rpc"])
        self.net = Network(self.network)
        self.explorer = accounts["explorer"]
        self.policy = default_policy()
        for name in self.policy.allowlist:
            self.policy.allowlist[name].address = accounts["vendors"][name]
        # spend signs only the kill switch and its undo; it stands where the local ring keeps the paying account
        self.ring = SimpleNamespace(agent=agent, policy=policy_key, treasury=spend,
                                    desk=SimpleNamespace(classic_address=accounts["desk"]), setup_log=[],
                                    attacker=SimpleNamespace(classic_address=accounts["attacker"]),
                                    northwind=SimpleNamespace(classic_address=accounts["northwind"]),
                                    vendors={n: SimpleNamespace(classic_address=a) for n, a in accounts["vendors"].items()})
        self.addresses = {k: accounts[k] for k in ("treasury", "spend", "desk")}
        self.audit = AuditChain(self.policy.hash())
        self.service = PolicyService(self.policy, policy_key, self.ledger, accounts["spend"], accounts["desk"], self.audit,
                                     accounts.get("registry"))
        directory = json.loads((ROOT / "env" / "vendors.json").read_text())
        self.daemon = SignerDaemon(agent, accounts["spend"], accounts["desk"], directory, self.policy.fee_cap_drops,
                                   forward=self.service.handle_intent)
        self.service.attach_daemon(self.daemon)
        # the audit log starts with this process, so only payments made from now on are expected to be in it
        self.before = {t["hash"] for t in self.net.history(accounts["spend"])}
        # the service keeps paid invoices in memory; read them back from the ledger so a restart cannot pay twice
        self.service.paid_invoices |= self._paid_on_ledger(accounts["spend"])

    def _paid_on_ledger(self, spend: str) -> set:
        by_hash = {invoice_id_hash(i): i for i in self.policy.open_purchase_orders}
        paid, marker = set(), None
        while True:
            r = self.ledger.client.request(AccountTx(account=spend, marker=marker)).result
            for e in r.get("transactions", []):
                tx = e.get("tx_json") or e.get("tx", {})
                if (tx.get("TransactionType") == "Payment" and tx.get("Account") == spend
                        and e.get("meta", {}).get("TransactionResult") == "tesSUCCESS" and tx.get("InvoiceID") in by_hash):
                    paid.add(by_hash[tx["InvoiceID"]])
            marker = r.get("marker")
            if not marker:
                return paid

    def facts(self, address: str) -> dict:
        return self.net.facts(address)

    def history(self, address: str) -> List[dict]:
        return [t for t in self.net.history(address) if t["hash"] not in self.before]

    def balance_drops(self, address: str) -> int:
        r = self.ledger.client.request(AccountInfo(account=address, ledger_index="validated")).result
        return int(r["account_data"]["Balance"]) if "account_data" in r else 0

    def restore(self):
        """Undo the kill switch: the paying account grants the desk Payment again."""
        spend, desk = self.addresses["spend"], self.addresses["desk"]
        if self.net.facts(spend)["delegations"].get(desk) == ["Payment"]:
            return None
        tx = DelegateSet(account=spend, authorize=desk, permissions=[Permission(permission_value="Payment")])
        return self.ledger.submit(_single_sign(tx, self.ring.treasury, self.ledger.next_sequence(spend),
                                               self.ledger.current_ledger_index() + 40))

    def _tickets(self) -> List[int]:
        r = self.ledger.client.request(AccountObjects(account=self.addresses["spend"], ledger_index="validated", type="ticket")).result
        return sorted(o["TicketSequence"] for o in r.get("account_objects", []))

    def rearm(self) -> Optional[str]:
        """The break-glass file is good once: its Ticket is used when it lands. Reserve a new Ticket if none is left
        and pre-sign a fresh revoke against it, the way setup does. Returns what was done, or None if still armed."""
        tickets = self._tickets()
        if BREAK_GLASS.exists() and json.loads(BREAK_GLASS.read_text()).get("TicketSequence") in tickets:
            return None
        if not tickets:
            tx = TicketCreate(account=self.addresses["spend"], ticket_count=1)
            r = self.ledger.submit(autofill_and_sign(tx, self.ledger.client, self.ring.treasury).to_xrpl())
            if not r.ok:
                return f"could not reserve a new ticket: {r.engine_result}"
            tickets = self._tickets()
        BREAK_GLASS.parent.mkdir(exist_ok=True)
        BREAK_GLASS.write_text(json.dumps(sign_break_glass(self.ring.treasury, self.addresses["desk"], tickets[0]), indent=2))
        return f"break-glass file re-armed on ticket {tickets[0]}"


class Flow:
    def __init__(self, network: str = "local") -> None:
        self.network = network
        self.world = None
        self.subscribers: List[queue.Queue] = []
        self.run_lock = threading.Lock()
        self.throttle = True
        self.running: Optional[str] = None
        self.tamper = False
        self.actor = "policy"
        self.reader = "scripted"
        try:
            self.model_key = _keys("GEMINI_API_KEY")["GEMINI_API_KEY"]
        except SystemExit:
            self.model_key = ""
        self.reset()

    # ----- the world -----
    def reset(self) -> None:
        note = "Every account, key and vendor was just created again."
        if self.network == "local":
            self.world = LocalWorld(invoices=[])
        elif self.world is None:
            self.world = NetworkWorld()
            note = "Connected to the accounts the setup script created."
        else:
            r = self.world.restore()
            armed = self.world.rearm()
            note = (f"The desk's Payment permission was restored: {r.engine_result}." if r
                    else "The desk still holds its Payment permission.") + (f" {armed[:1].upper()}{armed[1:]}." if armed else "") + \
                " Accounts and history stay as they are."
        w = self.world
        # the human's half of approving Northwind, on the daemon's own list, done at setup
        w.daemon.add_vendor("Northwind Freight", w.ring.northwind.classic_address)
        self.box_of: Dict[str, str] = {w.addresses["spend"]: "spend", w.addresses["treasury"]: "treasury",
                                       w.addresses["desk"]: "desk", w.ring.attacker.classic_address: "attacker_acct"}
        for wallet in [*w.ring.vendors.values(), w.ring.northwind]:
            self.box_of[wallet.classic_address] = "vendors"
        self.vendor_name = {wallet.classic_address: name for name, wallet in w.ring.vendors.items()}
        self.vendor_name[w.ring.northwind.classic_address] = "Northwind Freight"
        self.last_paid: Optional[str] = None
        self.baseline = {"vendors": self._vendor_drops(), "attacker_acct": w.balance_drops(w.ring.attacker.classic_address)}
        if not getattr(w, "_watched", False):
            self._instrument()
            w._watched = True
        self.emit({"type": "reset", "text": note})

    # ----- events -----
    def emit(self, event: dict) -> None:
        for q in list(self.subscribers):
            q.put(event)

    def pause(self, seconds: float = STEP) -> None:
        if self.throttle:
            time.sleep(seconds)

    def state(self, box: str, state: str) -> None:
        self.emit({"type": "state", "box": box, "state": state})

    def log(self, box: str, text: str, level: str = "") -> None:
        self.emit({"type": "log", "box": box, "text": text, "level": level})

    def edge(self, a: str, b: str, label: str = "", kind: str = "") -> None:
        self.emit({"type": "edge", "from": a, "to": b, "label": label, "kind": kind})
        self.pause()

    def checklist(self, box: str, labels: List[str], results: List[str]) -> None:
        """Show every check as pending, then reveal the real results one by one."""
        items = [{"label": l, "state": "pending"} for l in labels]
        self.emit({"type": "checks", "box": box, "items": items})
        for i, r in enumerate(results):
            self.pause(TICK)
            items[i] = {**items[i], "state": r}
            self.emit({"type": "checks", "box": box, "items": [dict(x) for x in items]})

    # ----- watching the real code -----
    def _instrument(self) -> None:
        w = self.world
        global _observer
        _observer = self

        forward = w.daemon._forward
        def daemon_forward(intent):
            self.state("daemon", "active")
            self.log("daemon", f"stored the request under ID {intent.nonce}")
            self.log("daemon", "it will sign only a payment that matches this request exactly")
            self.pause()
            self.state("daemon", "idle")
            self.edge("daemon", "policy", "request")
            self.state("policy", "active")
            self.log("policy", f"request: {intent.amount} XRP to {intent.vendor} for {intent.invoice_id}")
            return forward(intent)
        w.daemon._forward = daemon_forward

        sign = w.daemon.sign
        def daemon_sign(tx, nonce):
            self.state("daemon", "active")
            self.log("daemon", "got a payment to sign; comparing it with the stored request")
            try:
                signed = sign(tx, nonce)
            except Refusal as e:
                failed = next((i for i, (key, _) in enumerate(DAEMON_CHECKS) if key in e.reason), len(DAEMON_CHECKS) - 1)
                self.checklist("daemon", [l for _, l in DAEMON_CHECKS],
                               ["ok"] * failed + ["fail"] + ["skip"] * (len(DAEMON_CHECKS) - failed - 1))
                self.log("daemon", f"refused: {e.reason}", "bad")
                self.state("daemon", "stop")
                raise
            self.checklist("daemon", [l for _, l in DAEMON_CHECKS], ["ok"] * len(DAEMON_CHECKS))
            self.log("daemon", "every field matches: signed with the agent key", "good")
            self.state("daemon", "ok")
            self.edge("daemon", "policy", "agent signature")
            self.state("policy", "active")
            self.log("policy", "checked the agent's signature; added the policy signature (2 of 2)")
            return signed
        w.daemon.sign = daemon_sign

        reserve = w.service.budget.reserve
        def budget_reserve(drops):
            try:
                rid = reserve(drops)
            except Exception as e:
                self.log("policy", f"daily budget: {e}", "bad")
                self.state("policy", "stop")
                raise
            self.log("policy", f"reserved {drops_to_xrp(drops)} XRP against today's cap")
            return rid
        w.service.budget.reserve = budget_reserve

        for name, text in (("commit_proposal", "committed the proposal before signing"),
                           ("append_result", "logged the ledger's answer"), ("refused", "logged the refusal"),
                           ("parked", "logged the parked request"), ("admin", "logged the admin action")):
            self._watch_audit(name, text)

        submit = w.ledger.submit
        def ledger_submit(tx):
            return self.on_submit(tx, submit)
        w.ledger.submit = ledger_submit

    def _watch_audit(self, name: str, text: str) -> None:
        original = getattr(self.world.audit, name)
        def watched(*args, **kwargs):
            h = original(*args, **kwargs)
            self.emit({"type": "edge", "from": "policy", "to": "audit", "label": "", "kind": ""})
            self.state("audit", "ok")
            self.log("audit", f"{text} · row {len(self.world.audit.rows) - 1} · hash {h[:12]}")
            return h
        setattr(self.world.audit, name, watched)

    def on_rules(self, ev) -> None:
        self.checklist("policy", [r.name for r in ev.rules],
                       ["ok" if r.ok else "park" if r.soft else "fail" for r in ev.rules])
        for r in ev.rules:
            if not r.ok:
                self.log("policy", f"{r.name}: {r.note}", "warn" if r.soft else "bad")
        if ev.decision == "refuse":
            self.log("policy", "refused. Nothing is built and nothing is signed.", "bad")
            self.state("policy", "stop")
        elif ev.decision == "park":
            self.log("policy", "parked until a human approves this vendor", "warn")
            self.state("policy", "park")
        self.pause()

    def on_credential(self, ok: bool) -> None:
        self.log("policy", "vendor holds an accepted registry credential" if ok
                 else "vendor has no accepted credential from the registry", "" if ok else "bad")
        if not ok:
            self.log("policy", "refused. Nothing is built and nothing is signed.", "bad")
            self.state("policy", "stop")
        self.pause()

    def on_built(self, tx: dict) -> dict:
        dest = tx["Destination"]
        self.log("policy", f"built the payment: {drops_to_xrp(tx['Amount'])} XRP to {self.vendor_name.get(dest, _short(dest))} "
                           f"{_short(dest)}, address taken from my own vendor records")
        if self.tamper:
            attacker = self.world.ring.attacker.classic_address
            tx = {**tx, "Destination": attacker}
            self.log("policy", f"HACKED: destination swapped to the attacker {_short(attacker)}", "bad")
            self.state("policy", "warn")
        self.edge("policy", "daemon", "payment to sign")
        return tx

    def on_submit(self, tx: dict, submit: Callable) -> object:
        via_desk = bool(tx.get("Delegate"))
        src = self.box_of.get(tx["Account"], "spend")
        target = "desk" if via_desk else src
        if self.actor == "policy":
            self.log("policy", "submitting the two-signature payment to the ledger")
            self.state("policy", "ok")
        who = {"policy": "policy", "attacker": "attacker", "human": "admin"}[self.actor]
        what = tx["TransactionType"] if tx["TransactionType"] != "Payment" else f"{drops_to_xrp(tx['Amount'])} XRP payment"
        self.edge(who, target, what)
        self.state(target, "active")
        if self.world.explorer:
            self.log(target, f"sent to XRPL {self.network}; the ledger answers now, or after the next close if it applies it")
        result = submit(tx)
        code = result.engine_result
        if via_desk:
            n = len(tx.get("Signers") or [])
            labels = [f"signatures meet the desk's 2-of-2 list ({n} given)", "sequence and expiry are valid",
                      f"the desk's permission covers {tx['TransactionType']}", "the paying account has the money"]
        else:
            labels = ["signed with the account's own key", "sequence and expiry are valid", "allowed for this account",
                      "the account has the money"]
        failed = LEDGER_FAILS.get(code, None if code == "tesSUCCESS" else 3)
        results = ["ok"] * 4 if failed is None else ["ok"] * failed + ["fail"] + ["skip"] * (3 - failed)
        if tx["TransactionType"] != "Payment":
            labels, results = labels[:3], results[:3]
        self.checklist(target, labels, results)
        self.log(target, f"{code}: {MEANING.get(code, result.message or '')}", "good" if code == "tesSUCCESS" else "bad")
        if self.world.explorer and code[:3] in ("tes", "tec"):
            self.log(target, f"{self.world.explorer}/transactions/{result.hash}")
        if code[:3] in ("tef", "tem", "tel", "ter"):
            self.log(target, "rejected before reaching a ledger: no fee, and not in the account's history or on the explorer")
        self.state(target, "ok" if code == "tesSUCCESS" else "stop")
        if code == "tesSUCCESS" and tx["TransactionType"] == "Payment":
            dest = self.box_of.get(tx["Destination"], "vendors")
            if via_desk:
                self.edge("desk", "spend", "acts for")
            self.edge(src, dest, f"{drops_to_xrp(tx['Amount'])} XRP", "money")
            self.state(dest, "ok")
            self.log(dest, f"received {drops_to_xrp(tx['Amount'])} XRP" +
                     (f" ({self.vendor_name[tx['Destination']]})" if tx["Destination"] in self.vendor_name else ""), "good")
        self.emit({"type": "reports"})
        self.pause()
        return result

    # ----- scenarios -----
    def invoice(self, name: str):
        """Hand one invoice file to the reader, then to the daemon, which forwards it to the policy service."""
        text = self.world.invoice_text(name)
        hidden = hidden_text(text)
        self.emit({"type": "invoice", "text": text, "hidden": hidden})
        self.state("invoice", "warn" if hidden else "active")
        self.log("invoice", text.splitlines()[0])
        self.edge("invoice", "reader", "invoice")
        if not hidden:
            self.state("invoice", "ok")
        self.state("reader", "active")
        intent = None
        if self.reader == "model":
            # what a PDF text layer gives a model: the white-on-white text, with nothing marking it as hidden
            self.log("reader", f"asking {READER_MODEL} to read the invoice")
            try:
                intent, raw = model_extract(text.replace(PDF_LABEL, ""), self.model_key)
                self.log("reader", f"model answered: {raw}")
            except Exception as e:
                self.log("reader", f"model call failed ({e}); the scripted reader takes over", "warn")
        if intent is None:
            intent, _ = naive_extract(text)
        self.log("reader", f"read: vendor {intent.vendor}, amount {intent.amount} XRP, invoice {intent.invoice_id}")
        visible = re.search(r"Amount due:\s*([\d.]+)", text).group(1)
        self.fooled = bool(intent.claimed_destination) or Decimal(str(intent.amount or 0)) != Decimal(visible)
        if self.fooled:
            self.log("reader", "followed an instruction hidden in the invoice", "warn")
            self.log("reader", f"now asking for {intent.amount} XRP" +
                     (f" to {_short(intent.claimed_destination)}" if intent.claimed_destination else ""), "warn")
            self.state("reader", "warn")
        else:
            if hidden:
                self.log("reader", "ignored the hidden instruction", "good")
            self.state("reader", "ok")
        self.edge("reader", "daemon", "request")
        nonce = self.world.daemon.register(intent)
        outcome = self.world.service.outcomes[nonce]
        if outcome.status == "paid":
            self.last_paid = name
        return outcome

    def verdict_for(self, outcome) -> dict:
        if outcome.status == "paid":
            link = f"{self.world.explorer}/transactions/{outcome.tx_hash}" if self.world.explorer else ""
            return {"kind": "paid", "title": "Paid, on its own, within the rules", "text": outcome.message, "link": link}
        if outcome.status == "parked":
            return {"kind": "park", "title": "Parked for a human", "text": "Every rule passed except one: nobody has approved this vendor yet."}
        if outcome.status == "rejected_by_ledger":
            return {"kind": "stop", "title": "Stopped by the ledger", "by": "desk",
                    "text": f"{outcome.engine_result}: {MEANING.get(outcome.engine_result, '')}"}
        by = "daemon" if any("signer daemon" in f for f in outcome.failed) else "policy"
        who = "the signer daemon" if by == "daemon" else "the policy service"
        return {"kind": "stop", "title": f"Stopped by {who}", "by": by,
                "text": "Nothing was signed. " + "; ".join(outcome.failed)}

    def s_normal(self):
        todo = [n for n in CLEAN_INVOICES if f"INV-{n.split('_')[1]}" not in self.world.service.paid_invoices]
        if not todo:
            return {"kind": "info", "title": "All three clean invoices are paid", "text": "Press Reset to start over."}
        return self.verdict_for(self.invoice(todo[0]))

    def s_duplicate(self):
        if not self.last_paid:
            self.invoice(CLEAN_INVOICES[0])
            self.pause()
        return self.verdict_for(self.invoice(self.last_paid or CLEAN_INVOICES[0]))

    def s_overcap(self):
        return self.verdict_for(self.invoice("inv_9001_lumen_prepay.txt"))

    def s_poisoned(self):
        v = self.verdict_for(self.invoice("inv_2201_verdant_REISSUE.txt"))
        if self.reader == "model":
            v["text"] = (f"The AI ({READER_MODEL}) was fooled. " if self.fooled else
                         f"The AI ({READER_MODEL}) ignored the hidden text this time; the rules did not depend on it. ") + v["text"]
        return v

    def s_unknown(self):
        return self.verdict_for(self.invoice("inv_5510_northwind.txt"))

    def _admin_adds_northwind(self, address: str, actor: str):
        if "INV-5510" in self.world.service.paid_invoices:
            return {"kind": "info", "title": "Northwind is already approved and paid", "text": "Press Reset to try this again."}
        parked = any(i.vendor == "Northwind Freight" for i in self.world.service.parked.values())
        if not parked and "Northwind Freight" not in self.world.policy.allowlist:
            self.invoice("inv_5510_northwind.txt")
            self.pause()
        self.actor = "human"
        self.state("admin", "active")
        self.log("admin", f"{actor} approves Northwind Freight at {_short(address)}, US")
        self.edge("admin", "policy", "add vendor")
        self.state("admin", "ok")
        self.state("policy", "active")
        self.log("policy", "vendor list changed, so the policy hash changed; rerunning the parked request")
        self.actor = "policy"
        reruns = self.world.service.admin_add_vendor("Northwind Freight", address, "US", actor=actor)
        return self.verdict_for(reruns[0] if reruns else self.invoice("inv_5510_northwind.txt"))

    def s_approve(self):
        return self._admin_adds_northwind(self.world.ring.northwind.classic_address, "cfo")

    def s_corrupt(self):
        return self._admin_adds_northwind(self.world.ring.attacker.classic_address, "a corrupt admin")

    def s_hacked_policy(self):
        self.tamper = True
        try:
            return self.verdict_for(self.invoice("inv_3300_harbor_after_revoke.txt"))
        finally:
            self.tamper = False

    def s_forged(self):
        self.actor = "attacker"
        self.state("attacker", "active")
        self.log("attacker", "sends a payment request straight to the policy service, skipping the reader and daemon")
        self.edge("attacker", "policy", "forged request")
        self.state("attacker", "idle")
        self.actor = "policy"
        self.state("policy", "active")
        intent = Intent(vendor="Harbor Cloud Hosting", amount="5", invoice_id="INV-3300", reason="forged", nonce="forged-1")
        self.log("policy", "request: 5 XRP to Harbor Cloud Hosting for INV-3300")
        return self.verdict_for(self.world.service.handle_intent(intent))

    def s_agent_key(self):
        self.actor = "attacker"
        self.state("attacker", "active")
        self.log("attacker", "holds the agent key only")
        self.log("attacker", "signs 50 XRP to itself and sends it straight to the ledger")
        r = self.world.agent_key_alone(Decimal("50"))
        return {"kind": "stop", "title": "Stopped by the ledger", "by": "desk", "text": f"{r.engine_result}: {MEANING.get(r.engine_result, '')}"}

    def s_drain(self):
        self.actor = "attacker"
        self.state("attacker", "active")
        self.log("attacker", "holds BOTH keys, and pays itself around the policy service", "bad")
        w = self.world
        start = w.balance_drops(w.addresses["spend"])
        chunk = Decimal("100") if self.network == "local" else max(Decimal(1), (drops_to_xrp(start) / 3).quantize(Decimal(1)))
        for n in range(1, 10):
            r = w.ledger.submit(self._both_keys_payment(chunk, n))
            if not r.ok:
                break
        taken = start - w.balance_drops(w.addresses["spend"])
        treasury = w.balance_drops(w.addresses["treasury"])
        return {"kind": "capped", "title": f"Loss capped at the float: {drops_to_xrp(taken)} XRP",
                "text": f"The treasury ({drops_to_xrp(treasury)} XRP) was never reachable. Audit completeness now flags every one of these payments."}

    def _both_keys_payment(self, amount: Decimal, n: int) -> dict:
        tx = self.world._attacker_payment(amount, n)
        return multisign(tx, [sign(tx, self.world.ring.agent, multisign=True), sign(tx, self.world.ring.policy, multisign=True)]).to_xrpl()

    def s_take_over(self):
        self.actor = "attacker"
        self.state("attacker", "active")
        self.log("attacker", "holds both keys and tries to make itself the paying account's only signer", "bad")
        r = self.world.take_over()
        return {"kind": "stop", "title": "Stopped by the ledger", "by": "desk",
                "text": f"{r.engine_result}: the desk may send Payments and nothing else."}

    def s_top_up(self):
        if self.network != "local":
            self.state("admin", "active")
            self.log("admin", "the treasury key stays with a person: run make topup in a terminal")
            return {"kind": "info", "title": "A person tops up",
                    "text": "Run make topup in a terminal: it signs with the treasury key, which this page never holds. "
                            "The paying account's balance here updates when it lands."}
        self.actor = "human"
        self.state("admin", "active")
        self.log("admin", "signs 100 XRP from the treasury to the paying account with the treasury key")
        r = self.world.top_up(Decimal("100"))
        self.state("admin", "ok")
        return {"kind": "paid" if r.ok else "stop", "title": "Refilled by a human" if r.ok else "Top-up failed",
                "text": f"{r.engine_result}. No program holds the treasury key."}

    def s_kill(self):
        self.actor = "human"
        self.state("admin", "active")
        if self.network != "local" and BREAK_GLASS.exists():
            self.log("admin", "pulls the kill switch: submits break-glass/revoke.json, signed at setup; no key is used now")
            r = self.world.ledger.submit(json.loads(BREAK_GLASS.read_text()))
        else:
            self.log("admin", "pulls the kill switch: the paying account revokes the desk's permission")
            self.log("admin", "signed with the paying account's key: the local ledger has no tickets, so no pre-signed file here", "warn")
            r = self.world.revoke()
        self.state("admin", "ok")
        self.pause()
        self.actor = "policy"
        v = self.verdict_for(self.invoice("inv_3300_harbor_after_revoke.txt"))
        if v["kind"] == "stop" and v.get("by") == "desk":
            v["title"] = "Kill switch held"
            v["text"] = f"Revoke: {r.engine_result}. Then a fully signed payment: {v['text']}."
        return v

    SCENARIOS = {
        "normal": ("Normal payment", "A real invoice arrives. The agent pays it on its own, within the rules.", "s_normal"),
        "duplicate": ("Same invoice twice", "The agent tries to pay an invoice that is already paid.", "s_duplicate"),
        "overcap": ("Too big", "A 48 XRP prepayment, over the 25 XRP per-payment cap.", "s_overcap"),
        "unknown": ("New vendor", "An invoice from a vendor nobody has approved yet.", "s_unknown"),
        "approve": ("Admin approves vendor", "A human approves Northwind Freight; the parked invoice reruns.", "s_approve"),
        "poisoned": ("Poisoned invoice", "Hidden text tells the AI to send 50 XRP to a new account. The AI obeys.", "s_poisoned"),
        "forged": ("Forged request", "Someone skips the AI and asks the policy service directly.", "s_forged"),
        "hacked_policy": ("Hacked policy service", "The policy service is compromised and swaps the destination.", "s_hacked_policy"),
        "corrupt": ("Corrupt admin", "An insider approves Northwind Freight with the attacker's address.", "s_corrupt"),
        "agent_key": ("Stolen agent key", "An attacker signs a payment to itself with the agent key alone.", "s_agent_key"),
        "drain": ("Both keys stolen", "The attacker holds both keys and pays itself until the money runs out.", "s_drain"),
        "take_over": ("Take over the account", "With both keys, the attacker tries to seize the paying account.", "s_take_over"),
        "top_up": ("Top up", "A human refills the paying account from the treasury.", "s_top_up"),
        "kill": ("Kill switch", "Revoke the desk's permission, then try a fully signed payment.", "s_kill"),
    }

    def run(self, name: str, throttle: bool, reader: str = "scripted") -> bool:
        if name not in self.SCENARIOS or not self.run_lock.acquire(blocking=False):
            return False
        title, blurb, method = self.SCENARIOS[name]
        self.throttle, self.running, self.actor = throttle, name, "policy"
        self.reader = "model" if reader == "model" and self.model_key else "scripted"

        def go():
            try:
                self.emit({"type": "start", "scenario": name, "title": title, "blurb": blurb})
                verdict = getattr(self, method)()
            except Exception as e:
                verdict = {"kind": "stop", "title": "Error", "text": f"{type(e).__name__}: {e}"}
            finally:
                self.actor, self.running = "policy", None
                self.run_lock.release()
            self.emit({"type": "end", "scenario": name, **verdict})
            self.emit({"type": "reports"})

        threading.Thread(target=go, daemon=True).start()
        return True

    NETWORK_BLURBS = {
        "approve": "A human approves Northwind Freight. On devnet it holds no registry credential, so the rules still refuse it.",
        "top_up": "A person refills the paying account with make topup; this page never holds the treasury key.",
        "kill": "Submit the pre-signed break-glass file (no key), then try a fully signed payment. Reset re-arms it.",
    }

    def _vendor_drops(self) -> int:
        w = self.world
        return sum(w.balance_drops(x.classic_address) for x in [*w.ring.vendors.values(), w.ring.northwind])

    def snapshot(self) -> dict:
        w = self.world
        rep = build_reports(w.service, w.addresses, w)
        bal = lambda a: str(drops_to_xrp(w.balance_drops(a)))
        spend = rep["blast"]["accounts"]["spend"] if "blast" in rep else {"delegations": {}}
        blurbs = self.NETWORK_BLURBS if self.network != "local" else {}
        return {**rep, "network": self.network, "running": self.running, "policy_hash": w.policy.hash(),
                "balances": {"spend": bal(w.addresses["spend"]), "treasury": bal(w.addresses["treasury"]),
                             "desk": bal(w.addresses["desk"]),
                             "vendors": str(drops_to_xrp(self._vendor_drops() - self.baseline["vendors"])),
                             "attacker_acct": str(drops_to_xrp(w.balance_drops(w.ring.attacker.classic_address)
                                                               - self.baseline["attacker_acct"]))},
                "delegation": ", ".join(spend["delegations"].get(w.addresses["desk"], [])),
                "reader": {"model": READER_MODEL, "available": bool(self.model_key)},
                "scenarios": [{"id": k, "title": t, "blurb": blurbs.get(k, b)} for k, (t, b, _) in self.SCENARIOS.items()]}


_observer: Optional[Flow] = None
_evaluate, _build, _credential = policy_service.evaluate, policy_service.build_payment, policy_service.vendor_has_accepted_credential


def _watching() -> bool:
    return bool(_observer and _observer.running)


def _watched_evaluate(*args, **kwargs):
    ev = _evaluate(*args, **kwargs)
    if _watching():
        _observer.on_rules(ev)
    return ev


def _watched_build(*args, **kwargs):
    tx = _build(*args, **kwargs)
    return _observer.on_built(tx) if _watching() else tx


def _watched_credential(*args, **kwargs):
    ok = _credential(*args, **kwargs)
    if _watching():
        _observer.on_credential(ok)
    return ok


policy_service.evaluate = _watched_evaluate
policy_service.build_payment = _watched_build
policy_service.vendor_has_accepted_credential = _watched_credential


def create_app(flow: Flow) -> FastAPI:
    app = FastAPI()

    @app.get("/")
    def page():
        return FileResponse(PAGE)

    @app.get("/flow/state")
    def state():
        return flow.snapshot()

    @app.post("/flow/run")
    def run(body: dict = Body()):
        if not flow.run(body.get("scenario", ""), bool(body.get("throttle", True)), body.get("reader", "scripted")):
            return JSONResponse(status_code=409, content={"error": "a scenario is already running, or the name is unknown"})
        return {"started": body.get("scenario")}

    @app.post("/flow/reset")
    def reset():
        if flow.running:
            return JSONResponse(status_code=409, content={"error": "a scenario is running"})
        flow.reset()
        return {"ok": True}

    @app.get("/flow/events")
    def events():
        q: queue.Queue = queue.Queue()
        flow.subscribers.append(q)

        def stream():
            try:
                yield "data: {\"type\": \"hello\"}\n\n"
                while True:
                    try:
                        yield f"data: {json.dumps(q.get(timeout=15))}\n\n"
                    except queue.Empty:
                        yield ": keepalive\n\n"
            finally:
                flow.subscribers.remove(q)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    return app


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fuse interactive flow view")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--net", choices=["local", "devnet"], default="local")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    app = create_app(Flow(args.net))
    print(f"Fuse flow view ({args.net}): http://localhost:{args.port}/", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", timeout_graceful_shutdown=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
