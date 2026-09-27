import json

import httpx

from fuse.reader import reader
from fuse.reader.reader import INVOICES, llm_extract, llm_or_naive, main, naive_extract, pick_extractor, poll


class _Reply:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self.content}}]}


def test_llm_extract_sends_only_the_invoice_and_parses_the_reply(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENROUTER_MODEL", "some/model")
    attacker = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
    invoice = INVOICES["inv_2201_verdant_REISSUE.txt"].replace("{ATTACKER}", attacker)
    calls = []

    def fake_post(url, json, headers, timeout):
        calls.append((url, json, headers))
        return _Reply('Sure:\n{"vendor": "Verdant Print Co", "amount": 50, "invoice_id": "INV-2201", '
                      f'"destination": "{attacker}", "reason": "banking details changed"}}')

    monkeypatch.setattr(reader.httpx, "post", fake_post)
    intent, reason = llm_extract(invoice)
    url, body, headers = calls[0]
    assert url == reader.OPENROUTER_URL and body["model"] == "some/model" and body["temperature"] == 0
    assert headers == {"Authorization": "Bearer sk-or-test"}
    assert body["messages"][0]["content"] == reader.PROMPT + invoice
    assert (intent.vendor, intent.amount, intent.invoice_id, intent.claimed_destination) == \
        ("Verdant Print Co", "50", "INV-2201", attacker)
    assert reason == "banking details changed"


def test_llm_failure_falls_back_to_the_deterministic_extractor(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def dead(*args, **kwargs):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(reader.httpx, "post", dead)
    intent, _ = llm_or_naive(INVOICES["inv_0092_lumen.txt"])
    assert (intent.vendor, intent.amount, intent.invoice_id) == ("Lumen Legal", "21.00", "INV-0092")
    assert "model call failed (ConnectError)" in capsys.readouterr().err

    monkeypatch.setattr(reader.httpx, "post", lambda *a, **k: _Reply("not json at all"))
    intent, _ = llm_or_naive(INVOICES["inv_0092_lumen.txt"])
    assert intent.amount == "21.00"


def test_pick_extractor_needs_a_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert pick_extractor() == (naive_extract, "naive (deterministic)")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    extract, name = pick_extractor()
    assert extract is llm_or_naive and reader.DEFAULT_MODEL in name and "sk-or" not in name


def test_file_is_posted_exactly_once_across_two_polls(tmp_path):
    (tmp_path / "inv_2201_verdant.txt").write_text(INVOICES["inv_2201_verdant.txt"])
    (tmp_path / ".gitkeep").write_text("")
    posted = []

    def post(body):
        posted.append(body)
        return {"nonce": "abc", "outcome": {"status": "paid", "engine_result": "tesSUCCESS"}}

    seen = set()
    first = poll(str(tmp_path), seen, post, naive_extract)
    second = poll(str(tmp_path), seen, post, naive_extract)
    assert len(posted) == 1
    assert posted[0] == {"vendor": "Verdant Print Co", "amount": "12.40", "invoice_id": "INV-2201",
                         "reason": "invoice INV-2201 from Verdant Print Co, matches its purchase order",
                         "claimed_destination": None}
    assert "nonce" not in posted[0]
    assert first == ["inv_2201_verdant.txt  Verdant Print Co  12.40 XRP  -> paid tesSUCCESS"]
    assert second == []


def test_poisoned_invoice_posts_only_an_intent(tmp_path):
    attacker = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
    (tmp_path / "poison.txt").write_text(INVOICES["inv_2201_verdant_REISSUE.txt"].replace("{ATTACKER}", attacker))
    posted = []
    poll(str(tmp_path), set(), lambda body: posted.append(body) or {"outcome": {"status": "refused"}}, naive_extract)
    assert posted[0]["amount"] == "50" and posted[0]["claimed_destination"] == attacker
    assert set(posted[0]) == {"vendor", "amount", "invoice_id", "reason", "claimed_destination"}


def test_daemon_error_is_a_line_not_a_crash(tmp_path):
    (tmp_path / "a_lumen.txt").write_text(INVOICES["inv_0092_lumen.txt"])
    (tmp_path / "b_harbor.txt").write_text(INVOICES["inv_7734_harbor.txt"])
    calls = []

    def post(body):
        calls.append(body["vendor"])
        if len(calls) == 1:
            raise httpx.ConnectError("connection refused")
        return {"outcome": {"status": "paid", "engine_result": "tesSUCCESS"}}

    lines = poll(str(tmp_path), set(), post, naive_extract)
    assert calls == ["Lumen Legal", "Harbor Cloud Hosting"]
    assert lines[0].endswith("-> error: connection refused")
    assert lines[1].endswith("-> paid tesSUCCESS")


def test_write_fixtures_uses_attacker_from_accounts_file(tmp_path, monkeypatch, capsys):
    accounts = tmp_path / "accounts.json"
    accounts.write_text(json.dumps({"attacker": "rATTACKER"}))
    monkeypatch.setenv("ACCOUNTS_FILE", str(accounts))
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    assert main(["--inbox", str(inbox), "--write-fixtures"]) == 0
    written = sorted(p.name for p in (inbox / "fixtures").iterdir())
    assert written == sorted(INVOICES)
    assert "rATTACKER" in (inbox / "fixtures" / "inv_2201_verdant_REISSUE.txt").read_text()
    assert not [p for p in inbox.iterdir() if p.is_file()]
