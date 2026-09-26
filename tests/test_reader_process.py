import json

from fuse.reader.reader import INVOICES, main, naive_extract, poll


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
