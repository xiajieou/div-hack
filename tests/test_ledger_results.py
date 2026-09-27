"""Ledger-results sweep: a code that is not tesSUCCESS is never a success, and tem takes nothing."""
import pytest
from xrpl.models.transactions import TicketCreate
from xrpl.wallet import Wallet

from fuse.ledger.local import LocalLedger, Result
from fuse.registry import setup_local_registry
from fuse.setup import _single_sign


def test_unknown_type_is_tem_and_takes_nothing():
    ledger = LocalLedger()
    wallet = Wallet.create()
    ledger.fund(wallet.classic_address, 20_000_000)
    before = ledger.account(wallet.classic_address).balance_drops
    sequence = ledger.next_sequence(wallet.classic_address)
    tx = _single_sign(TicketCreate(account=wallet.classic_address, ticket_count=1), wallet, sequence, ledger.current_ledger_index() + 20)
    result = ledger.submit(tx)
    assert result.engine_result == "temUNKNOWN"
    assert result.validated is False
    assert result.ok is False
    assert ledger.next_sequence(wallet.classic_address) == sequence
    assert ledger.account(wallet.classic_address).balance_drops == before


def test_ter_and_tec_are_not_success():
    past = Result("terPRE_SEQ", "H", False)
    claimed = Result("tecUNFUNDED_PAYMENT", "H", True)
    assert past.ok is False and claimed.ok is False
    assert Result("tesSUCCESS", "H", True).ok is True


def test_setup_records_a_failed_credential_submit(monkeypatch):
    ledger = LocalLedger()
    vendor = Wallet.create()
    ledger.fund(vendor.classic_address, 20_000_000)
    monkeypatch.setattr("fuse.registry.issue", lambda *args: Result("tecNO_TARGET", "H", True, "no such account"))
    with pytest.raises(RuntimeError, match="tecNO_TARGET"):
        setup_local_registry(ledger, [vendor])
    assert ledger.credentials(vendor.classic_address) == []
