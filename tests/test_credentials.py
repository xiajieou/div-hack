"""Vendor credentials: Credential entries on the local ledger and the policy hook that reads them."""
from xrpl.models.transactions import CredentialAccept, CredentialCreate, CredentialDelete
from xrpl.wallet import Wallet

from fuse.ledger.local import LSF_ACCEPTED, LocalLedger
from fuse.setup import _single_sign

TYPE_HEX = b"verified-vendor".hex().upper()


def _submit(ledger, model, wallet):
    return ledger.submit(_single_sign(model, wallet, ledger.next_sequence(wallet.classic_address), ledger.current_ledger_index() + 20))


def _ledger_with(*wallets):
    ledger = LocalLedger()
    for w in wallets:
        ledger.fund(w.classic_address, 20_000_000)
    return ledger


def test_create_then_accept_sets_the_accepted_flag():
    registry, vendor = Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, vendor)
    r = _submit(ledger, CredentialCreate(account=registry.classic_address, subject=vendor.classic_address, credential_type=TYPE_HEX), registry)
    assert r.engine_result == "tesSUCCESS"
    [entry] = ledger.credentials(vendor.classic_address)
    assert entry["Issuer"] == registry.classic_address and entry["CredentialType"] == TYPE_HEX
    assert not entry["Flags"] & LSF_ACCEPTED
    r = _submit(ledger, CredentialAccept(account=vendor.classic_address, issuer=registry.classic_address, credential_type=TYPE_HEX), vendor)
    assert r.engine_result == "tesSUCCESS"
    assert ledger.credentials(vendor.classic_address)[0]["Flags"] & LSF_ACCEPTED
    assert ledger.credentials(registry.classic_address) == []


def test_documented_error_codes():
    registry, vendor, stranger = Wallet.create(), Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, vendor, stranger)
    unfunded = Wallet.create().classic_address
    create = lambda subject: CredentialCreate(account=registry.classic_address, subject=subject, credential_type=TYPE_HEX)
    accept = CredentialAccept(account=vendor.classic_address, issuer=registry.classic_address, credential_type=TYPE_HEX)
    assert _submit(ledger, create(unfunded), registry).engine_result == "tecNO_TARGET"
    assert _submit(ledger, accept, vendor).engine_result == "tecNO_ENTRY"
    assert _submit(ledger, create(vendor.classic_address), registry).engine_result == "tesSUCCESS"
    assert _submit(ledger, create(vendor.classic_address), registry).engine_result == "tecDUPLICATE"
    assert _submit(ledger, accept, vendor).engine_result == "tesSUCCESS"
    assert _submit(ledger, accept, vendor).engine_result == "tecDUPLICATE"
    by_stranger = CredentialDelete(account=stranger.classic_address, subject=vendor.classic_address, issuer=registry.classic_address, credential_type=TYPE_HEX)
    assert _submit(ledger, by_stranger, stranger).engine_result == "tecNO_PERMISSION"
    assert len(ledger.credentials(vendor.classic_address)) == 1


def test_issuer_can_revoke_and_subject_can_delete():
    registry, vendor = Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, vendor)
    create = CredentialCreate(account=registry.classic_address, subject=vendor.classic_address, credential_type=TYPE_HEX)
    _submit(ledger, create, registry)
    revoke = CredentialDelete(account=registry.classic_address, subject=vendor.classic_address, credential_type=TYPE_HEX)
    assert _submit(ledger, revoke, registry).engine_result == "tesSUCCESS"
    assert ledger.credentials(vendor.classic_address) == []
    assert _submit(ledger, revoke, registry).engine_result == "tecNO_ENTRY"
    _submit(ledger, create, registry)
    by_subject = CredentialDelete(account=vendor.classic_address, issuer=registry.classic_address, credential_type=TYPE_HEX)
    assert _submit(ledger, by_subject, vendor).engine_result == "tesSUCCESS"
    assert ledger.credentials(vendor.classic_address) == []


def test_credential_transactions_are_signature_checked():
    registry, vendor, attacker = Wallet.create(), Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, vendor, attacker)
    forged = CredentialCreate(account=registry.classic_address, subject=vendor.classic_address, credential_type=TYPE_HEX)
    r = ledger.submit(_single_sign(forged, attacker, ledger.next_sequence(registry.classic_address), ledger.current_ledger_index() + 20))
    assert r.engine_result == "tefBAD_AUTH"
    assert ledger.credentials(vendor.classic_address) == []
