"""Vendor credentials: Credential entries on the local ledger and the policy hook that reads them."""
from xrpl.models.transactions import CredentialAccept, CredentialCreate, CredentialDelete
from xrpl.wallet import Wallet

from fuse.ledger.local import LSF_ACCEPTED, LocalLedger
from fuse.registry import CREDENTIAL_TYPE_HEX, setup_local_registry
from fuse.setup import _single_sign
from tests.test_acceptance import world

TYPE_HEX = b"verified-vendor".hex().upper()


def _accepted_from(ledger, address, registry_address):
    return [c for c in ledger.credentials(address)
            if c["Issuer"] == registry_address and c["CredentialType"] == CREDENTIAL_TYPE_HEX and c["Flags"] & LSF_ACCEPTED]


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


def test_world_vendors_hold_accepted_credentials_and_the_attacker_none(world):
    assert CREDENTIAL_TYPE_HEX == TYPE_HEX
    ledger, ring, registry = world["ledger"], world["ring"], world["registry"]
    assert world["service"].registry == registry.classic_address
    for w in [*ring.vendors.values(), ring.northwind]:
        assert len(_accepted_from(ledger, w.classic_address, registry.classic_address)) == 1
    assert ledger.credentials(ring.attacker.classic_address) == []


def test_setup_local_registry_issues_and_accepts_once_per_vendor():
    vendors = [Wallet.create(), Wallet.create()]
    ledger = _ledger_with(*vendors)
    registry = setup_local_registry(ledger, vendors)
    assert all(len(_accepted_from(ledger, v.classic_address, registry.classic_address)) == 1 for v in vendors)
    types = [h["type"] for h in ledger.history]
    assert types == ["CredentialCreate", "CredentialAccept"] * 2
    assert all(h["result"] == "tesSUCCESS" for h in ledger.history)


def test_credential_transactions_are_signature_checked():
    registry, vendor, attacker = Wallet.create(), Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, vendor, attacker)
    forged = CredentialCreate(account=registry.classic_address, subject=vendor.classic_address, credential_type=TYPE_HEX)
    r = ledger.submit(_single_sign(forged, attacker, ledger.next_sequence(registry.classic_address), ledger.current_ledger_index() + 20))
    assert r.engine_result == "tefBAD_AUTH"
    assert ledger.credentials(vendor.classic_address) == []
