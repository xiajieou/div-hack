"""Vendor credentials: Credential entries on the local ledger and the policy hook that reads them."""
from xrpl.models.transactions import CredentialAccept, CredentialCreate, CredentialDelete
from xrpl.wallet import Wallet

from fuse.ledger.local import LSF_ACCEPTED, LocalLedger
from fuse.policy.credentials import vendor_has_accepted_credential
from fuse.registry import CREDENTIAL_TYPE_HEX, issue, revoke, setup_local_registry
from fuse.setup import _single_sign
from tests.test_acceptance import run_intent, world

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


# ----- the policy hook -----
def _refused_for_credential(world, outcome):
    assert outcome.status == "refused"
    assert any("accepted registry credential" in f for f in outcome.failed)
    assert world["daemon"].intents[outcome.intent["nonce"]].signatures_issued == 0
    assert world["service"].budget.committed_drops() == 0


def test_allowlisted_vendor_without_accepted_credential_is_refused(world):
    ledger, ring, registry = world["ledger"], world["ring"], world["registry"]
    lumen = ring.vendors["Lumen Legal"]
    before = len(ledger.history)
    # issued but never accepted: the registry alone cannot make a vendor payable
    assert revoke(ledger, registry, lumen.classic_address).ok
    assert issue(ledger, registry, lumen.classic_address).ok
    assert not vendor_has_accepted_credential(ledger, lumen.classic_address, registry.classic_address)
    o = run_intent(world, vendor="Lumen Legal", amount="21.00", invoice_id="INV-0092")
    _refused_for_credential(world, o)
    assert [h["type"] for h in ledger.history[before:]] == ["CredentialDelete", "CredentialCreate"]


def test_credential_deleted_after_acceptance_refuses_again(world):
    ledger, ring, registry = world["ledger"], world["ring"], world["registry"]
    verdant = ring.vendors["Verdant Print Co"]
    paid = run_intent(world, vendor="Verdant Print Co", amount="12.40", invoice_id="INV-2201")
    assert paid.status == "paid" and paid.engine_result == "tesSUCCESS"
    assert revoke(ledger, registry, verdant.classic_address).ok
    balance_before = ledger.balance_xrp(verdant.classic_address)
    o = run_intent(world, vendor="Harbor Cloud Hosting", amount="8.90", invoice_id="INV-7734")
    assert o.status == "paid", "other vendors are unaffected"
    o = run_intent(world, vendor="Verdant Print Co", amount="5.00", invoice_id="INV-3300")
    assert o.status == "refused" and any("accepted registry credential" in f for f in o.failed)
    assert ledger.balance_xrp(verdant.classic_address) == balance_before


def test_corrupt_admin_adds_attacker_as_vendor_still_refused(world):
    ledger, ring, attacker = world["ledger"], world["ring"], world["ring"].attacker.classic_address
    parked = run_intent(world, vendor="Northwind Freight", amount="6.40", invoice_id="INV-5510")
    assert parked.status == "parked"
    attacker_before = ledger.balance_xrp(attacker)
    # the admin controls both lists and points the name at the attacker; the registry never issued to it
    world["daemon"].add_vendor("Northwind Freight", attacker)
    [rerun] = world["service"].admin_add_vendor("Northwind Freight", attacker, "US", actor="insider")
    _refused_for_credential(world, rerun)
    assert ledger.balance_xrp(attacker) == attacker_before
    admin_rows = [r for r in world["audit"].dump() if r.get("kind") == "admin"]
    assert admin_rows, "the admin action itself is still logged"


def test_hook_needs_registry_issuer_type_and_flag():
    registry, other, vendor = Wallet.create(), Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, other, vendor)
    assert not vendor_has_accepted_credential(ledger, vendor.classic_address, None)
    assert issue(ledger, registry, vendor.classic_address).ok
    assert not vendor_has_accepted_credential(ledger, vendor.classic_address, registry.classic_address), "not accepted"
    _submit(ledger, CredentialAccept(account=vendor.classic_address, issuer=registry.classic_address, credential_type=TYPE_HEX), vendor)
    assert vendor_has_accepted_credential(ledger, vendor.classic_address, registry.classic_address)
    assert not vendor_has_accepted_credential(ledger, vendor.classic_address, other.classic_address), "wrong issuer"
    other_type = b"something-else".hex().upper()
    _submit(ledger, CredentialCreate(account=other.classic_address, subject=vendor.classic_address, credential_type=other_type), other)
    _submit(ledger, CredentialAccept(account=vendor.classic_address, issuer=other.classic_address, credential_type=other_type), vendor)
    assert not vendor_has_accepted_credential(ledger, vendor.classic_address, other.classic_address), "wrong type"


def test_credential_transactions_are_signature_checked():
    registry, vendor, attacker = Wallet.create(), Wallet.create(), Wallet.create()
    ledger = _ledger_with(registry, vendor, attacker)
    forged = CredentialCreate(account=registry.classic_address, subject=vendor.classic_address, credential_type=TYPE_HEX)
    r = ledger.submit(_single_sign(forged, attacker, ledger.next_sequence(registry.classic_address), ledger.current_ledger_index() + 20))
    assert r.engine_result == "tefBAD_AUTH"
    assert ledger.credentials(vendor.classic_address) == []
