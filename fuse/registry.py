"""The vendor registry: a separate authority that issues on-chain "verified-vendor" credentials.

A credential counts only once the vendor has accepted it (CredentialAccept sets lsfAccepted). The registry key
is not the policy key and not an admin setting: getting on the allowlist and holding a credential are two acts
by two parties. The check that reads these lives in fuse/policy/credentials.py.
"""
from __future__ import annotations

from typing import Iterable

from xrpl.models.transactions import CredentialAccept, CredentialCreate, CredentialDelete
from xrpl.wallet import Wallet

from .ledger.local import Result
from .setup import _single_sign

CREDENTIAL_TYPE = "verified-vendor"
CREDENTIAL_TYPE_HEX = CREDENTIAL_TYPE.encode().hex().upper()
LAST_LEDGER_WINDOW = 20


def _send(ledger, model, wallet: Wallet) -> Result:
    return ledger.submit(_single_sign(model, wallet, ledger.next_sequence(wallet.classic_address),
                                      ledger.current_ledger_index() + LAST_LEDGER_WINDOW))


def issue(ledger, registry: Wallet, vendor_address: str) -> Result:
    return _send(ledger, CredentialCreate(account=registry.classic_address, subject=vendor_address, credential_type=CREDENTIAL_TYPE_HEX), registry)


def accept(ledger, vendor: Wallet, registry_address: str) -> Result:
    return _send(ledger, CredentialAccept(account=vendor.classic_address, issuer=registry_address, credential_type=CREDENTIAL_TYPE_HEX), vendor)


def revoke(ledger, registry: Wallet, vendor_address: str) -> Result:
    return _send(ledger, CredentialDelete(account=registry.classic_address, subject=vendor_address, credential_type=CREDENTIAL_TYPE_HEX), registry)


def setup_local_registry(ledger, vendors: Iterable[Wallet]) -> Wallet:
    """Local worlds only: a funded registry that has issued to each vendor, and each vendor has accepted."""
    registry = Wallet.create()
    ledger.fund(registry.classic_address, 20_000_000)
    for vendor in vendors:
        issue(ledger, registry, vendor.classic_address)
        accept(ledger, vendor, registry.classic_address)
    return registry
