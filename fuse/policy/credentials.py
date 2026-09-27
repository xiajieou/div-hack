"""Vendor credential check. The rule is code, not configuration: no admin setting may disable it.

A vendor passes only if the ledger holds a Credential entry whose subject is that vendor, issued by the
registry, of type "verified-vendor", accepted, and not expired. A service with no registry address pays nobody.
"""
import time

from ..ledger.local import LSF_ACCEPTED
from ..registry import CREDENTIAL_TYPE_HEX

RIPPLE_EPOCH = 946684800  # 2000-01-01 UTC; Expiration is seconds since then


def _still_valid(entry: dict) -> bool:
    expiry = entry.get("Expiration")
    return expiry is None or int(expiry) + RIPPLE_EPOCH > time.time()


def vendor_has_accepted_credential(ledger, vendor_address: str, registry_address: str) -> bool:
    if not registry_address:
        return False
    return any(
        c.get("Subject") == vendor_address
        and c.get("Issuer") == registry_address
        and c.get("CredentialType") == CREDENTIAL_TYPE_HEX
        and c.get("Flags", 0) & LSF_ACCEPTED
        and _still_valid(c)
        for c in ledger.credentials(vendor_address)
    )
