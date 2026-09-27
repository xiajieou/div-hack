"""Vendor credential check. The rule is code, not configuration: no admin setting may disable it.

A vendor passes only if the ledger holds a Credential entry on the vendor's account, issued by the registry,
of type "verified-vendor", with lsfAccepted set. A service with no registry address pays nobody.
"""
from ..ledger.local import LSF_ACCEPTED
from ..registry import CREDENTIAL_TYPE_HEX


def vendor_has_accepted_credential(ledger, vendor_address: str, registry_address: str) -> bool:
    if not registry_address:
        return False
    return any(c["Issuer"] == registry_address and c["CredentialType"] == CREDENTIAL_TYPE_HEX and c["Flags"] & LSF_ACCEPTED
               for c in ledger.credentials(vendor_address))
