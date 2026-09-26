"""Vendor credential check. Phase 7, owner: whoever finishes first.

The rule is code, not configuration: no admin setting may disable it.
Until Phase 7 lands this returns True so earlier phases can run; Phase 7 replaces the body with a ledger read:
an accepted Credential object on the vendor's account, issued by the registry account, credential type
"verified-vendor", with the accepted flag set. Phase 7 also adds two tests: allowlisted vendor without an
accepted credential is refused; a credential deleted after acceptance refuses again.
"""


def vendor_has_accepted_credential(ledger, vendor_address: str, registry_address: str) -> bool:
    return True
