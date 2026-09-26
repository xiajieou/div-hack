"""Audit completeness check. Phase 6, owner: Front, after exercise 2 is green.

Read-only: account_tx over the spend account, filtered to outgoing Payment transactions with result tesSUCCESS
(planning/DECISIONS.md D5), matched by hash to the audit log's result rows. Prints the payments the log never saw.
Boundary: pytest tests/test_ex2_audit_completeness.py -q; after the stolen-keys scene it flags exactly the
attacker's payments.

    python -m fuse.reports.audit_completeness --mode local|testnet
"""
from exercises.ex2_audit_completeness import unlogged_payments  # noqa: F401
