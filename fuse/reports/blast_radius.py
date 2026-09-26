"""Blast radius report. Phase 5, owner: Front, after exercise 1 is green.

Builds the snapshot from the ledger adapter (local or testnet): spend account delegations and regular key,
desk signer list, quorum, regular key and master-disabled flag, balances. Prints the worst-case rows and the
findings that invalidate them. Boundary: pytest tests/test_ex1_blast_radius.py -q; the report on the local
ledger matches the table in planning/SPEC.md; on testnet it prints every check.

    python -m fuse.reports.blast_radius --mode local|testnet
"""
from exercises.ex1_blast_radius import Finding, Row, blast_radius  # noqa: F401
