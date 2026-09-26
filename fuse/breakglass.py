"""Break-glass file: the pre-signed kill switch. Phase 1, owner: Ledger, after exercise 3 is green.

Wires exercises.ex3_break_glass into setup: TicketCreate on the spend account, then sign a DelegateSet with empty
Permissions against that TicketSequence with no LastLedgerSequence and a generous fee, and write the signed
transaction to break-glass/revoke.json. scripts/kill_switch.py and the dashboard submit that file; neither holds a key.
"""
from exercises.ex3_break_glass import build_break_glass, sign_break_glass  # noqa: F401
