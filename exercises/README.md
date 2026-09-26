# Exercises: the three v2 pieces you implement by hand

The agents write the tests and the interfaces. You write the implementations. Each exercise is one of the
new v2 pieces, so finishing them is not homework, it is the build.

1. `ex1_blast_radius.py`  — the report a risk team reads. Pure function over a ledger snapshot.
2. `ex2_audit_completeness.py` — the check that the log missed nothing. Pure function over ledger history.
3. `ex3_break_glass.py` — the pre-signed kill switch. Builds and signs a Ticket-based DelegateSet offline.

Start one: delete the `pytestmark = pytest.mark.skip(...)` line at the top of its test file, then

    pytest tests/test_ex1_blast_radius.py -q

and make it green. Ask the Cursor agent in ask mode to explain, not to write. When you are done, wire the
function into the real service (Phase 5, 6, 1 in planning/ROADMAP.md) and delete the stub's NotImplementedError.
