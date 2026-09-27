from fuse.reports.blast_radius import blast_radius


CLEAN = {
    "float_drops": 30_000_000,
    "spend": {"delegations": {"rDesk": ["Payment"]}, "regular_key": None, "master_disabled": False},
    "desk": {"quorum": 2, "signers": {"rAgent": 1, "rPolicy": 1}, "regular_key": None, "master_disabled": True},
    "treasury_drops": 250_000_000,
}


def test_clean_setup_rows_and_order():
    rows, findings = blast_radius(CLEAN)
    assert findings == []
    assert [r.part for r in rows] == ["reader", "agent key", "policy key", "agent+policy keys", "spend account key", "treasury key"]
    loss = {r.part: r.max_loss_drops for r in rows}
    assert loss["reader"] == 0 and loss["agent key"] == 0 and loss["policy key"] == 0
    assert loss["agent+policy keys"] == 30_000_000
    assert loss["spend account key"] == 30_000_000
    assert loss["treasury key"] == 250_000_000
    assert all(r.why for r in rows)


def test_extra_permission_is_a_finding_and_widens_loss():
    snap = {**CLEAN, "spend": {**CLEAN["spend"], "delegations": {"rDesk": ["Payment", "TrustSet"]}}}
    rows, findings = blast_radius(snap)
    assert any("TrustSet" in f.text or "permission" in f.text.lower() for f in findings)
    loss = {r.part: r.max_loss_drops for r in rows}
    assert loss["agent key"] == 30_000_000 and loss["policy key"] == 30_000_000


def test_second_delegate_is_a_finding():
    snap = {**CLEAN, "spend": {**CLEAN["spend"], "delegations": {"rDesk": ["Payment"], "rOther": ["Payment"]}}}
    _, findings = blast_radius(snap)
    assert any("delegate" in f.text.lower() for f in findings)


def test_regular_key_on_desk_is_a_finding():
    snap = {**CLEAN, "desk": {**CLEAN["desk"], "regular_key": "rSomeone"}}
    _, findings = blast_radius(snap)
    assert any("regular key" in f.text.lower() for f in findings)


def test_master_enabled_on_desk_is_a_finding():
    snap = {**CLEAN, "desk": {**CLEAN["desk"], "master_disabled": False}}
    _, findings = blast_radius(snap)
    assert any("master" in f.text.lower() for f in findings)


def test_quorum_one_means_one_key_is_enough():
    snap = {**CLEAN, "desk": {**CLEAN["desk"], "quorum": 1}}
    rows, findings = blast_radius(snap)
    assert any("quorum" in f.text.lower() for f in findings)
    loss = {r.part: r.max_loss_drops for r in rows}
    assert loss["agent key"] == 30_000_000


def test_signer_list_on_spend_account_is_a_finding():
    snap = {**CLEAN, "spend": {**CLEAN["spend"], "signers": {"rAgent": 1}}}
    _, findings = blast_radius(snap)
    assert any("signer list" in f.text for f in findings)


def test_treasury_delegate_is_a_finding():
    snap = {**CLEAN, "treasury": {"address": "rTreasury", "delegations": {"rDesk": ["Payment"]}}}
    _, findings = blast_radius(snap)
    assert any("treasury has delegates" in f.text for f in findings)


def test_paying_straight_from_treasury_is_a_finding():
    snap = {**CLEAN, "spend": {**CLEAN["spend"], "address": "rSame"}, "treasury": {"address": "rSame"}}
    _, findings = blast_radius(snap)
    assert any("straight from the treasury" in f.text for f in findings)


def test_revoked_delegation_means_both_keys_move_nothing():
    snap = {**CLEAN, "spend": {**CLEAN["spend"], "delegations": {}}}
    rows, findings = blast_radius(snap)
    assert findings == []
    loss = {r.part: r.max_loss_drops for r in rows}
    assert loss["agent+policy keys"] == 0
    assert loss["spend account key"] == 30_000_000


def test_local_ledger_setup_has_no_findings():
    from fuse.reports.blast_radius import read_snapshot
    from fuse.reports.sources import LocalWorld
    world = LocalWorld(attack=False)
    rows, findings = blast_radius(read_snapshot(world, world.addresses))
    assert findings == []
    assert {r.part: r.max_loss_drops for r in rows}["agent key"] == 0


def test_desk_balance_is_within_reach_of_both_keys():
    snap = {**CLEAN, "desk": {**CLEAN["desk"], "balance_drops": 6_200_000}}
    rows, findings = blast_radius(snap)
    loss = {r.part: r.max_loss_drops for r in rows}
    assert findings == []
    assert loss["agent key"] == 0 and loss["policy key"] == 0
    assert loss["agent+policy keys"] == 30_000_000 + 6_200_000
    revoked = {**snap, "spend": {**snap["spend"], "delegations": {}}}
    loss = {r.part: r.max_loss_drops for r in blast_radius(revoked)[0]}
    assert loss["agent+policy keys"] == 6_200_000


def test_a_finding_puts_the_desk_balance_within_one_key():
    snap = {**CLEAN, "desk": {**CLEAN["desk"], "quorum": 1, "balance_drops": 6_200_000}}
    loss = {r.part: r.max_loss_drops for r in blast_radius(snap)[0]}
    assert loss["agent key"] == 30_000_000 + 6_200_000
