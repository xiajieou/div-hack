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
