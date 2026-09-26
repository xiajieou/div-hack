"""Run the Fuse demo.

  python -m fuse.demo                      # local mini-ledger, no network, real signatures
  python -m fuse.demo --mode testnet       # XRPL testnet via the public faucet (first run = the S0 spike)
  python -m fuse.demo --mode testnet --no-delegation   # multisig-only fallback if the amendment is not enabled

Beats, in the order the challenge brief's four questions suggest:
  0 setup   1-3 three clean invoices   4 prompt-injected invoice   5 leaked agent key (two rejections by the ledger)
  6 agent oversteps   7 unknown vendor parked, added, rerun   8 kill switch   9 audit chain verified, then tampered
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from decimal import Decimal

from xrpl.models.transactions import Payment, SignerListSet
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import multisign, sign

from .audit import AuditChain
from .config import VendorRecord, default_policy
from .ledger.local import LocalLedger
from .policy.builder import build_payment
from .policy.service import MULTISIGN_FEE_DROPS, PolicyService
from .reader.reader import INVOICES, hidden_text, pick_extractor, write_fixtures
from .setup import KeyRing, revoke_delegation, run_setup
from .signer.daemon import SignerDaemon

LINE = "─" * 78


def banner(n, title):
    print(f"\n{LINE}\n  Beat {n}: {title}\n{LINE}")


def short(h: str) -> str:
    return (h[:8] + "…" + h[-6:]) if h else "—"


def show_outcome(o, ledger) -> None:
    label = {"paid": "PAID", "refused": "REFUSED", "parked": "PARKED", "rejected_by_ledger": "REJECTED BY LEDGER"}[o.status]
    it = o.intent
    print(f"  intent   : {it['amount']} XRP to {it['vendor']} for {it['invoice_id']}" + (f"  (claims new account {short(it['claimed_destination'])})" if it.get('claimed_destination') else ""))
    print(f"  reason   : {it['reason']}")
    for r in o.rules:
        mark = "✓" if r["ok"] else ("!" if r["soft"] else "✗")
        print(f"    {mark} {r['rule']}" + (f"  ({r['note']})" if r["note"] else ""))
    print(f"  result   : {label}" + (f"  {o.engine_result}  tx {short(o.tx_hash)}" if o.tx_hash else ""))
    if o.failed:
        for f in o.failed:
            print(f"             - {f}")
    if o.message:
        print(f"  note     : {o.message}")
    if getattr(ledger, "explorer", "") and o.tx_hash:
        print(f"  explorer : {ledger.explorer}/transactions/{o.tx_hash}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fuse demo")
    ap.add_argument("--mode", choices=["local", "testnet", "devnet"], default="local")
    ap.add_argument("--no-delegation", action="store_true", help="multisig-only fallback: desk holds the funds, no Delegate field")
    ap.add_argument("--inbox", default=None, help="directory for invoice fixtures (default: a temp dir)")
    args = ap.parse_args(argv)

    policy = default_policy()
    delegation = not args.no_delegation

    if args.mode == "local":
        ledger = LocalLedger()
        ring = KeyRing.local(ledger, policy)
    else:
        from .ledger.testnet import DEVNET_RPC, TESTNET_RPC, TestnetLedger
        ledger = TestnetLedger(TESTNET_RPC if args.mode == "testnet" else DEVNET_RPC)
        print("Funding accounts from the faucet (this takes a minute)…")
        ring = KeyRing.testnet(ledger, policy)

    treasury_addr = ring.treasury.classic_address if delegation else ring.desk.classic_address
    desk_addr = ring.desk.classic_address if delegation else None
    if not delegation and args.mode == "local":
        ledger.fund(ring.desk.classic_address, 250_000_000)

    # ----- beat 0: setup -----
    banner(0, "Setup: delegation, signer list, master key off")
    for r in run_setup(ledger, ring, delegation=delegation):
        pass
    for line in ring.setup_log:
        print("  " + line)
    print()
    print("  " + ledger.describe(ring.treasury.classic_address).replace("\n", "\n  "))
    print("  " + ledger.describe(ring.desk.classic_address).replace("\n", "\n  "))
    print(f"  agent key  {ring.agent.classic_address}   (inside the signer daemon)")
    print(f"  policy key {ring.policy.classic_address}   (inside the policy service)")
    print(f"  attacker   {ring.attacker.classic_address}")
    print(f"  policy hash {policy.hash()[:16]}…  per-payment cap {policy.per_payment_cap_xrp} XRP, daily cap {policy.daily_cap_xrp} XRP")

    audit = AuditChain(policy.hash())
    service = PolicyService(policy, ring.policy, ledger, treasury_addr, desk_addr, audit)
    daemon = SignerDaemon(ring.agent, treasury_addr, desk_addr,
                          {name: w.classic_address for name, w in ring.vendors.items()},
                          policy.fee_cap_drops, forward=service.handle_intent)
    service.attach_daemon(daemon)

    inbox = args.inbox or tempfile.mkdtemp(prefix="fuse-inbox-")
    write_fixtures(inbox, ring.attacker.classic_address)
    extract, extractor_name = pick_extractor()
    print(f"  reader     {extractor_name} extractor; inbox {inbox}")

    def process(filename: str):
        text = open(os.path.join(inbox, filename)).read()
        intent, _ = extract(text)
        nonce = daemon.register(intent)                # forwards to the policy service
        return service.outcomes[nonce], text

    # ----- beats 1-3: the happy path -----
    for i, f in enumerate(["inv_2201_verdant.txt", "inv_7734_harbor.txt", "inv_0092_lumen.txt"], start=1):
        banner(i, f"Clean invoice {f} paid autonomously")
        o, _ = process(f)
        show_outcome(o, ledger)

    # ----- beat 4: prompt injection -----
    banner(4, "The brief asks: what if the agent is prompt-injected?")
    o, text = process("inv_2201_verdant_REISSUE.txt")
    print("  hidden text in the PDF:")
    for line in (hidden_text(text) or "").splitlines():
        print("     | " + line)
    show_outcome(o, ledger)
    print("  A swapped vendor address also dies here: the Destination field is only ever filled from the allowlist record.")

    # ----- beat 5: leaked agent key -----
    banner(5, "The brief asks: what if the key leaks? (the attacker now holds the agent key)")
    attacker_vendor = VendorRecord("attacker", ring.attacker.classic_address, "??")
    seq = ledger.next_sequence(treasury_addr)
    lls = ledger.current_ledger_index() + 40
    stolen = build_payment(treasury=treasury_addr, desk=desk_addr, vendor=attacker_vendor, amount_xrp=Decimal("50"),
                           invoice_id="FAKE-1", commitment="00" * 32, policy_hash=policy.hash(), fee_drops=MULTISIGN_FEE_DROPS,
                           sequence=seq, last_ledger_sequence=lls)
    one_sig = sign(Payment.from_xrpl(stolen), ring.agent, multisign=True).to_xrpl()
    r = ledger.submit(one_sig)
    print(f"  (a) 50 XRP to the attacker, signed with the agent key alone, submitted straight to the ledger")
    print(f"      ledger says: {r.engine_result}   {r.message}")
    if delegation:
        seq = ledger.next_sequence(treasury_addr)
        takeover = SignerListSet(account=treasury_addr, delegate=desk_addr, signer_quorum=1,
                                 signer_entries=[SignerEntry(account=ring.attacker.classic_address, signer_weight=1)],
                                 fee=str(MULTISIGN_FEE_DROPS), sequence=seq, last_ledger_sequence=lls, signing_pub_key="")
        both = multisign(takeover, [sign(takeover, ring.agent, multisign=True), sign(takeover, ring.policy, multisign=True)]).to_xrpl()
        r2 = ledger.submit(both)
        print(f"  (b) SignerListSet on the treasury via the desk, signed with BOTH keys (assume the policy key leaked too)")
        print(f"      ledger says: {r2.engine_result}   {r2.message}")
        print("      Delegation covers Payment only. Even both keys cannot change who controls the treasury.")
    else:
        print("  (b) skipped: multisig-only fallback has no delegation scope to demonstrate.")

    # ----- beat 6: overstep -----
    banner(6, "The brief asks: what if the agent reasons its way into an unauthorized outcome?")
    o, _ = process("inv_9001_lumen_prepay.txt")
    show_outcome(o, ledger)

    # ----- beat 7: unknown vendor -----
    banner(7, "Unknown vendor: parked, added by a human through the logged admin path, rerun")
    o, _ = process("inv_5510_northwind.txt")
    show_outcome(o, ledger)
    print("  → a human adds Northwind Freight to the allowlist (logged), and the parked intent reruns:")
    daemon.add_vendor("Northwind Freight", ring.northwind.classic_address)
    reruns = service.admin_add_vendor("Northwind Freight", ring.northwind.classic_address, "US", actor="cfo@company")
    for o2 in reruns:
        show_outcome(o2, ledger)

    # ----- beat 8: kill switch -----
    banner(8, "Kill switch: the treasury revokes the delegation, then a valid double-signed payment is attempted")
    if delegation:
        r = revoke_delegation(ledger, ring)
        print(f"  DelegateSet with no permissions: {r.engine_result}")
        o, _ = process("inv_3300_harbor_after_revoke.txt")
        show_outcome(o, ledger)
    else:
        print("  skipped in multisig-only fallback; the equivalent is removing the agent from the desk signer list.")

    # ----- beat 9: audit -----
    banner(9, "Audit chain: verify, then tamper with one historical row")
    ok, msg = audit.verify(service.memos_by_tx_hash)
    print(f"  verify: {'OK' if ok else 'FAIL'} — {msg}")
    victim = next(r for r in audit.rows if r.kind == "refused")
    victim.record["failed"] = ["(edited after the fact)"]
    ok, msg = audit.verify(service.memos_by_tx_hash)
    print(f"  after editing a refusal row: {'OK' if ok else 'FAIL'} — {msg}")

    # ----- summary -----
    print(f"\n{LINE}\n  Ledger history\n{LINE}")
    for h in ledger.history:
        print(f"  {h['result']:<28} {h['type']:<14} {short(h['hash'])}")
    print(f"\n  treasury balance now {ledger.balance_xrp(ring.treasury.classic_address)} XRP")
    for name, w in list(ring.vendors.items()) + [("Northwind Freight", ring.northwind)]:
        print(f"  {name:<22} {ledger.balance_xrp(w.classic_address)} XRP")
    print(f"  attacker               {ledger.balance_xrp(ring.attacker.classic_address)} XRP   (unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
