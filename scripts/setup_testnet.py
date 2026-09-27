"""One-command setup on the XRPL devnet (delegation is not enabled on testnet). Phase 1, owner: Ledger.

Funds treasury, spend, desk, registry, vendors and the attacker from the faucet; the spend account keeps only the
float and returns the rest to the treasury (no program signs with the treasury key); spend delegates Payment only
to the desk; the desk sets its signer list (agent + policy, quorum 2) and disables its master key; the result is
read back from the ledger and checked; then writes env/accounts.json and env/vendors.json (addresses only) and
the seeds plus AGENT_ADDRESS to .env.
The desk seed is never saved: once its master key is off it is useless.

    py -3.13 scripts/setup_testnet.py [--float 30] [--net devnet]
"""
import argparse
import json
import re
import sys
from decimal import Decimal
from pathlib import Path

from xrpl.models.requests import AccountInfo, AccountObjects, ServerInfo
from xrpl.models.transactions import AccountSet, AccountSetAsfFlag, DelegateSet, Payment, SignerListSet
from xrpl.models.transactions.delegate_set import Permission
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import autofill, autofill_and_sign, multisign, sign
from xrpl.wallet import Wallet

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fuse.config import default_policy, xrp_to_drops  # noqa: E402
from fuse.ledger.testnet import DEVNET_RPC, TESTNET_RPC, TestnetLedger  # noqa: E402

NETS = {"devnet": DEVNET_RPC, "testnet": TESTNET_RPC}
SPEND_OBJECTS = 3        # delegation, break-glass ticket, one spare
FEE_SLACK_DROPS = 1000   # left on the spend account to cover the fee of the return payment
LSF_DISABLE_MASTER = 0x00100000


def create_accounts(ledger):
    w = {name: ledger.faucet_wallet() for name in ("treasury", "spend", "desk", "registry")}
    w["agent"] = Wallet.create()     # signers on the desk's list; they never hold funds
    w["policy"] = Wallet.create()
    vendors = {name: ledger.faucet_wallet() for name in default_policy().allowlist}
    extra = {"northwind": ledger.faucet_wallet(), "attacker": ledger.faucet_wallet()}
    return w, vendors, extra


def set_float(ledger, spend, treasury, float_xrp):
    info = ledger.client.request(ServerInfo()).result["info"]["validated_ledger"]
    reserve = Decimal(str(info["reserve_base_xrp"])) + SPEND_OBJECTS * Decimal(str(info["reserve_inc_xrp"]))
    balance = int(ledger.client.request(AccountInfo(account=spend.classic_address, ledger_index="validated")).result["account_data"]["Balance"])
    excess = balance - int(xrp_to_drops(float_xrp + reserve)) - FEE_SLACK_DROPS
    if excess <= 0:
        sys.exit(f"spend account holds {balance} drops; not enough for a {float_xrp} XRP float plus {reserve} XRP reserve")
    tx = Payment(account=spend.classic_address, destination=treasury.classic_address, amount=str(excess))
    r = ledger.submit(autofill_and_sign(tx, ledger.client, spend).to_xrpl())
    print(f"  spend returns {excess / 1_000_000:.6f} XRP to treasury   {r.engine_result}  {r.message}")
    if not r.ok:
        sys.exit("could not set the float")
    return reserve


def wire_desk(ledger, w):
    """Delegate Payment only from spend to desk, then put the desk behind agent + policy and switch its own key off.
    The signer list must exist before the master key goes, or the ledger refuses (tecNO_ALTERNATIVE_KEY)."""
    spend, desk = w["spend"].classic_address, w["desk"].classic_address
    steps = [
        ("DelegateSet spend -> desk (Payment only)", w["spend"],
         DelegateSet(account=spend, authorize=desk, permissions=[Permission(permission_value="Payment")])),
        ("SignerListSet on desk (agent + policy, quorum 2)", w["desk"],
         SignerListSet(account=desk, signer_quorum=2,
                       signer_entries=[SignerEntry(account=w["agent"].classic_address, signer_weight=1),
                                       SignerEntry(account=w["policy"].classic_address, signer_weight=1)])),
        ("AccountSet disable desk master key", w["desk"],
         AccountSet(account=desk, set_flag=AccountSetAsfFlag.ASF_DISABLE_MASTER)),
    ]
    hashes = {}
    for label, wallet, tx in steps:
        r = ledger.submit(autofill_and_sign(tx, ledger.client, wallet).to_xrpl())
        print(f"  {label:50} {r.engine_result}  {r.message}")
        if not r.ok:
            sys.exit(f"setup stopped at: {label}")
        hashes[tx.transaction_type.value] = r.hash
    return hashes


def verify(ledger, w, vendor_addr):
    """Read the result back from the ledger, then make two refusals that cost nothing and move nothing."""
    spend, desk, agent, policy = (w[k].classic_address for k in ("spend", "desk", "agent", "policy"))
    problems = []

    flags = ledger.client.request(AccountInfo(account=desk, ledger_index="validated")).result["account_data"]["Flags"]
    if not flags & LSF_DISABLE_MASTER:
        problems.append("desk master key is still enabled")
    desk_objs = ledger.client.request(AccountObjects(account=desk, ledger_index="validated")).result["account_objects"]
    signer_lists = [o for o in desk_objs if o["LedgerEntryType"] == "SignerList"]
    signers = {e["SignerEntry"]["Account"]: e["SignerEntry"]["SignerWeight"] for sl in signer_lists for e in sl["SignerEntries"]}
    if len(signer_lists) != 1 or signer_lists[0]["SignerQuorum"] != 2 or signers != {agent: 1, policy: 1}:
        problems.append(f"desk signer list is not agent + policy with quorum 2: {signer_lists}")
    spend_objs = ledger.client.request(AccountObjects(account=spend, ledger_index="validated")).result["account_objects"]
    delegates = {o["Authorize"]: sorted(p["Permission"]["PermissionValue"] for p in o["Permissions"])
                 for o in spend_objs if o["LedgerEntryType"] == "Delegate"}
    if delegates != {desk: ["Payment"]}:
        problems.append(f"spend delegations are not exactly desk: Payment: {delegates}")

    pay = autofill(Payment(account=spend, delegate=desk, destination=vendor_addr, amount="1"), ledger.client, signers_count=2)
    r = ledger.submit(multisign(pay, [sign(pay, w["agent"], multisign=True)]).to_xrpl())
    print(f"  check: payment with the agent key alone              {r.engine_result}")
    if r.engine_result != "tefBAD_QUORUM":
        problems.append(f"agent key alone got {r.engine_result}, expected tefBAD_QUORUM")
    r = ledger.submit(autofill_and_sign(AccountSet(account=desk), ledger.client, w["desk"]).to_xrpl())
    print(f"  check: anything signed with the desk's own key       {r.engine_result}")
    if r.engine_result != "tefMASTER_DISABLED":
        problems.append(f"desk master key got {r.engine_result}, expected tefMASTER_DISABLED")

    print("  " + ledger.describe(spend).replace("\n", "\n  "))
    print("  " + ledger.describe(desk).replace("\n", "\n  "))
    if problems:
        sys.exit("setup verification failed:\n  " + "\n  ".join(problems))


def env_name(vendor):
    return "VENDOR_" + re.sub(r"[^A-Z0-9]+", "_", vendor.upper()).strip("_") + "_SEED"


def write_env(values):
    path = ROOT / ".env"
    source = path if path.exists() else ROOT / ".env.example"
    lines = source.read_text().splitlines()
    for key, value in values.items():
        line = f"{key}={value}"
        idx = next((i for i, l in enumerate(lines) if l.split("=", 1)[0].strip() == key), None)
        if idx is None:
            lines.append(line)
        else:
            lines[idx] = line
    path.write_text("\n".join(lines) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", choices=NETS, default="devnet")
    ap.add_argument("--float", dest="float_xrp", type=Decimal, default=Decimal("30"))
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")  # describe() prints arrows; the Windows console default can't
    ledger = TestnetLedger(NETS[args.net])
    print(f"network: {args.net} {ledger.rpc_url}")

    print("C1 accounts (faucet)")
    w, vendors, extra = create_accounts(ledger)
    reserve = set_float(ledger, w["spend"], w["treasury"], args.float_xrp)

    print("C2 delegation, signer list, desk master key off")
    setup_tx = wire_desk(ledger, w)
    print("C2 verify")
    verify(ledger, w, next(iter(vendors.values())).classic_address)

    # written only once everything above succeeded, so a failed run never leaves a half-configured accounts.json
    accounts = {
        "network": args.net, "rpc": ledger.rpc_url, "explorer": ledger.explorer,
        "float_xrp": str(args.float_xrp), "spend_reserve_xrp": str(reserve),
        **{name: wallet.classic_address for name, wallet in w.items()},
        "vendors": {name: wallet.classic_address for name, wallet in vendors.items()},
        "northwind": extra["northwind"].classic_address,
        "attacker": extra["attacker"].classic_address,
        "setup_tx": setup_tx,
    }
    out = ROOT / "env" / "accounts.json"
    out.write_text(json.dumps(accounts, indent=2) + "\n")
    # the signer daemon's vendor directory, same shape the local mode writes
    (ROOT / "env" / "vendors.json").write_text(json.dumps(accounts["vendors"], indent=2) + "\n")

    env = write_env({
        "NETWORK": args.net,
        "AGENT_ADDRESS": w["agent"].classic_address,
        "TREASURY_SEED": w["treasury"].seed, "SPEND_SEED": w["spend"].seed, "AGENT_SEED": w["agent"].seed,
        "POLICY_SEED": w["policy"].seed, "REGISTRY_SEED": w["registry"].seed,
        **{env_name(name): wallet.seed for name, wallet in vendors.items()},
    })

    for name in ("treasury", "spend", "desk", "registry"):
        addr = accounts[name]
        print(f"  {name:22} {addr}  {ledger.balance_xrp(addr)} XRP  {ledger.explorer}/accounts/{addr}")
    for name in ("agent", "policy"):
        print(f"  {name:22} {accounts[name]}  (signer key, unfunded)")
    for name, addr in [*accounts["vendors"].items(), ("northwind (not listed)", accounts["northwind"]), ("attacker", accounts["attacker"])]:
        print(f"  {name:22} {addr}  {ledger.explorer}/accounts/{addr}")
    print(f"  addresses -> {out.relative_to(ROOT)}, env/vendors.json   seeds -> {env.relative_to(ROOT)} (gitignored)")


if __name__ == "__main__":
    main()
