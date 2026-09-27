"""Phase 0 spike. Owner: Ledger. Raced in two worktrees. Throwaway.

Prove one delegated, two-signature XRP payment from the spend account validates on the XRPL test network,
then capture four result codes. Print, at the end:
    tesSUCCESS hash + explorer link
    (1) same payment with only the agent signature
    (2) SignerListSet on the spend account through the desk, signed by both keys
    (3) a payment after the spend account sends DelegateSet with empty Permissions
    (4) one CredentialCreate
Also print which amendments the server reports enabled (PermissionDelegationV1_1, Credentials).

    py -3.13 scripts/spike/run.py              # testnet
    py -3.13 scripts/spike/run.py --net devnet
"""
import argparse
from decimal import Decimal
import sys
#from xmlrpc import client

from xrpl.account import get_balance
from xrpl.clients import JsonRpcClient
import time

from xrpl.models.requests import Feature, Tx
from xrpl.models.transactions import (AccountSet, AccountSetAsfFlag, CredentialAccept, CredentialCreate, DelegateSet,
                                      Payment, SignerListSet)
from xrpl.models.transactions.delegate_set import Permission
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import XRPLReliableSubmissionException, autofill, multisign, sign, submit_and_wait
from xrpl.transaction import submit as submit_signed
from xrpl.utils import str_to_hex, xrp_to_drops
from xrpl.wallet import Wallet, generate_faucet_wallet

NETS = {
    "testnet": ("https://s.altnet.rippletest.net:51234", "https://testnet.xrpl.org"),
    "devnet": ("https://s.devnet.rippletest.net:51234", "https://devnet.xrpl.org"),
}
AMENDMENTS = ["PermissionDelegationV1_1", "Credentials"]


def xrp(client, address):
    return get_balance(address, client) / 1_000_000


def submit(client, tx, wallet=None):
    """Submit and wait. Returns (result code, hash). Never swallows the code."""
    try:
        res = submit_and_wait(tx, client, wallet).result
        return res["meta"]["TransactionResult"], res["hash"]
    except XRPLReliableSubmissionException as e:
        return str(e), ""


def submit_fast(client, signed):
    """For a signed transaction expected to fail. tef, tem and ter results never reach a ledger, so the
    server's first answer is final and we return it at once. tes and tec get recorded, so wait for that."""
    res = submit_signed(signed, client).result
    code, h = res["engine_result"], signed.get_hash()
    if code[:3] not in ("tes", "tec"):
        return code, ""
    for _ in range(10):
        time.sleep(2)
        t = client.request(Tx(transaction=h)).result
        if t.get("validated"):
            return t["meta"]["TransactionResult"], h
    return code, h


def accounts(client, explorer):
    spend = generate_faucet_wallet(client)
    desk = generate_faucet_wallet(client)
    vendor = generate_faucet_wallet(client)
    # signers on a signer list do not need to exist on the ledger
    agent = Wallet.create()
    policy = Wallet.create()
    for name, w in [("spend", spend), ("desk", desk), ("vendor", vendor)]:
        print(f"  {name:7} {w.classic_address}  {xrp(client, w.classic_address):.6f} XRP  {explorer}/accounts/{w.classic_address}")
    for name, w in [("agent", agent), ("policy", policy)]:
        print(f"  {name:7} {w.classic_address}  (local key, unfunded)")
    return spend, desk, vendor, agent, policy


def amendments(client):
    features = {v.get("name"): v.get("enabled") for v in client.request(Feature()).result["features"].values()}
    for name in AMENDMENTS:
        print(f"  {name:26} {'enabled' if features.get(name) else 'NOT enabled'}")
    return {name: bool(features.get(name)) for name in AMENDMENTS}


def setup(client, explorer, spend, desk, agent, policy):
    steps = [
        ("DelegateSet spend -> desk (Payment only)", spend,
         DelegateSet(account=spend.classic_address, authorize=desk.classic_address,
                     permissions=[Permission(permission_value="Payment")])),
        ("SignerListSet on desk (agent + policy, quorum 2)", desk,
         SignerListSet(account=desk.classic_address, signer_quorum=2,
                       signer_entries=[SignerEntry(account=agent.classic_address, signer_weight=1),
                                       SignerEntry(account=policy.classic_address, signer_weight=1)])),
        ("AccountSet disable desk master key", desk,
         AccountSet(account=desk.classic_address, set_flag=AccountSetAsfFlag.ASF_DISABLE_MASTER)),
    ]
    ok = True
    for label, wallet, tx in steps:
        code, h = submit(client, tx, wallet)
        print(f"  {label:50} {code}  {explorer}/transactions/{h}" if h else f"  {label:50} {code}")
        ok = ok and code == "tesSUCCESS"
    return ok


def delegated_payment(client, spend, desk, vendor, amount_xrp=Decimal("1")):
    # Account is the spend account (its Sequence, its funds); the desk signs and pays the fee
    tx = Payment(account=spend.classic_address, delegate=desk.classic_address,
                 destination=vendor.classic_address, amount=xrp_to_drops(amount_xrp))
    return autofill(tx, client, signers_count=2)


def pay_with_both_keys(client, explorer, spend, desk, vendor, agent, policy):
    tx = delegated_payment(client, spend, desk, vendor)
    signed = multisign(tx, [sign(tx, agent, multisign=True), sign(tx, policy, multisign=True)])
    before = xrp(client, spend.classic_address)
    code, h = submit(client, signed)
    print(f"  delegated payment, agent + policy signatures     {code}")
    if h:
        print(f"  hash {h}\n  {explorer}/transactions/{h}")
    print(f"  spend balance {before:.6f} -> {xrp(client, spend.classic_address):.6f} XRP")
    return code == "tesSUCCESS"

def only_agent_key(client, spend, desk, vendor, agent): 
    tx = delegated_payment(client, spend, desk, vendor)
    signed = multisign(tx, [sign(tx, agent, multisign=True)])
    before = xrp(client, spend.classic_address)
    code, h = submit_fast(client, signed)
    print(f"  delegated payment, agent signature     {code}")
    print(f"  spend balance {before:.6f} -> {xrp(client, spend.classic_address):.6f} XRP")
    return code
    
def settings_change(client, spend, desk, agent, policy):
    # both keys try to hand control of the spend account to the agent key alone
    tx = SignerListSet(account=spend.classic_address, delegate=desk.classic_address, signer_quorum=1,
                       signer_entries=[SignerEntry(account=agent.classic_address, signer_weight=1)])
    tx = autofill(tx, client, signers_count=2)
    signed = multisign(tx, [sign(tx, agent, multisign=True), sign(tx, policy, multisign=True)])
    code, _ = submit_fast(client, signed)
    print(f"  SignerListSet on spend via desk, agent + policy signatures     {code}")
    return code

def pay_after_revoke(client, explorer, spend, desk, vendor, agent, policy):
    revoke = DelegateSet(account=spend.classic_address, authorize=desk.classic_address, permissions=[])
    code, _ = submit(client, revoke, spend)
    print(f"  DelegateSet spend -> desk (revoke)     {code}")
    tx = delegated_payment(client, spend, desk, vendor)
    signed = multisign(tx, [sign(tx, agent, multisign=True), sign(tx, policy, multisign=True)])
    before = xrp(client, spend.classic_address)
    code, h = submit_fast(client, signed)
    print(f"  revoke, delegated payment, agent + policy signatures     {code}")
    if h:
        print(f"  hash {h}\n  {explorer}/transactions/{h}")
    print(f"  spend balance {before:.6f} -> {xrp(client, spend.classic_address):.6f} XRP")
    return code

def create_credential(client, explorer, vendor):
    registry = generate_faucet_wallet(client)
    print(f"  registry {registry.classic_address}")
    cred_type = str_to_hex("VerifiedVendor")
    create = CredentialCreate(account=registry.classic_address, subject=vendor.classic_address, credential_type=cred_type)
    code, h = submit(client, create, registry)
    print(f"  CredentialCreate registry -> vendor     {code}  {explorer}/transactions/{h}" if h else f"  CredentialCreate registry -> vendor     {code}")
    # the credential only counts once the vendor accepts it
    accept = CredentialAccept(account=vendor.classic_address, issuer=registry.classic_address, credential_type=cred_type)
    accept_code, h = submit(client, accept, vendor)
    print(f"  CredentialAccept by vendor     {accept_code}  {explorer}/transactions/{h}" if h else f"  CredentialAccept by vendor     {accept_code}")
    return f"{code} (accept {accept_code})"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", choices=NETS, default="testnet")
    args = ap.parse_args()
    rpc, explorer = NETS[args.net]
    client = JsonRpcClient(rpc)
    print(f"network: {args.net} {rpc}")

    print("A1 accounts")
    spend, desk, vendor, agent, policy = accounts(client, explorer)

    print("A2 amendments")
    enabled = amendments(client)
    if not enabled["PermissionDelegationV1_1"]:
        sys.exit(f"  delegation is not enabled on {args.net}; DelegateSet would fail. Try --net devnet.")

    print("A3 setup")
    if not setup(client, explorer, spend, desk, agent, policy):
        sys.exit("  setup did not fully succeed; stopping before the payment")

    print("A4 first real payment")
    if not pay_with_both_keys(client, explorer, spend, desk, vendor, agent, policy):
        sys.exit("  payment did not return tesSUCCESS")

    #calling A5 block 
    print("A5 expected failures")
    codes = {}
    codes["agent key only"] = only_agent_key(client, spend, desk, vendor, agent)
    
    codes["settings change, both keys"] = settings_change(client, spend, desk, agent, policy)
    codes["payment after revoke"] = pay_after_revoke(client, explorer, spend, desk, vendor, agent, policy)
    codes["credential create"] = create_credential(client, explorer, vendor)
    for name, code in codes.items():
        print(f"  {name:30} {code}")
if __name__ == "__main__":
    main()
