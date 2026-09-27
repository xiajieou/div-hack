import pytest
from xrpl.transaction import sign
from xrpl.utils import str_to_hex
from xrpl.wallet import Wallet

from fuse.ledger.testnet import model_from_dict

A, B = Wallet.create(), Wallet.create()
CRED = str_to_hex("VerifiedVendor")
BASE = {"Fee": "12", "Sequence": 5, "LastLedgerSequence": 100, "SigningPubKey": ""}


@pytest.mark.parametrize("tx", [
    {"TransactionType": "TicketCreate", "Account": A.classic_address, "TicketCount": 1},
    {"TransactionType": "CredentialCreate", "Account": A.classic_address, "Subject": B.classic_address, "CredentialType": CRED},
    {"TransactionType": "CredentialAccept", "Account": B.classic_address, "Issuer": A.classic_address, "CredentialType": CRED},
])
def test_new_types_round_trip_signed(tx):
    signed = sign(model_from_dict({**tx, **BASE}), A).to_xrpl()
    assert model_from_dict(signed).to_xrpl() == signed


def test_unknown_type_is_refused():
    with pytest.raises(ValueError):
        model_from_dict({"TransactionType": "SetRegularKey", "Account": A.classic_address})
