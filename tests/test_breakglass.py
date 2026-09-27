from xrpl.core.binarycodec import encode_for_signing
from xrpl.core.keypairs import derive_classic_address, is_valid_message
from xrpl.wallet import Wallet

from fuse.breakglass import build_break_glass, sign_break_glass


def test_unsigned_shape():
    tx = build_break_glass("rSpend", "rDesk", ticket_sequence=42)
    assert tx["TransactionType"] == "DelegateSet"
    assert tx["Account"] == "rSpend" and tx["Authorize"] == "rDesk"
    assert tx["Permissions"] == []
    assert tx["Sequence"] == 0 and tx["TicketSequence"] == 42
    assert "LastLedgerSequence" not in tx
    assert int(tx["Fee"]) >= 1000


def test_signed_by_spend_wallet_and_verifiable_offline():
    spend, desk = Wallet.create(), Wallet.create()
    signed = sign_break_glass(spend, desk.classic_address, ticket_sequence=7)
    assert signed["Account"] == spend.classic_address
    assert derive_classic_address(signed["SigningPubKey"]) == spend.classic_address
    payload = encode_for_signing({k: v for k, v in signed.items() if k != "TxnSignature"})
    assert is_valid_message(bytes.fromhex(payload), bytes.fromhex(signed["TxnSignature"]), signed["SigningPubKey"])
    assert signed["Permissions"] == [] and signed["TicketSequence"] == 7 and "LastLedgerSequence" not in signed


def test_tampering_breaks_the_signature():
    spend, desk = Wallet.create(), Wallet.create()
    signed = sign_break_glass(spend, desk.classic_address, ticket_sequence=7)
    signed["Authorize"] = Wallet.create().classic_address
    payload = encode_for_signing({k: v for k, v in signed.items() if k != "TxnSignature"})
    assert not is_valid_message(bytes.fromhex(payload), bytes.fromhex(signed["TxnSignature"]), signed["SigningPubKey"])
