"""One-command testnet setup. Phase 1, owner: Ledger.

Funds treasury, spend, desk, registry, vendors and the attacker from the faucet; treasury tops up the spend
account; spend sends DelegateSet (Payment only) to desk; desk sets its signer list and disables its master key;
spend creates a Ticket and the break-glass file is written to break-glass/revoke.json; writes env/accounts.json
for the services and prints explorer links. --rlusd sets trust lines and switches the currency once the XRP path is green.
"""
raise NotImplementedError("Phase 1: setup")
