"""Phase 0 spike. Owner: Ledger. Raced in two worktrees. Throwaway.

Prove one delegated, two-signature XRP payment from the spend account validates on the XRPL test network,
then capture four result codes. Print, at the end:
    tesSUCCESS hash + explorer link
    (1) same payment with only the agent signature
    (2) SignerListSet on the spend account through the desk, signed by both keys
    (3) a payment after the spend account sends DelegateSet with empty Permissions
    (4) one CredentialCreate
Also print which amendments the server reports enabled (PermissionDelegationV1_1, Credentials).
The prompt is in planning/PROMPTS.md. fuse/ledger/testnet.py and fuse/setup.py are the starting material.
"""
raise NotImplementedError("Phase 0: the spike")
