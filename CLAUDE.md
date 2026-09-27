# CLAUDE.md: Fuse (DivHacks 2026, Ripple track)

## What this project is

Fuse is a wallet arrangement on the XRP Ledger (XRPL) that lets an AI agent pay vendor invoices autonomously without being able to lose the company's money. The agent can propose payments, but cannot produce a valid one alone. Two independent parts must agree before money moves, and the ledger caps the worst case.

Pitch line: "Trick the agent completely, and the worst it can do is ask for something the rules refuse. Steal every key it can reach, and the loss is still capped."

Target: Ripple sponsor challenge "Best Agentic Finance Infrastructure on XRPL." Hard requirement: at least one on-chain transaction executed autonomously by an agent within guardrails. Ripple values demos where the agent gets *stopped*. A human approving each payment does NOT count.

Core thesis from Ripple's brief: constraints only count when enforced somewhere the agent does not control. Never move a safety check into the reader.

Deadline: Devpost submission by 10:30 AM EST, Sunday Sep 27, 2026. Team of 3. Favor working demos over completeness.

## Network and assets

- XRPL **testnet** only. JSON-RPC `https://s.altnet.rippletest.net:51234`, WebSocket `wss://s.altnet.rippletest.net:51233`.
- **Spike in XRP first.** Switch to RLUSD only after a delegated, multisigned payment returns `tesSUCCESS`.
- RLUSD test tokens from tryrlusd.com. Every account holding RLUSD needs a trust line to the issuer. Get the issuer address from tryrlusd.com / Ripple docs; do not guess it.
- Fees are always paid in XRP. The desk pays the fee on delegated payments, so it needs XRP even when the payment is RLUSD.
- Expect trust-line errors (`tecPATH_DRY`, `tecNO_LINE`) before any real problem with the delegation + multisign + RLUSD combination.
- If RLUSD fights back, demo in XRP and say so in the pitch.
- Permission Delegation is enabled on testnet. Credentials are almost certainly live; confirm with one `CredentialCreate` in the spike.

## Accounts

| Account | Role |
| --- | --- |
| Treasury | Main money. Key used only for scheduled top-ups of the spend account, signed by a human, never by any program. |
| Spend account | Holds the float (e.g. 2,000). Delegates **Payment only** to the desk (`DelegateSet`). Admin holds its key, used only for setup. |
| Desk | Master key disabled. `SignerListSet`: daemon key + policy key, weight 1 each, quorum 2. Sends payments on the spend account's behalf via the `Delegate` field; pays the fee. |
| Vendor registry | Separate authority issuing on-chain "verified vendor" credentials. Each vendor must accept its credential (`CredentialAccept`) during setup before it counts. |
| Vendors | A few legitimate vendors plus one scammer account (no credential). |

## Kill switch (break-glass file)

At setup: create a Ticket on the spend account, sign a `DelegateSet` with empty permissions against that `TicketSequence`, with NO `LastLedgerSequence`, and save the signed blob as a file. In an emergency anyone submits it; no key is needed at that moment.

- Sign it with a generous fee: it never expires, and the fee is locked in at signing while network fees can rise.
- Never use that Ticket for anything else.
- Re-sign it if the spend account's signing setup changes (e.g. the key that signed it gets disabled).
- Anyone holding the file can revoke the desk. That's the safe direction, but treat it like a fire alarm: not secret, not public.

The dashboard's kill switch button submits this file. **The dashboard never holds any key.**

## Components

- **Reader** (LLM, the only "smart" part): extracts vendor, amount, invoice ID into an *intent*. Never produces addresses that get used, never touches keys.
- **Signer daemon**: holds the agent key. Stores each intent under a random nonce, forwards it to the policy service, signs only a transaction that exactly matches the stored intent.
- **Policy service**: holds the policy key. Checks rules, builds the exact transaction itself, verifies the daemon's signature, adds its own, submits, logs.
- **Dashboard**: invoices, decisions, testnet explorer links, refusals, blast radius report, kill switch (submits the break-glass file).

## Payment flow

1. Reader files an intent (vendor, amount, invoice ID) with the daemon.
2. Daemon stores it under a nonce, forwards to the policy service.
3. Policy service checks: vendor on its list AND holds an **accepted** registry credential (check the accepted flag), claimed destination matches the vendor record, allowed jurisdiction, open purchase order, no duplicate invoice, per-payment cap, daily cap (reserved atomically), velocity.
4. Policy service builds the transaction: destination from its own vendor record, hashed invoice ID in `InvoiceID`, audit commitment in `Memos`, agent `SourceTag`, `Delegate` = desk, `Account` = spend account.
5. Daemon compares to the stored intent; signs only on exact match.
6. Policy service verifies, co-signs, combines (multisign), submits, logs the result code.
7. Ledger checks both signatures against the desk's signer list and that the delegation covers Payment.

## Security invariants (never break these)

- Destinations come ONLY from the policy service's vendor records. Never from reader output.
- Built payments must NOT set the partial-payment flag, `Paths`, or `SendMax`.
- The daemon signs only exact matches to a stored intent. No "close enough."
- The daemon's vendor directory is loaded from its own file on the daemon's host (`VENDORS_FILE`); the policy service has no path to change it. Adding a vendor is two separate actions.
- Keys never enter the LLM's context, prompts, logs, or the dashboard.
- Rule checks live in the policy service, never only in the reader.
- The credential requirement is code, not configuration. No admin setting may disable it. Admins may edit the vendor list and caps only.
- Payments come from the spend account, never directly from the treasury.
- No program ever signs with the treasury key.
- Log is hash-chained; each payment's memo carries the commitment made before submission. Claim only what it proves: nothing was altered afterward. Completeness is checked separately against ledger history.

## Worst case per compromised part (what the blast radius report prints)

| Compromised | Max loss |
| --- | --- |
| Reader (prompt injection) | $0: it can only file intents |
| Agent (daemon) key | $0: ledger needs the policy signature |
| Policy key | Alone $0. With a poisoned reader too: up to the float, to legitimate vendors only (daemon blocks other destinations/amounts) |
| Vendor registry key | $0: credential alone doesn't get a vendor on the policy list |
| Policy admin | No payment outside the vendor list (a listed vendor still needs an accepted registry credential, enforced in code). Can raise caps: with a poisoned reader, up to the float to legitimate vendors |
| Daemon + policy keys | Spend float, payments only (no setting changes) |
| Spend account key | Spend float |
| Treasury key | Everything (human-only key) |

The report must enumerate every path money could take, or its number is wrong. Check and print: all delegates of the spend account; regular key, signer list and master-key-disabled flag on every account involved; balances. Re-run on setup changes and alert if the worst case grows.

## Attacks the demo must show failing

| Attack | Stopped by |
| --- | --- |
| Poisoned invoice (known vendor, "new bank details") | Policy service: claimed destination mismatch + cap + duplicate checks; nothing signed |
| Swapped address | Destinations only from policy records |
| Agent's own mistake (duplicate, over cap, off-list) | Policy service refuses before signing |
| Leaked agent key alone | Ledger: not enough signatures |
| Settings change with both keys | Ledger: delegation covers Payment only (record the actual error code in the spike) |
| Both keys stolen | Ledger caps loss at the float |
| Fake vendor added by corrupt admin | Also needs a registry credential |
| Kill switch | Break-glass file submitted; even a valid signed payment fails |

## Demo (about 3 minutes)

Set the float to two or three payments' worth so scene 4 drains it quickly. Scenes total 3:00; budget 3:30 with transitions.

1. Normal payment (20s): agent pays on its own; show it on the testnet explorer.
2. Poisoned invoice (25s): reader fooled, policy refuses, nothing signed.
3. Agent's own mistake (15s): duplicate refused.
4. Stolen keys (35s): agent key alone rejected; both keys stop at the float.
5. Top-up (10s): a human refills the spend account from the treasury, so scene 7 fails for the right reason.
6. Settings change (20s): both keys try to change spend account settings; ledger refuses with the real error code.
7. Kill switch (20s): submit the break-glass file; a fully signed payment now fails with the delegation error, not `tecUNFUNDED_PAYMENT`.
8. Proof for the risk team (25s): blast radius report with its checks; audit completeness check flags the payments the log never saw (the attacker's from scene 4). This is intended, not a bug.
9. Close (10s).

## Build order

1. **Spike in XRP** (~30 min): one delegated, two-signature payment from the spend account returning `tesSUCCESS` on testnet. Record every result code. Include one `CredentialCreate` and one settings-change attempt to capture its error code.
2. Switch the spike to RLUSD (trust lines on spend account and vendors).
3. HTTP layer between reader, daemon, policy service.
4. Break-glass file and dashboard.
5. Blast radius report.
6. Audit completeness check (read-only script over the spend account's `account_tx`; every payment must have a matching log entry).
7. Vendor credentials, including each vendor's `CredentialAccept` and an accepted-flag check in the policy service.
8. Pitch slides.
9. Stretch: honey key (decoy key that triggers a freeze). Not in the demo.

Cut order if time runs out: honey key, then vendor credentials, then audit completeness check. Keep the capped spend account, break-glass file and blast radius report.

What cutting removes: cutting vendor credentials removes the "fake vendor added" attack, the "policy admin" worst-case row and the "one insider isn't enough" claim. Cutting the audit completeness check removes the second half of scene 8. Keep the pitch matched to whatever ships.

Team split: **Ledger** (spike, RLUSD switch, account setup, break-glass file) · **Core services** (HTTP layer, policy and daemon changes) · **Front** (dashboard, blast radius report, audit completeness check, pitch) · vendor credentials to whoever finishes first.

## Existing code

- Python prototype with 31 passing acceptance tests against a local mini-ledger that verifies real signatures. **Keep all tests passing.** Add tests for every new rule and attack.
- Browser demo running the same logic in xrpl.js.
- Planning bundle: spec, decisions, roadmap, gate, runbook.
- The prototype is the source of truth for attack stories; keep the demo and docs matching what the code actually does.

## Repo layout, ownership and commands

Ownership is one person per path (see CODEOWNERS). The owner reads every diff that lands there. Phase numbers refer to planning/ROADMAP.md.

```
fuse/                             the package
  config.py                       policy as data: caps, allowlist, jurisdictions, RLUSD flag     Core
  setup.py                        accounts, DelegateSet, SignerListSet, master off, revoke       Ledger
  breakglass.py                   Ticket-based pre-signed revocation                             Ledger
  ledger/local.py                 mini-ledger for tests: real signature, quorum, delegation checks   Core
  ledger/testnet.py               xrpl-py adapter, same interface (untested until the spike)     Ledger
  policy/rules.py                 the rules; human-owned, no agent edits                          Core
  policy/builder.py               canonical Payment                                               Core
  policy/service.py               the pipeline                                                    Core
  policy/credentials.py           accepted-credential check; the rule is code (Phase 7)           whoever finishes first
  policy/api.py                   FastAPI app (Phase 2)                                            Core
  signer/daemon.py                agent key + intent table; verifier human-owned                  Core
  signer/api.py                   daemon over HTTP (Phase 3)                                       Core
  reader/reader.py                untrusted reader and invoice fixtures (Phase 3 makes it a process)   Core
  reports/blast_radius.py         worst case per compromised part, setup findings (Phase 5)       Front
  reports/audit_completeness.py   ledger payments missing from the audit log (Phase 6)            Front
  audit.py, budget.py             hash chain; atomic reservations                                  Core
  demo.py                         local demo; doubles as the integration test                     Core
scripts/spike/run.py              Phase 0, raced in two worktrees, throwaway                       Ledger
scripts/setup_testnet.py          Phase 1: fund, delegate, signer list, ticket, break-glass file   Ledger
scripts/topup.py                  human-signed top-up (demo scene 5)                               Ledger
scripts/kill_switch.py            submits break-glass/revoke.json; holds no key                    Ledger
scripts/credentials.py            Phase 7: registry issues, vendors accept                         whoever finishes first
tests/                            test_acceptance.py (AC3–AC16), blast radius, audit, break-glass  Core owns test_acceptance.py
dashboard/                        Phase 4; holds no keys                                           Front
demo/backup/fuse-live-demo.html   browser demo in xrpl.js; the fallback if testnet is down on stage
pitch/                            outline and slides (Phase 8)                                     Front
planning/                         SPEC, ROADMAP, DECISIONS, CATCHUP, LEARN, PROMPTS; gitignored, shared on the team drive
inbox/ env/ data/ break-glass/    runtime folders, gitignored; env/accounts.json is written by setup
```

Commands (Makefile): `make install` · `make test` · `make demo-local` · `make spike` · `make setup-testnet` · `make topup` · `make kill` · `make policy` / `make daemon` / `make reader` (three terminals) · `make blast` · `make audit-check`. Tests: `pytest -q` (42 pass; the 3 break-glass tests are skipped until fuse/breakglass.py is implemented).

Session protocol: start by reading planning/CATCHUP.md and the current phase in planning/ROADMAP.md; end by updating CATCHUP.md (where we are, what is green with the boundary command's output, what is broken, the next single step and its owner). Prompts for every phase, the race, the rematch and the sweeps are in planning/PROMPTS.md.

## Conventions

- Python with `xrpl-py` for services; xrpl.js only in the browser demo.
- Don't invent XRPL field names, flags, error codes, or addresses. Check the docs (xrpl.org/docs, the XRPL MCP server, Context7), run it on testnet, or ask.
- When a ledger call fails, surface the exact result code; don't swallow it.
- Keep the reader simple. This track is about the financial guardrails, not the AI.
- Prefer small, working, demoable increments over big refactors.
- No plan files, scratchpads or docs unless asked; no emojis; minimal plain-voice comments; no "changed by AI" or TODO litter; match the file you are in; no new dependencies unless impossible without one; execute directly; leave zero scaffolding behind. Append to every task: smallest clean change, no unrelated edits, run the named checks and paste the output.
- Commits: conventional with scope, one idea each, evidence in the message when there is any. Trunk-based on main; worktrees only for the Phase 0 race. A person commits after reading the diff.
