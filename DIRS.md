# Directories

| Dir | What's in it | Owner |
|---|---|---|
| `fuse/` | The Python package: setup, config, audit log, budget, demo | mixed, see CODEOWNERS |
| `fuse/ledger/` | Ledger backends: local mini-ledger for tests, testnet adapter | Core (local), Ledger (testnet) |
| `fuse/policy/` | Policy service: rules, payment builder, pipeline, HTTP API | Core |
| `fuse/signer/` | Signer daemon holding the agent key, plus its HTTP API | Core |
| `fuse/reader/` | Untrusted invoice reader and fixtures | Core |
| `fuse/reports/` | Blast radius and audit completeness reports | Front |
| `scripts/` | Testnet setup, top-up, kill switch, credentials, Phase 0 spike | Ledger |
| `exercises/` | Three hand-written pieces with pre-written tests | Front (ex1, ex2), Ledger (ex3) |
| `tests/` | Acceptance tests and exercise tests | Core |
| `dashboard/` | Status page over the policy API; holds no keys | Front |
| `demo/backup/` | Browser demo, the fallback if testnet is down on stage | none |
| `pitch/` | Pitch outline and slides | Front |
| `docs/` | System design diagram (PNG shown in the README, SVG source) | none |
| `inbox/` `env/` `data/` `break-glass/` | Runtime folders, gitignored | none |
| `planning/` | Spec, roadmap, decisions. Not in this repo on purpose, so clones and cloud agents will not have it; get it from the team drive and drop it in here | none |

Owners: Ledger @isnahos · Core @xiajieou · Front @longlostt
