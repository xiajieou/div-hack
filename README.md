# Fuse

An AI agent that pays vendor invoices on the XRP Ledger without being able to lose the company's money.

The agent can propose payments all day, but it can never sign one alone. Two independent programs must agree before any money moves, and the ledger itself limits what even both of them together can do.

Built for DivHacks 2026, Ripple track: Best Agentic Finance Infrastructure on XRPL.

<!-- Add docs/system-design.png back here once the build matches the target design (separate spend account, break-glass file, dashboard). -->

## How it works

Three programs, each holding at most one key:

- **Reader**: reads an invoice and turns it into a request: vendor, amount, invoice ID. It is assumed to be fooled, so it holds no keys and never chooses where money goes.
- **Signer daemon**: holds the agent key. It remembers each request and signs only a payment that matches it exactly.
- **Policy service**: holds the policy key. It checks the rules (known vendor, allowed country, open purchase order, no duplicate, per-payment and daily caps, rate limit), builds the payment itself with the destination taken from its own vendor records, collects the daemon's signature, adds its own, submits, and logs.

On the ledger:

- **Desk**: an account whose own key is switched off. It can act only when the agent key and the policy key sign together (2 of 2).
- **Paying account**: holds the money and allows the desk to send Payments on its behalf, and nothing else (XRPL Permission Delegation). Changing its settings is refused even with both keys.

A payment moves like this: invoice → reader → daemon stores the request → policy checks the rules and builds the payment → daemon signs if it matches → policy co-signs and submits → the ledger checks both signatures and the Payment-only permission.

## What gets stopped

| Attack | Stopped by |
| --- | --- |
| Poisoned invoice ("our bank details changed, send 50 XRP here") | Policy service: destination mismatch, over cap, duplicate. Nothing is signed. |
| Agent mistakes: duplicate, over cap, unknown vendor | Policy service refuses; unknown vendors are parked until a human adds them |
| Stolen agent key alone | Ledger: `tefBAD_QUORUM` |
| Both keys try to change account settings | Ledger: `temINVALID` |
| Kill switch, then a fully signed payment | Ledger: `terNO_DELEGATE_PERMISSION` |
| Someone edits the audit log afterwards | Hash chain verification fails |
| Payments made around the service with stolen keys | Audit completeness check lists every payment the log never saw |

Ledger codes are from a run on XRPL devnet. Example of an autonomous, two-signature delegated payment: [devnet tx E3FF8540…3DDED4](https://devnet.xrpl.org/transactions/E3FF854003625B37608C6A7986011E65194BF23428DE1CCDB0AA38FEBE3DDED4).

## Run it

```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

On Windows, set `PYTHONIOENCODING=utf-8` first (PowerShell: `$env:PYTHONIOENCODING="utf-8"`).

| Command | What it does |
| --- | --- |
| `make test` | Test suite, against a local ledger that checks real signatures |
| `make demo-local` | Full demo on the local ledger, no network |
| `python -m fuse.demo --mode devnet` | Same demo on XRPL devnet with fresh faucet accounts; takes a few minutes |
| `make blast` | Blast radius report: worst case per stolen key, plus any setup mistake that would make it worse |
| `make audit-check` | Audit completeness: payments on the ledger that the audit log never saw |

The two reports accept `MODE=devnet` to read real accounts from `env/accounts.json`.

## Network

Fuse runs on **XRPL devnet, in XRP**. Permission Delegation, which the desk depends on, is not enabled on testnet yet, and RLUSD is only issued on testnet, so the demo uses XRP.

## Status

| Piece | Status |
| --- | --- |
| Payment pipeline: reader, daemon, policy service, ledger checks | Working, local and devnet |
| Desk: 2-of-2 signatures, own key off, Payment-only delegation | Working on devnet |
| Policy service and signer daemon over HTTP | Working |
| Hash-chained audit log | Working |
| Blast radius and audit completeness reports | Working |
| Separate spend account, refilled by hand from a treasury | In progress; payments currently come from a single account |
| Pre-signed break-glass file (kill switch that needs no key) | In progress; the demo currently revokes with the account key |
| One-command devnet setup | In progress |
| Reader as its own process watching `inbox/` | In progress |
| Dashboard | In progress |
| Vendor credentials from an on-ledger registry | Planned, optional |

## Team

Ledger: @isnahos · Core services: @xiajieou · Front & verification: @longlostt
