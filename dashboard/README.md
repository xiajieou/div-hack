# Dashboard and flow view

## Flow view (`flow.html`, `flow.py`)

    make flow               # local ledger; then open http://localhost:8001/
    make flow MODE=devnet   # the accounts scripts/setup_testnet.py created, real transactions

On devnet the flow server reads env/accounts.json and the agent, policy and spend keys from .env, never the treasury
key: Top up tells the presenter to run `make topup`. The kill switch submits break-glass/revoke.json with no key;
Reset restores the desk's Payment permission and re-arms the file on a new Ticket. Accounts and history stay. Audit completeness counts payments since the server started, and the invoices
already paid on the ledger are read back at startup so a restart cannot pay one twice.

The system drawn as boxes, top to bottom. Pick a scenario and it runs through the real policy service, signer daemon
and local ledger; each box lights up as it acts (amber working or fooled, green passed, red stopped it, blue waiting for
a human). Hover or click a box for its live checklist and output. Slow motion pauses between steps; Follow along opens
the box that is working. Blast radius and audit completeness stay on the right and update after every ledger call.
`flow.py` only watches: it wraps the functions each part calls and streams what happened. The one exception is the
"hacked policy service" scenario, which swaps the destination after the payment is built, and says so.

## Dashboard (`index.html`)

One page, `index.html`, served by the policy service at `/dashboard`. It holds no keys.

    make dashboard          # local ledger with the demo invoices and two stolen-key attacks, no network
    make policy             # the real policy service; open http://localhost:8001/dashboard

It polls `GET /status` (invoices, decisions, audit log, ledger history), `GET /reports` (blast radius and audit
completeness) and `GET /invoices` (inbox files, to show the poisoned invoice's hidden text). Its two buttons call
`POST /admin/vendor` and `POST /submit-file`; the kill switch stays disabled until `break-glass/revoke.json` exists.

`make dashboard` leaves Northwind Freight parked and prints its address, so the Add vendor form has something to do.
