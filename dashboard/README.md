# Dashboard

One page, `index.html`, served by the policy service at `/dashboard`. It holds no keys.

    make dashboard          # local ledger with the demo invoices and two stolen-key attacks, no network
    make policy             # the real policy service; open http://localhost:8001/dashboard

It polls `GET /status` (invoices, decisions, audit log, ledger history), `GET /reports` (blast radius and audit
completeness) and `GET /invoices` (inbox files, to show the poisoned invoice's hidden text). Its two buttons call
`POST /admin/vendor` and `POST /submit-file`; the kill switch stays disabled until `break-glass/revoke.json` exists.

`make dashboard` leaves Northwind Freight parked and prints its address, so the Add vendor form has something to do.
