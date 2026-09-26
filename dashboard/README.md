# Dashboard (Phase 4, owner: Front)

One page over GET /status from the policy service. Build against mock rows first; switch to the live API when Phase 2 lands.

Shows: invoices with their decisions (paid, refused, parked, rejected by ledger), testnet explorer links, the poisoned row's hidden text, the blast radius table (Phase 5), the audit completeness result (Phase 6).

Actions: add vendor (POST /admin/vendor, the logged admin path), kill switch (POST /submit-file with break-glass/revoke.json). The dashboard holds no keys.

Stack: whatever the owner is fastest in. A single static page polling the API is enough for the demo; Next.js only if it costs nothing.
