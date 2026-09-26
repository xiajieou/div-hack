"""Rules. No network, no ledger, no model. Pure evaluation of an intent against the written policy.

Decision:
  refuse  - a hard rule failed; nothing is signed
  park    - every hard rule passed but the destination is unknown; a human must add the vendor, then the intent reruns
  pay     - proceed to reservation, build, signatures, submit
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import List, Optional, Set

from ..config import Policy


@dataclass
class Intent:
    vendor: str
    amount: str                     # decimal string in XRP
    invoice_id: str
    reason: str = ""
    claimed_destination: Optional[str] = None   # what the invoice says; never used as a Destination
    nonce: str = ""

    def public(self) -> dict:
        return {"vendor": self.vendor, "amount": self.amount, "invoice_id": self.invoice_id, "reason": self.reason,
                "claimed_destination": self.claimed_destination, "nonce": self.nonce}


@dataclass
class RuleResult:
    name: str
    ok: bool
    soft: bool = False
    note: str = ""


@dataclass
class Evaluation:
    rules: List[RuleResult] = field(default_factory=list)
    decision: str = "refuse"

    @property
    def failed(self) -> List[str]:
        return [f"{r.name}: {r.note}" if r.note else r.name for r in self.rules if not r.ok and not r.soft]

    def passed_all(self) -> bool:
        return all(r.ok for r in self.rules)


def parse_amount(text: str) -> Optional[Decimal]:
    try:
        d = Decimal(str(text).strip())
    except (InvalidOperation, ValueError):
        return None
    if not d.is_finite() or d <= 0:
        return None
    if -d.as_tuple().exponent > 6:
        return None   # XRP has six decimal places; anything finer is malformed
    return d


def evaluate(intent: Intent, policy: Policy, paid_invoices: Set[str], in_flight_invoices: Set[str],
             committed_xrp: Decimal, payments_last_hour: int) -> Evaluation:
    ev = Evaluation()
    r = ev.rules.append

    amount = parse_amount(intent.amount)
    r(RuleResult("amount is a positive decimal with at most 6 places", amount is not None, note="" if amount else f"got {intent.amount!r}"))
    if amount is None:
        return ev

    r(RuleResult("invoice id present", bool(intent.invoice_id and intent.invoice_id.strip()), note="" if intent.invoice_id else "missing"))
    if not intent.invoice_id:
        return ev

    po = policy.open_purchase_orders.get(intent.invoice_id)
    dup = intent.invoice_id in paid_invoices or intent.invoice_id in in_flight_invoices
    r(RuleResult("invoice matches an open purchase order and is unpaid", bool(po) and not dup,
                 note=("already paid or in flight" if dup else ("" if po else "no purchase order"))))

    r(RuleResult(f"amount within per-payment cap ({policy.per_payment_cap_xrp} XRP)", amount <= policy.per_payment_cap_xrp,
                 note="" if amount <= policy.per_payment_cap_xrp else f"{amount} over cap"))

    projected = committed_xrp + amount
    r(RuleResult(f"daily total within cap ({policy.daily_cap_xrp} XRP)", projected <= policy.daily_cap_xrp,
                 note=f"{projected} after this payment" if projected <= policy.daily_cap_xrp else f"{projected} would exceed cap"))

    r(RuleResult(f"velocity under {policy.per_hour_max_payments} per hour", payments_last_hour + 1 <= policy.per_hour_max_payments))

    vendor = policy.allowlist.get(intent.vendor)
    if vendor is None:
        r(RuleResult("destination is an allowlisted vendor", False, soft=True, note="unknown vendor; parked for a human to add"))
    else:
        r(RuleResult("destination is an allowlisted vendor", True, note=vendor.name))
        r(RuleResult("vendor jurisdiction allowed", vendor.jurisdiction in policy.allowed_jurisdictions,
                     note=vendor.jurisdiction))
        if intent.claimed_destination:
            match = intent.claimed_destination == vendor.address
            r(RuleResult("claimed destination matches the vendor record", match,
                         note="" if match else "invoice names a different account: address swap attempt"))

    if any(not x.ok and not x.soft for x in ev.rules):
        ev.decision = "refuse"
    elif any(x.soft for x in ev.rules):
        ev.decision = "park"
    else:
        ev.decision = "pay"
    return ev
