"""The written policy. Everything the co-signer enforces lives here, and its hash rides in every payment memo."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from decimal import Decimal
from typing import Dict, Optional, Set

SOURCE_TAG = 20260926          # identifies the Fuse agent on every payment (agent attribution)
XRP_DROPS = Decimal(1_000_000)


@dataclass
class VendorRecord:
    name: str
    address: str                 # filled at setup; the only place a Destination can come from
    jurisdiction: str
    destination_tag: Optional[int] = None


@dataclass
class Policy:
    per_payment_cap_xrp: Decimal = Decimal("25")
    daily_cap_xrp: Decimal = Decimal("60")
    per_hour_max_payments: int = 20
    fee_cap_drops: int = 100
    allowed_jurisdictions: Set[str] = field(default_factory=lambda: {"US", "CA", "GB"})
    allowlist: Dict[str, VendorRecord] = field(default_factory=dict)
    open_purchase_orders: Dict[str, str] = field(default_factory=dict)   # invoice_id -> PO

    def hash(self) -> str:
        """SHA-256 of the policy as data. Changes to caps or the allowlist change this, and it is in every memo."""
        payload = {
            "per_payment_cap_xrp": str(self.per_payment_cap_xrp),
            "daily_cap_xrp": str(self.daily_cap_xrp),
            "per_hour_max_payments": self.per_hour_max_payments,
            "fee_cap_drops": self.fee_cap_drops,
            "allowed_jurisdictions": sorted(self.allowed_jurisdictions),
            "allowlist": {k: asdict(v) for k, v in sorted(self.allowlist.items())},
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def default_policy() -> Policy:
    """Vendors get their addresses at setup (local wallets or faucet wallets)."""
    p = Policy()
    p.allowlist = {
        "Verdant Print Co": VendorRecord("Verdant Print Co", "", "US"),
        "Harbor Cloud Hosting": VendorRecord("Harbor Cloud Hosting", "", "US"),
        "Lumen Legal": VendorRecord("Lumen Legal", "", "GB"),
        "Baltic Freight": VendorRecord("Baltic Freight", "", "RU"),   # on the list, wrong jurisdiction
    }
    p.open_purchase_orders = {
        "INV-2201": "PO-118",
        "INV-7734": "PO-119",
        "INV-0092": "PO-121",
        "INV-5510": "PO-124",
        "INV-3300": "PO-130",
        "INV-9001": "PO-140",
    }
    return p


def xrp_to_drops(amount: Decimal) -> str:
    return str(int((amount * XRP_DROPS).to_integral_value()))


def drops_to_xrp(drops: str | int) -> Decimal:
    return Decimal(int(drops)) / XRP_DROPS
