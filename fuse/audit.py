"""Hash-chained audit trail.

  H(0) = 64 zero hex chars
  proposal row:  H(n)   = sha256(H(n-1) + canonical json of the proposal record)   -> rides in the payment memo
  result row:    H(n+1) = sha256(H(n)   + canonical json of {tx hash, result})
  refusals, parks and admin actions are rows too; they are anchored by the next successful payment's memo.

What this proves: nothing already committed was altered without detection, and each payment's memo matches the
commitment made before it was submitted. What it does not prove: that nothing was omitted before a commitment.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

GENESIS = "0" * 64


def _h(prev: str, record: dict) -> str:
    return hashlib.sha256((prev + json.dumps(record, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


@dataclass
class Row:
    kind: str            # proposal | result | refused | parked | admin | note
    record: dict
    prev: str
    hash: str
    t: float = field(default_factory=time.time)


class AuditChain:
    def __init__(self, policy_hash: str) -> None:
        self.policy_hash = policy_hash
        self.rows: List[Row] = []
        self._lock = threading.Lock()

    @property
    def head(self) -> str:
        return self.rows[-1].hash if self.rows else GENESIS

    def _append(self, kind: str, record: dict) -> Row:
        with self._lock:
            record = dict(record)
            record["kind"] = kind
            record["policy_hash"] = self.policy_hash
            row = Row(kind, record, self.head, _h(self.head, record))
            self.rows.append(row)
            return row

    def commit_proposal(self, proposal: dict) -> str:
        """Called BEFORE submission. The returned hash goes into the payment memo."""
        return self._append("proposal", proposal).hash

    def append_result(self, commitment: str, tx_hash: str, engine_result: str, note: str = "") -> str:
        return self._append("result", {"commitment": commitment, "tx_hash": tx_hash, "result": engine_result, "note": note}).hash

    def refused(self, intent: dict, failed_rules: List[str], extra: Optional[dict] = None) -> str:
        return self._append("refused", {"intent": intent, "failed": failed_rules, **(extra or {})}).hash

    def parked(self, intent: dict, reason: str) -> str:
        return self._append("parked", {"intent": intent, "reason": reason}).hash

    def admin(self, action: str, detail: dict) -> str:
        return self._append("admin", {"action": action, **detail}).hash

    def note(self, text: str, detail: Optional[dict] = None) -> str:
        return self._append("note", {"text": text, **(detail or {})}).hash

    # ----- verification -----
    def verify(self, memos_by_tx_hash: Dict[str, str]) -> tuple[bool, str]:
        """Recompute every hash; check each result row's payment memo carries the commitment made before it."""
        prev = GENESIS
        for i, row in enumerate(self.rows):
            if row.prev != prev:
                return False, f"row {i} ({row.kind}) prev pointer mismatch"
            if _h(prev, row.record) != row.hash:
                return False, f"row {i} ({row.kind}) hash mismatch: contents were altered"
            if row.kind == "result" and row.record["result"] == "tesSUCCESS":
                memo = memos_by_tx_hash.get(row.record["tx_hash"])
                if memo != row.record["commitment"]:
                    return False, f"row {i}: payment memo {str(memo)[:12]} does not match commitment {row.record['commitment'][:12]}"
            prev = row.hash
        return True, f"{len(self.rows)} rows verified; head {self.head[:12]}"

    def dump(self) -> List[dict]:
        return [{"i": i, "kind": r.kind, "hash": r.hash[:12], "prev": r.prev[:12], **{k: v for k, v in r.record.items() if k not in ("kind", "policy_hash")}} for i, r in enumerate(self.rows)]
