"""Daily budget with atomic reservations.

The check and the reservation happen inside one SQLite transaction opened with BEGIN IMMEDIATE, which takes the
write lock before reading. Two concurrent requests therefore serialize: the second one reads the first one's
reservation and is refused if the cap would be exceeded. Reservations are released if the payment is refused later
in the pipeline or expires unvalidated, and settled when the ledger validates it.
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from decimal import Decimal
from typing import Optional


class BudgetError(Exception):
    pass


class Budget:
    def __init__(self, daily_cap_drops: int, per_hour_max: int, path: str = ":memory:") -> None:
        self.daily_cap_drops = daily_cap_drops
        self.per_hour_max = per_hour_max
        self._lock = threading.RLock()  # SQLite in-memory databases are per-connection; a lock keeps one connection safe
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, drops INTEGER NOT NULL, status TEXT NOT NULL, created REAL NOT NULL)")

    def committed_drops(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COALESCE(SUM(drops),0) FROM reservations WHERE status IN ('reserved','settled')").fetchone()
            return int(row[0])

    def payments_last_hour(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) FROM reservations WHERE status IN ('reserved','settled') AND created > ?", (time.time() - 3600,)).fetchone()
            return int(row[0])

    def reserve(self, drops: int) -> str:
        """Atomically reserve drops against the daily cap. Raises BudgetError if the cap or velocity would be exceeded."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                committed = self.committed_drops()
                if committed + drops > self.daily_cap_drops:
                    raise BudgetError(f"daily cap: {committed + drops} would exceed {self.daily_cap_drops} drops")
                if self.payments_last_hour() + 1 > self.per_hour_max:
                    raise BudgetError(f"velocity: more than {self.per_hour_max} payments in the last hour")
                rid = uuid.uuid4().hex
                self._db.execute("INSERT INTO reservations VALUES (?,?,?,?)", (rid, drops, "reserved", time.time()))
                self._db.execute("COMMIT")
                return rid
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def release(self, rid: str) -> None:
        with self._lock:
            self._db.execute("UPDATE reservations SET status='released' WHERE id=?", (rid,))

    def settle(self, rid: str) -> None:
        with self._lock:
            self._db.execute("UPDATE reservations SET status='settled' WHERE id=?", (rid,))

    def reset(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM reservations")
