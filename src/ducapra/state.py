from __future__ import annotations

import sqlite3
import hashlib
import json
import time
from pathlib import Path
from typing import Protocol


class StateStore(Protocol):
    def get_round(self) -> int:
        ...

    def advance_round(self, expected_round: int) -> int:
        ...

    def reserve_nonce(self, nonce: str, now_ms: int | None = None) -> None:
        ...

    def evict_nonces(self, now_ms: int | None = None) -> None:
        ...

    def record_triangle(self, round_id: int, triangle_hash: str, now_ms: int | None = None) -> None:
        ...

    def append_audit_event(
        self,
        event_type: str,
        outcome: str,
        details: dict,
        now_ms: int | None = None,
    ) -> str:
        ...

    def audit_events(self) -> list[dict]:
        ...


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _audit_hash(
    *,
    sequence: int,
    previous_hash: str,
    event_type: str,
    outcome: str,
    details: dict,
    timestamp_ms: int,
) -> str:
    payload = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event_type": event_type,
        "outcome": outcome,
        "details": details,
        "timestamp_ms": timestamp_ms,
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


class InMemoryStateStore:
    def __init__(self, nonce_ttl_seconds: int):
        self.nonce_ttl_ms = nonce_ttl_seconds * 1000
        self._round_id = 0
        self._nonces: dict[str, int] = {}
        self._triangles: list[tuple[int, str, int]] = []
        self._audit_events: list[dict] = []

    def get_round(self) -> int:
        return self._round_id

    def advance_round(self, expected_round: int) -> int:
        if self._round_id != expected_round:
            raise ValueError("round state changed during execution")
        self._round_id += 1
        return self._round_id

    def reserve_nonce(self, nonce: str, now_ms: int | None = None) -> None:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        self.evict_nonces(now_ms)
        if nonce in self._nonces:
            raise ValueError("replay detected")
        self._nonces[nonce] = now_ms

    def reserve(self, nonce: str, now_ms: int | None = None) -> None:
        self.reserve_nonce(nonce, now_ms=now_ms)

    def evict_nonces(self, now_ms: int | None = None) -> None:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        expired = [
            nonce
            for nonce, seen_at_ms in self._nonces.items()
            if now_ms - seen_at_ms > self.nonce_ttl_ms
        ]
        for nonce in expired:
            del self._nonces[nonce]

    def evict(self, now_ms: int | None = None) -> None:
        self.evict_nonces(now_ms=now_ms)

    def record_triangle(self, round_id: int, triangle_hash: str, now_ms: int | None = None) -> None:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        self._triangles.append((round_id, triangle_hash, now_ms))

    def append_audit_event(
        self,
        event_type: str,
        outcome: str,
        details: dict,
        now_ms: int | None = None,
    ) -> str:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        previous_hash = self._audit_events[-1]["event_hash"] if self._audit_events else "0" * 64
        sequence = len(self._audit_events) + 1
        event_hash = _audit_hash(
            sequence=sequence,
            previous_hash=previous_hash,
            event_type=event_type,
            outcome=outcome,
            details=details,
            timestamp_ms=now_ms,
        )
        self._audit_events.append(
            {
                "sequence": sequence,
                "previous_hash": previous_hash,
                "event_hash": event_hash,
                "event_type": event_type,
                "outcome": outcome,
                "details": details,
                "timestamp_ms": now_ms,
            }
        )
        return event_hash

    def audit_events(self) -> list[dict]:
        return list(self._audit_events)

    def __len__(self) -> int:
        return len(self._nonces)


class SQLiteStateStore:
    """Restart-safe DuCaPra state using SQLite.

    This stores replay nonces, the monotonic TLA round, and observed triangle
    hashes. It is a local durable store, not a distributed consensus mechanism.
    Multi-node deployments should place this behind a service or transactional DB
    with equivalent compare-and-swap semantics for `advance_round`.
    """

    def __init__(self, path: str | Path, nonce_ttl_seconds: int):
        self.path = Path(path)
        self.nonce_ttl_ms = nonce_ttl_seconds * 1000
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    seen_at_ms INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS triangles (
                    triangle_hash TEXT PRIMARY KEY,
                    round_id INTEGER NOT NULL,
                    seen_at_ms INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    timestamp_ms INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO state(key, value) VALUES ('round_id', 0)"
            )

    def get_round(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM state WHERE key = 'round_id'"
        ).fetchone()
        if row is None:
            raise RuntimeError("state table is missing round_id")
        return int(row[0])

    def advance_round(self, expected_round: int) -> int:
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE state
                SET value = value + 1
                WHERE key = 'round_id' AND value = ?
                """,
                (expected_round,),
            )
            if cursor.rowcount != 1:
                raise ValueError("round state changed during execution")
        return self.get_round()

    def reserve_nonce(self, nonce: str, now_ms: int | None = None) -> None:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        with self._conn:
            self._evict_nonces_unlocked(now_ms)
            try:
                self._conn.execute(
                    "INSERT INTO nonces(nonce, seen_at_ms) VALUES (?, ?)",
                    (nonce, now_ms),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("replay detected") from exc

    def reserve(self, nonce: str, now_ms: int | None = None) -> None:
        self.reserve_nonce(nonce, now_ms=now_ms)

    def evict_nonces(self, now_ms: int | None = None) -> None:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        with self._conn:
            self._evict_nonces_unlocked(now_ms)

    def evict(self, now_ms: int | None = None) -> None:
        self.evict_nonces(now_ms=now_ms)

    def _evict_nonces_unlocked(self, now_ms: int) -> None:
        cutoff_ms = now_ms - self.nonce_ttl_ms
        self._conn.execute("DELETE FROM nonces WHERE seen_at_ms < ?", (cutoff_ms,))

    def record_triangle(self, round_id: int, triangle_hash: str, now_ms: int | None = None) -> None:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        with self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO triangles(triangle_hash, round_id, seen_at_ms)
                VALUES (?, ?, ?)
                """,
                (triangle_hash, round_id, now_ms),
            )

    def append_audit_event(
        self,
        event_type: str,
        outcome: str,
        details: dict,
        now_ms: int | None = None,
    ) -> str:
        now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        details_json = _canonical_json(details).decode()
        with self._conn:
            row = self._conn.execute(
                "SELECT sequence, event_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = row[1] if row else "0" * 64
            next_sequence = int(row[0]) + 1 if row else 1
            event_hash = _audit_hash(
                sequence=next_sequence,
                previous_hash=previous_hash,
                event_type=event_type,
                outcome=outcome,
                details=details,
                timestamp_ms=now_ms,
            )
            self._conn.execute(
                """
                INSERT INTO audit_log(
                    sequence,
                    previous_hash,
                    event_hash,
                    event_type,
                    outcome,
                    details_json,
                    timestamp_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_sequence,
                    previous_hash,
                    event_hash,
                    event_type,
                    outcome,
                    details_json,
                    now_ms,
                ),
            )
        return event_hash

    def audit_events(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT sequence, previous_hash, event_hash, event_type, outcome, details_json, timestamp_ms
            FROM audit_log
            ORDER BY sequence ASC
            """
        ).fetchall()
        return [
            {
                "sequence": int(sequence),
                "previous_hash": previous_hash,
                "event_hash": event_hash,
                "event_type": event_type,
                "outcome": outcome,
                "details": json.loads(details_json),
                "timestamp_ms": int(timestamp_ms),
            }
            for sequence, previous_hash, event_hash, event_type, outcome, details_json, timestamp_ms in rows
        ]

    def __len__(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM nonces").fetchone()
        return int(row[0])

    def close(self) -> None:
        self._conn.close()
