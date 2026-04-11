"""Persistent correlation: string sets and sliding-window thresholds (SQLite)."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_lock = threading.Lock()
_init_done = False


def _db_path() -> str:
    return os.environ.get(
        "IOTA_CORRELATION_STATE",
        os.path.join(os.path.expanduser("~"), ".cache", "iota", "correlation.sqlite"),
    )


def _conn() -> sqlite3.Connection:
    path = _db_path()
    if path == ":memory:":
        c = sqlite3.connect(path, timeout=30)
    else:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        c = sqlite3.connect(path, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def _ensure_schema() -> None:
    global _init_done
    if _init_done:
        return
    with _conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kv_seen (
                k TEXT PRIMARY KEY,
                seen_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS window_counts (
                dedup_key TEXT NOT NULL,
                ts REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_window_dedup_ts
                ON window_counts(dedup_key, ts);
            """
        )
    _init_done = True


def correlation_enabled() -> bool:
    return os.environ.get("IOTA_CORRELATION", "1") not in ("0", "false", "False")


def get_string_set(key: str) -> List[str]:
    """Return a non-empty list if key was previously stored (SIEM-style string set)."""
    _ensure_schema()
    with _lock:
        with _conn() as conn:
            cur = conn.execute("SELECT k FROM kv_seen WHERE k = ?", (key,))
            row = cur.fetchone()
            return [row[0]] if row else []


def put_string_set(key: str, value: str) -> None:  # noqa: ARG001 — value kept for API parity
    _ensure_schema()
    with _lock:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv_seen (k, seen_at) VALUES (?, ?)",
                (key, time.time()),
            )


def sliding_window_threshold_crossed(
    dedup_key: str,
    window_seconds: int,
    threshold: int,
    event_ts: Optional[float] = None,
) -> bool:
    """
    Count events for dedup_key in [event_ts - window, event_ts].
    Return True only when this event is the one that reaches exactly `threshold`
    (Nth matching event in the window).
    """
    if not correlation_enabled():
        return True
    _ensure_schema()
    now = float(event_ts) if event_ts is not None else time.time()
    cutoff = now - float(window_seconds)
    with _lock:
        with _conn() as conn:
            conn.execute(
                "DELETE FROM window_counts WHERE dedup_key = ? AND ts < ?",
                (dedup_key, cutoff),
            )
            cur = conn.execute(
                "SELECT COUNT(*) FROM window_counts WHERE dedup_key = ?",
                (dedup_key,),
            )
            prev = int(cur.fetchone()[0])
            conn.execute(
                "INSERT INTO window_counts (dedup_key, ts) VALUES (?, ?)",
                (dedup_key, now),
            )
            new = prev + 1
            return new == threshold


def event_unix_ts(event: Dict[str, Any]) -> float:
    """Best-effort event time for windowing (replay-friendly)."""
    v = (
        event.get("p_event_time")
        or event.get("Datetime")
        or event.get("EdgeStartTimestamp")
        or event.get("date_create")
    )
    if v is None:
        return time.time()
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if not s:
        return time.time()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return time.time()
