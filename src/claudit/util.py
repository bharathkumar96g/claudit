from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def short_id(*parts: str) -> str:
    """Stable row id derived from content; not a security primitive."""
    return hashlib.sha1("|".join(parts).encode("utf-8"), usedforsecurity=False).hexdigest()[:24]


def utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def one(con: Any, sql: str, params: Sequence[Any] = ()) -> tuple[Any, ...]:
    """fetchone() that is known to return a row (aggregates, existence checks)."""
    row = con.execute(sql, list(params)).fetchone()
    if row is None:
        raise RuntimeError(f"query returned no row: {sql[:80]}")
    return row
