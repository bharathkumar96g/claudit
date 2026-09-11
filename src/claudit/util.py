from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def short_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:24]


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
