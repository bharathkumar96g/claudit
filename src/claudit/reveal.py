"""Re-read raw text from the source transcript on demand. Local only; nothing here is persisted."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

from .detect import Match, redact, scan
from .ingest import extract_segments
from .util import sha256


def reveal_segment(con: duckdb.DuckDBPyConnection, segment_id: str) -> str | None:
    """The segment's original text, or None if the transcript is missing or has changed since ingest."""
    row = con.execute(
        "SELECT e.file_path, e.line_no, s.source, s.seq, s.text_sha256"
        " FROM segments s JOIN events e ON e.event_id = s.event_id WHERE s.segment_id = ?",
        [segment_id],
    ).fetchone()
    if row is None:
        return None
    file_path, line_no, source, seq, expected_sha = row
    path = Path(file_path)
    if not path.is_file():
        return None

    raw: bytes | None = None
    with path.open("rb") as f:
        for i, line in enumerate(f, start=1):
            if i == line_no:
                raw = line
                break
    if raw is None:
        return None
    try:
        rec = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict):
        return None

    segments = extract_segments(rec)
    if seq >= len(segments) or segments[seq].source != source:
        return None
    text = segments[seq].text
    return text if sha256(text) == expected_sha else None


def redacted_window(text: str, start: int, end: int, window: int) -> str:
    """Text around [start, end) with every other detected value redacted and the target marked «…»."""
    lo, hi = max(0, start - window), min(len(text), end + window)
    piece = text[lo:hi]
    t_start, t_end = start - lo, end - lo
    others = [m for m in scan(piece) if not (m.start < t_end and t_start < m.end)]
    marked = Match("target", "", t_start, t_end, piece[t_start:t_end])
    out = piece
    for m in sorted([*others, marked], key=lambda m: m.start, reverse=True):
        replacement = f"«{m.value}»" if m is marked else f"[REDACTED:{m.category}]"
        out = f"{out[:m.start]}{replacement}{out[m.end:]}"
    return out


def redacted_text(text: str) -> str:
    return redact(text, scan(text))


def reveal_finding(con: duckdb.DuckDBPyConnection, finding_id: str, context: int = 200) -> tuple[str, str] | None:
    """(raw value, surrounding excerpt) for a finding, verified against its fingerprint."""
    row = con.execute(
        "SELECT segment_id, start_off, end_off, fingerprint FROM findings WHERE finding_id = ?", [finding_id]
    ).fetchone()
    if row is None:
        return None
    segment_id, start, end, fingerprint = row
    text = reveal_segment(con, segment_id)
    if text is None:
        return None
    value = text[start:end]
    if sha256(value) != fingerprint:
        return None
    return value, redacted_window(text, start, end, context)
