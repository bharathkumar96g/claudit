"""Checkpointed ingest of Claude Code JSONL transcripts.

Detection runs in the ingest path, before anything is persisted, so the raw
value of a secret never reaches disk: segments are stored redacted, findings
carry a fingerprint and masked preview only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from .detect import DETECTOR_VERSION, redact, scan
from .util import sha256, short_id, utc_now


@dataclass
class ScanStats:
    files: int = 0
    lines: int = 0
    events: int = 0
    segments: int = 0
    findings: int = 0
    invalid: int = 0


def _parse_ts(value: object) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _flatten(content: object) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            else:
                parts.append(json.dumps(block, ensure_ascii=False))
        return "\n".join(parts)
    return json.dumps(content, ensure_ascii=False)


def _flatten_input(inp: object) -> str:
    """Tool inputs keep string values raw; JSON-escaping them would hide newlines from the detectors."""
    if not isinstance(inp, dict):
        return json.dumps(inp, ensure_ascii=False)
    parts = []
    for key, value in inp.items():
        rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        parts.append(f"{key}: {rendered}")
    return "\n".join(parts)


def extract_segments(rec: dict) -> list[tuple[str, str]]:
    """Text chunks the model actually saw or produced, tagged by who put them there."""
    kind = rec.get("type")
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    content = msg.get("content")
    out: list[tuple[str, str]] = []

    if kind == "user":
        if isinstance(content, str):
            out.append(("user_prompt", content))
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    out.append(("user_prompt", str(block.get("text", ""))))
                elif block.get("type") == "tool_result":
                    out.append(("tool_result", _flatten(block.get("content"))))
    elif kind == "assistant" and isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                out.append(("assistant_text", str(block.get("text", ""))))
            elif block.get("type") == "tool_use":
                out.append(("tool_input", _flatten_input(block.get("input", {}))))
    elif kind == "attachment" and rec.get("attachment") is not None:
        out.append(("attachment", json.dumps(rec["attachment"], ensure_ascii=False)))

    return [(source, text) for source, text in out if text and text.strip()]


def read_complete_lines(path: Path, offset: int) -> tuple[list[str], int]:
    """Lines appended after `offset`. A trailing partial line (writer mid-flush) waits for the next run."""
    with path.open("rb") as f:
        f.seek(offset)
        buf = f.read()
    last_nl = buf.rfind(b"\n")
    if last_nl == -1:
        return [], offset
    chunk = buf[: last_nl + 1]
    lines = chunk.decode("utf-8", errors="replace").split("\n")[:-1]
    return lines, offset + len(chunk)


def scan_file(con: duckdb.DuckDBPyConnection, path: Path, project_hint: str, stats: ScanStats) -> None:
    row = con.execute("SELECT byte_offset, line_no FROM checkpoints WHERE file_path = ?", [str(path)]).fetchone()
    offset, line_no = row if row else (0, 0)
    lines, new_offset = read_complete_lines(path, offset)
    if not lines:
        return

    now = utc_now()
    ev_rows, seg_rows, fd_rows = [], [], []
    for raw in lines:
        line_no += 1
        stats.lines += 1
        raw = raw.rstrip("\r")
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            stats.invalid += 1
            continue
        if not isinstance(rec, dict):
            stats.invalid += 1
            continue

        event_id = str(rec.get("uuid") or short_id(str(path), str(line_no)))
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        session_id = rec.get("sessionId") or rec.get("session_id")
        project = rec.get("cwd") or project_hint
        ts = _parse_ts(rec.get("timestamp"))
        ev_rows.append(
            (
                event_id, str(path), line_no, session_id, project,
                str(rec.get("type") or "unknown"), msg.get("role"), ts,
                rec.get("cwd"), rec.get("gitBranch"), msg.get("model"), now,
            )
        )

        for seq, (source, text) in enumerate(extract_segments(rec)):
            segment_id = short_id(event_id, source, str(seq))
            matches = scan(text)
            seg_rows.append(
                (segment_id, event_id, session_id, project, source, seq,
                 len(text), sha256(text), redact(text, matches), ts)
            )
            for m in matches:
                fd_rows.append(
                    (
                        short_id(segment_id, m.category, str(m.start)), segment_id, event_id,
                        session_id, project, source, m.category, m.severity, m.fingerprint, m.preview,
                        m.start, m.end, m.end - m.start, DETECTOR_VERSION, ts, now,
                    )
                )

    con.begin()
    try:
        if ev_rows:
            con.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ev_rows)
        if seg_rows:
            con.executemany("INSERT OR IGNORE INTO segments VALUES (?,?,?,?,?,?,?,?,?,?)", seg_rows)
        if fd_rows:
            con.executemany(
                "INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", fd_rows
            )
        con.execute("INSERT OR REPLACE INTO checkpoints VALUES (?,?,?,?)", [str(path), new_offset, line_no, now])
        con.commit()
    except Exception:
        con.rollback()
        raise

    stats.files += 1
    stats.events += len(ev_rows)
    stats.segments += len(seg_rows)
    stats.findings += len(fd_rows)


def scan_dir(con: duckdb.DuckDBPyConnection, root: Path, stats: ScanStats) -> None:
    for path in sorted(root.rglob("*.jsonl")):
        scan_file(con, path, project_hint=path.parent.name, stats=stats)
