"""Checkpointed ingest of Claude Code JSONL transcripts.

Detection runs in the ingest path and only metadata is persisted (ADR-0002): segments carry
length, hash, source and file path; findings carry a fingerprint and a masked preview. No
transcript text is written to the database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from .detect import DETECTOR_VERSION, scan
from .util import sha256, short_id, utc_now


@dataclass
class ScanStats:
    files: int = 0
    lines: int = 0
    events: int = 0
    segments: int = 0
    findings: int = 0
    invalid: int = 0
    duplicates: int = 0
    reused: int = 0


@dataclass(frozen=True)
class Segment:
    source: str
    text: str
    path: str | None = None


REUSE_MIN_CHARS = 512
_FINDING_COLS = "category, severity, fingerprint, preview, start_off, end_off, match_len"


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


def _input_path(inp: object) -> str | None:
    if not isinstance(inp, dict):
        return None
    for key in ("file_path", "path", "notebook_path"):
        if isinstance(inp.get(key), str):
            return inp[key]
    return None


def _result_path(rec: dict) -> str | None:
    tur = rec.get("toolUseResult")
    if isinstance(tur, dict):
        file = tur.get("file")
        if isinstance(file, dict) and isinstance(file.get("filePath"), str):
            return file["filePath"]
        if isinstance(tur.get("filePath"), str):
            return tur["filePath"]
    return None


def extract_segments(rec: dict) -> list[Segment]:
    """Text chunks the model saw or produced, tagged by who put them there and which file they came from."""
    kind = rec.get("type")
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    content = msg.get("content")
    out: list[Segment] = []

    if kind == "user":
        if isinstance(content, str):
            out.append(Segment("user_prompt", content))
        elif isinstance(content, list):
            result_path = _result_path(rec)
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    out.append(Segment("user_prompt", str(block.get("text", ""))))
                elif block.get("type") == "tool_result":
                    out.append(Segment("tool_result", _flatten(block.get("content")), result_path))
    elif kind == "assistant" and isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                out.append(Segment("assistant_text", str(block.get("text", ""))))
            elif block.get("type") == "thinking":
                out.append(Segment("assistant_thinking", str(block.get("thinking", ""))))
            elif block.get("type") == "tool_use":
                inp = block.get("input", {})
                out.append(Segment("tool_input", _flatten_input(inp), _input_path(inp)))
    elif kind == "attachment" and rec.get("attachment") is not None:
        out.append(Segment("attachment", json.dumps(rec["attachment"], ensure_ascii=False)))

    return [s for s in out if s.text and s.text.strip()]


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


def _parse_records(lines: list[str], start_line: int, stats: ScanStats) -> list[tuple[int, dict]]:
    out = []
    line_no = start_line
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
        out.append((line_no, rec))
    return out


def _reusable(con: duckdb.DuckDBPyConnection, sha: str, cache: dict) -> list[tuple] | None:
    """Finding tuples of an identical chunk already scanned with the current rules, if any."""
    if sha in cache:
        return cache[sha]
    row = con.execute("SELECT segment_id FROM segments WHERE text_sha256 = ? LIMIT 1", [sha]).fetchone()
    if row is None:
        return None
    rows = con.execute(
        f"SELECT {_FINDING_COLS}, detector_version FROM findings WHERE segment_id = ?", [row[0]]
    ).fetchall()
    if any(r[-1] != DETECTOR_VERSION for r in rows):
        return None
    found = [r[:-1] for r in rows]
    cache[sha] = found
    return found


def scan_file(con: duckdb.DuckDBPyConnection, path: Path, project_hint: str, stats: ScanStats) -> None:
    row = con.execute(
        "SELECT byte_offset, line_no, project FROM checkpoints WHERE file_path = ?", [str(path)]
    ).fetchone()
    offset, line_no, known_project = row if row else (0, 0, None)
    lines, new_offset = read_complete_lines(path, offset)
    if not lines:
        return

    records = _parse_records(lines, line_no, stats)
    line_no += len(lines)

    # A resumed session copies earlier history into its new file; those events are already stored,
    # so skip them before extracting and scanning anything.
    ids = [str(rec["uuid"]) for _, rec in records if rec.get("uuid")]
    known: set[str] = set()
    for i in range(0, len(ids), 5000):
        known.update(
            r[0] for r in con.execute(
                "SELECT event_id FROM events WHERE list_contains(?, event_id)", [ids[i : i + 5000]]
            ).fetchall()
        )
    if known:
        stats.duplicates += len(known)
        records = [(n, rec) for n, rec in records if str(rec.get("uuid") or "") not in known]

    # One file is one session; the project is the directory the session was launched in.
    # cwd can change mid-session, so it is resolved once per file and remembered in the checkpoint.
    file_session = path.stem
    project = known_project or next((r.get("cwd") for _, r in records if r.get("cwd")), None) or project_hint

    now = utc_now()
    ev_rows, seg_rows, fd_rows = [], [], []
    reuse_cache: dict = {}
    for line_no_of, rec in records:
        event_id = str(rec.get("uuid") or short_id(str(path), str(line_no_of)))
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        session_id = rec.get("sessionId") or rec.get("session_id") or file_session
        ts = _parse_ts(rec.get("timestamp"))
        ev_rows.append(
            (
                event_id, str(path), line_no_of, session_id, project,
                str(rec.get("type") or "unknown"), msg.get("role"), ts,
                rec.get("cwd"), rec.get("gitBranch"), msg.get("model"), now,
            )
        )

        for seq, seg in enumerate(extract_segments(rec)):
            segment_id = short_id(event_id, seg.source, str(seq))
            sha = sha256(seg.text)
            found = _reusable(con, sha, reuse_cache) if len(seg.text) >= REUSE_MIN_CHARS else None
            if found is not None:
                stats.reused += 1
            else:
                matches = scan(seg.text)
                found = [(m.category, m.severity, m.fingerprint, m.preview, m.start, m.end, m.end - m.start) for m in matches]
                if len(seg.text) >= REUSE_MIN_CHARS:
                    reuse_cache[sha] = found
            seg_rows.append(
                (segment_id, event_id, session_id, project, seg.source, seq, seg.path,
                 len(seg.text), seg.text.count("\n") + 1, sha, ts)
            )
            for category, severity, fingerprint, preview, start, end, match_len in found:
                fd_rows.append(
                    (
                        short_id(segment_id, category, str(start)), segment_id, event_id,
                        session_id, project, seg.source, category, severity, fingerprint, preview,
                        start, end, match_len, DETECTOR_VERSION, ts, now,
                    )
                )

    def counts() -> tuple[int, int, int]:
        return con.execute(
            "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM segments), (SELECT count(*) FROM findings)"
        ).fetchone()

    con.begin()
    try:
        before = counts()
        if ev_rows:
            con.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ev_rows)
        if seg_rows:
            con.executemany("INSERT OR IGNORE INTO segments VALUES (?,?,?,?,?,?,?,?,?,?,?)", seg_rows)
        if fd_rows:
            con.executemany(
                "INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", fd_rows
            )
        con.execute(
            "INSERT OR REPLACE INTO checkpoints VALUES (?,?,?,?,?)", [str(path), new_offset, line_no, now, project]
        )
        after = counts()
        con.commit()
    except Exception:
        con.rollback()
        raise

    stats.files += 1
    stats.events += after[0] - before[0]
    stats.segments += after[1] - before[1]
    stats.findings += after[2] - before[2]
    stats.duplicates += len(ev_rows) - (after[0] - before[0])  # same-file repeats, if any


def scan_dir(con: duckdb.DuckDBPyConnection, root: Path, stats: ScanStats) -> None:
    # Oldest file first: a resumed session copies earlier history into its new file, and a message
    # seen twice is attributed to the session it first appeared in.
    for path in sorted(root.rglob("*.jsonl"), key=lambda p: (p.stat().st_mtime, str(p))):
        scan_file(con, path, project_hint=path.parent.name, stats=stats)
