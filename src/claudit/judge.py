"""Local-model judgment layer. Talks only to a local Ollama server; nothing leaves the machine.

Two jobs the deterministic rules can't do:
- adjudicate: is a flagged value a real secret, or a placeholder / fixture / example?
- semantic scan: sensitive content with no pattern (customer data, internal architecture, proprietary logic).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

import duckdb

from .ollama import OllamaClient
from .reveal import reveal_segment
from .util import sha256, short_id, utc_now

VERDICTS = ("confirmed", "benign", "unsure")
SEMANTIC_KINDS = (
    "customer_or_employee_data",
    "credentials",
    "proprietary_code_or_logic",
    "internal_infrastructure",
    "financial",
    "legal_or_hr",
    "other",
)
SEMANTIC_SEVERITIES = ("high", "medium", "low")

ADJUDICATE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reason"],
}

SEMANTIC_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": list(SEMANTIC_KINDS)},
                    "severity": {"type": "string", "enum": list(SEMANTIC_SEVERITIES)},
                    "summary": {"type": "string"},
                },
                "required": ["kind", "severity", "summary"],
            },
        }
    },
    "required": ["findings"],
}

ADJUDICATE_SYSTEM = (
    "You review excerpts from a developer's AI coding session. One substring is marked between « and ». "
    "Decide whether it is a REAL secret, credential, or personal record that should not have been shared "
    "(verdict: confirmed); a placeholder, example, test fixture, documentation sample, throwaway local value, "
    "or otherwise non-sensitive string (verdict: benign); or genuinely unclear (verdict: unsure). "
    "Judge from context: file headers, comments, variable names, surrounding prose. "
    "Give confidence between 0 and 1. In the reason, never repeat the marked value or any part of it."
)

SEMANTIC_SYSTEM = (
    "You audit text a developer typed into an AI coding assistant. Identify information an employer would "
    "not want sent to a third-party AI service: customer or employee personal data, credentials in any form, "
    "proprietary business logic or unreleased product details, internal hostnames, IPs, or architecture, "
    "financial figures, legal or HR matters. Report only concrete sensitive content actually present. "
    "Do not report generic code, public library names, the developer's own task description, or values "
    "already shown as [REDACTED:...]. If nothing qualifies, return an empty findings list. "
    "Summaries must describe the information without repeating names, identifiers, numbers, or values."
)

SEV_ORDER_SQL = "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
WINDOW = 400
SEMANTIC_MAX_CHARS = 6000


@dataclass
class JudgeStats:
    judged: int = 0
    confirmed: int = 0
    benign: int = 0
    unsure: int = 0
    unavailable: int = 0
    prompt_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0


@dataclass
class SemanticStats:
    scanned: int = 0
    findings: int = 0
    prompt_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0


def _scrub(reason: str, value: str, preview: str) -> str:
    out = reason.replace(value, preview)
    for line in value.splitlines():
        if len(line) >= 8:
            out = out.replace(line, preview)
    return out[:500]


def _parse_verdict(content: str) -> tuple[str, float | None, str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return "unsure", None, "model returned unparseable output"
    if not isinstance(data, dict):
        return "unsure", None, "model returned unparseable output"
    verdict = data.get("verdict")
    if verdict not in VERDICTS:
        verdict = "unsure"
    try:
        confidence = min(1.0, max(0.0, float(data.get("confidence"))))
    except (TypeError, ValueError):
        confidence = None
    return verdict, confidence, str(data.get("reason", ""))


def _store_judgment(con, finding_id, verdict, confidence, reason, model, prompt_tokens, output_tokens, duration_ms):
    con.execute(
        "INSERT OR REPLACE INTO judgments VALUES (?,?,?,?,?,?,?,?,?)",
        [finding_id, verdict, confidence, reason, model, prompt_tokens, output_tokens, duration_ms, utc_now()],
    )


def adjudicate(
    con: duckdb.DuckDBPyConnection,
    client: OllamaClient,
    model: str,
    limit: int = 200,
    on_result: Callable[[str, str, str, str], None] | None = None,
) -> JudgeStats:
    rows = con.execute(
        f"SELECT f.finding_id, f.segment_id, f.category, f.preview, f.start_off, f.end_off, f.fingerprint"
        f" FROM findings f LEFT JOIN judgments j ON j.finding_id = f.finding_id"
        f" WHERE j.finding_id IS NULL ORDER BY {SEV_ORDER_SQL}, f.ts LIMIT ?",
        [limit],
    ).fetchall()

    stats = JudgeStats()
    for finding_id, segment_id, category, preview, start, end, fingerprint in rows:
        text = reveal_segment(con, segment_id)
        value = text[start:end] if text is not None else None
        if value is None or sha256(value) != fingerprint:
            reason = "source transcript missing or changed since ingest"
            _store_judgment(con, finding_id, "unavailable", None, reason, model, 0, 0, 0)
            stats.unavailable += 1
            if on_result:
                on_result(category, preview, "unavailable", reason)
            continue

        excerpt = f"{text[max(0, start - WINDOW):start]}«{value}»{text[end:end + WINDOW]}"
        messages = [
            {"role": "system", "content": ADJUDICATE_SYSTEM},
            {"role": "user", "content": f"Rule category: {category}\n\nExcerpt:\n{excerpt}"},
        ]
        result = client.chat(model, messages, schema=ADJUDICATE_SCHEMA)
        verdict, confidence, reason = _parse_verdict(result.content)
        reason = _scrub(reason, value, preview)
        _store_judgment(
            con, finding_id, verdict, confidence, reason, model,
            result.prompt_tokens, result.output_tokens, result.duration_ms,
        )

        stats.judged += 1
        setattr(stats, verdict, getattr(stats, verdict) + 1)
        stats.prompt_tokens += result.prompt_tokens
        stats.output_tokens += result.output_tokens
        stats.duration_ms += result.duration_ms
        if on_result:
            on_result(category, preview, verdict, reason)
    return stats


def _parse_semantic(content: str) -> list[tuple[str, str, str]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    items = data.get("findings") if isinstance(data, dict) else None
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind") if item.get("kind") in SEMANTIC_KINDS else "other"
        severity = item.get("severity") if item.get("severity") in SEMANTIC_SEVERITIES else "medium"
        summary = str(item.get("summary", "")).strip()[:300]
        if summary:
            out.append((kind, severity, summary))
    return out


def semantic_scan(
    con: duckdb.DuckDBPyConnection,
    client: OllamaClient,
    model: str,
    limit: int = 100,
    sources: tuple[str, ...] = ("user_prompt",),
    on_result: Callable[[str, int], None] | None = None,
) -> SemanticStats:
    placeholders = ",".join("?" * len(sources))
    rows = con.execute(
        f"SELECT s.segment_id, s.event_id, s.session_id, s.project, s.source, s.text_redacted, s.ts"
        f" FROM segments s LEFT JOIN semantic_scans sc ON sc.segment_id = s.segment_id"
        f" WHERE sc.segment_id IS NULL AND s.source IN ({placeholders}) AND s.char_len >= 40"
        f" ORDER BY s.ts LIMIT ?",
        [*sources, limit],
    ).fetchall()

    stats = SemanticStats()
    for segment_id, event_id, session_id, project, source, text, ts in rows:
        messages = [
            {"role": "system", "content": SEMANTIC_SYSTEM},
            {"role": "user", "content": text[:SEMANTIC_MAX_CHARS]},
        ]
        result = client.chat(model, messages, schema=SEMANTIC_SCHEMA)
        found = _parse_semantic(result.content)
        now = utc_now()

        con.begin()
        try:
            for i, (kind, severity, summary) in enumerate(found):
                con.execute(
                    "INSERT OR REPLACE INTO semantic_findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    [short_id(segment_id, kind, str(i)), segment_id, event_id, session_id, project,
                     source, kind, severity, summary, model, ts, now],
                )
            con.execute(
                "INSERT OR REPLACE INTO semantic_scans VALUES (?,?,?,?,?)",
                [segment_id, model, len(found), result.duration_ms, now],
            )
            con.commit()
        except Exception:
            con.rollback()
            raise

        stats.scanned += 1
        stats.findings += len(found)
        stats.prompt_tokens += result.prompt_tokens
        stats.output_tokens += result.output_tokens
        stats.duration_ms += result.duration_ms
        if on_result:
            on_result(source, len(found))
    return stats
