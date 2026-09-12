"""Local-model judgment layer. Talks only to a local Ollama server; nothing leaves the machine.

Two jobs the deterministic rules can't do:
- adjudicate: is a flagged value a real secret, or a placeholder / fixture / example?
- semantic scan: sensitive content with no pattern (customer data, internal architecture, proprietary logic).

Routing: vendor-format credentials outside test/docs/example paths are confirmed by rule and never
sent to the model; only ambiguous categories or benign-looking paths are.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

import duckdb

from .ollama import OllamaClient
from .reveal import redacted_text, redacted_window, reveal_segment
from .util import sha256, short_id, utc_now

JUDGE_PROMPT_VERSION = 3

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

# Categories whose format alone says little about whether the value is real.
AMBIGUOUS = {"generic_secret", "high_entropy_string", "email", "phone", "ssn", "credit_card"}
BENIGN_PATH = re.compile(
    r"(?i)(?:^|/)(?:tests?|specs?|fixtures?|docs?|examples?|samples?|mocks?|__tests__)(?:/|$)"
    r"|(?:^|/)test_[^/]*$|_test\.[a-z]+$|\.(?:example|sample|template|dist)(?:$|\.)|(?:^|/)readme"
)

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
    "A pattern matcher already decided it has the format of a secret or personal record. Your job is to decide, "
    "from the surrounding text and the file path only, whether it should be treated as real.\n\n"
    "Rules:\n"
    "1. Default is confirmed. A secret pasted into a session is real unless the text explicitly says otherwise.\n"
    "2. Answer benign ONLY if there is an explicit marker in the excerpt or path that this specific value is not "
    "real or not sensitive: a comment or sentence saying fake, example, sample, dummy, placeholder, throwaway, "
    "not a real token, or for tests; a file path or header like tests/ or .env.example; a docs sentence showing an "
    "example value; or credentials clearly scoped to a local-only test database.\n"
    "3. The topic of the conversation is irrelevant. A key that appears while the developer is discussing an "
    "unrelated task is still a real key. Lack of any mention of the secret is NOT evidence it is benign.\n"
    "4. Answer unsure only when the excerpt contains conflicting markers.\n\n"
    "Other detected values in the excerpt appear as [REDACTED:category]; do not comment on them. "
    "Give confidence between 0 and 1. In the reason, cite the marker you relied on, or say there was none; "
    "never repeat the marked value or any part of it."
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
SCRUB_MIN_RUN = 8

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DIGIT_RUN = re.compile(r"\d{4,}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_\-]{8,}")


@dataclass
class JudgeStats:
    judged: int = 0
    routed: int = 0
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
    unavailable: int = 0
    prompt_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0


def needs_model(category: str, severity: str, path: str | None) -> bool:
    if category in AMBIGUOUS or severity in ("medium", "low"):
        return True
    return bool(path and BENIGN_PATH.search(path))


def _scrub(reason: str, value: str, preview: str) -> str:
    """Remove the value and any run of >= SCRUB_MIN_RUN consecutive characters of it (a password inside a URL, one line of a key)."""
    out = reason.replace(value, preview)
    i = 0
    while i + SCRUB_MIN_RUN <= len(value):
        if value[i : i + SCRUB_MIN_RUN] in out:
            j = i + SCRUB_MIN_RUN
            while j < len(value) and value[i : j + 1] in out:
                j += 1
            out = out.replace(value[i:j], preview)
            i = j
        else:
            i += 1
    return out[:500]


def _scrub_summary(summary: str, source_text: str) -> str:
    """Summaries describe; they must not carry identifiers out of the text they describe."""
    out = _EMAIL.sub("[email]", summary)
    out = _DIGIT_RUN.sub("####", out)
    for token in set(_IDENTIFIER.findall(out)):
        looks_like_identifier = any(c.isdigit() for c in token) or (token != token.lower() and token != token.upper() and token != token.capitalize())
        if looks_like_identifier and token in source_text:
            out = out.replace(token, "[redacted]")
    return out[:300]


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
        "INSERT OR REPLACE INTO judgments VALUES (?,?,?,?,?,?,?,?,?,?)",
        [finding_id, verdict, confidence, reason, model, JUDGE_PROMPT_VERSION,
         prompt_tokens, output_tokens, duration_ms, utc_now()],
    )


def adjudicate(
    con: duckdb.DuckDBPyConnection,
    client: OllamaClient,
    model: str,
    limit: int = 200,
    on_result: Callable[[str, str, str, str], None] | None = None,
) -> JudgeStats:
    rows = con.execute(
        f"SELECT f.finding_id, f.segment_id, f.category, f.severity, f.preview, f.start_off, f.end_off,"
        f" f.fingerprint, s.path"
        f" FROM findings f JOIN segments s ON s.segment_id = f.segment_id"
        f" LEFT JOIN judgments j ON j.finding_id = f.finding_id"
        f" WHERE j.finding_id IS NULL OR j.prompt_version <> ?"
        f" ORDER BY {SEV_ORDER_SQL}, f.ts LIMIT ?",
        [JUDGE_PROMPT_VERSION, limit],
    ).fetchall()

    stats = JudgeStats()
    for finding_id, segment_id, category, severity, preview, start, end, fingerprint, path in rows:
        if not needs_model(category, severity, path):
            reason = "vendor-format credential outside a test, docs, or example path; confirmed by rule, not sent to the model"
            _store_judgment(con, finding_id, "confirmed", None, reason, "rules", 0, 0, 0)
            stats.routed += 1
            stats.confirmed += 1
            if on_result:
                on_result(category, preview, "confirmed", "by rule")
            continue

        text = reveal_segment(con, segment_id)
        value = text[start:end] if text is not None else None
        if value is None or sha256(value) != fingerprint:
            reason = "source transcript missing or changed since ingest"
            _store_judgment(con, finding_id, "unavailable", None, reason, model, 0, 0, 0)
            stats.unavailable += 1
            if on_result:
                on_result(category, preview, "unavailable", reason)
            continue

        excerpt = redacted_window(text, start, end, WINDOW)
        messages = [
            {"role": "system", "content": ADJUDICATE_SYSTEM},
            {"role": "user", "content": f"Rule category: {category}\nFile: {path or 'unknown'}\n\nExcerpt:\n{excerpt}"},
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
        summary = str(item.get("summary", "")).strip()
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
        f"SELECT s.segment_id, s.event_id, s.session_id, s.project, s.source, s.path, s.ts"
        f" FROM segments s LEFT JOIN semantic_scans sc ON sc.segment_id = s.segment_id"
        f" WHERE (sc.segment_id IS NULL OR sc.prompt_version <> ?) AND s.source IN ({placeholders}) AND s.char_len >= 40"
        f" ORDER BY s.ts LIMIT ?",
        [JUDGE_PROMPT_VERSION, *sources, limit],
    ).fetchall()

    stats = SemanticStats()
    for segment_id, event_id, session_id, project, source, path, ts in rows:
        raw = reveal_segment(con, segment_id)
        now = utc_now()
        if raw is None:
            con.execute(
                "INSERT OR REPLACE INTO semantic_scans VALUES (?,?,?,?,?,?)",
                [segment_id, "unavailable", JUDGE_PROMPT_VERSION, 0, 0, now],
            )
            stats.unavailable += 1
            continue

        text = redacted_text(raw)[:SEMANTIC_MAX_CHARS]
        messages = [
            {"role": "system", "content": SEMANTIC_SYSTEM},
            {"role": "user", "content": f"File: {path or 'n/a'}\n\n{text}"},
        ]
        result = client.chat(model, messages, schema=SEMANTIC_SCHEMA)
        found = [(k, s, _scrub_summary(summary, raw)) for k, s, summary in _parse_semantic(result.content)]

        con.begin()
        try:
            for i, (kind, severity, summary) in enumerate(found):
                con.execute(
                    "INSERT OR REPLACE INTO semantic_findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    [short_id(segment_id, kind, str(i)), segment_id, event_id, session_id, project,
                     source, kind, severity, summary, model, ts, now],
                )
            con.execute(
                "INSERT OR REPLACE INTO semantic_scans VALUES (?,?,?,?,?,?)",
                [segment_id, model, JUDGE_PROMPT_VERSION, len(found), result.duration_ms, now],
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
