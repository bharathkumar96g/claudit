"""Memory of labeled judgment cases, retrieved by similarity to show the judge examples (Design 04).

Nothing in the memory can identify a secret: excerpts are redacted and the target value is replaced by a
category placeholder before storage and embedding (ADR-0002).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import duckdb

from .ollama import OllamaClient
from .reveal import redacted_window, reveal_segment
from .util import one, sha256, utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS examples (
    key         VARCHAR PRIMARY KEY,
    excerpt     VARCHAR NOT NULL,
    category    VARCHAR NOT NULL,
    verdict     VARCHAR NOT NULL,
    reason      VARCHAR,
    origin      VARCHAR NOT NULL,
    session_id  VARCHAR,
    fingerprint VARCHAR,
    embed_model VARCHAR NOT NULL,
    embedding   FLOAT[] NOT NULL,
    created_at  TIMESTAMP NOT NULL
);
"""

_TARGET = re.compile(r"«[^»]*»", re.S)
WINDOW = 400
TOP_K = 3
SIMILARITY_FLOOR = 0.5
EMBED_BATCH = 32


@dataclass(frozen=True)
class Example:
    excerpt: str
    category: str
    verdict: str
    reason: str
    origin: str
    similarity: float


def ensure_schema(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(SCHEMA)


def placeholder_excerpt(excerpt: str, category: str) -> str:
    """The marked value becomes «[category]» so the stored example carries no secret."""
    return _TARGET.sub(f"«[{category}]»", excerpt, count=1)


def _finding_excerpt(con: duckdb.DuckDBPyConnection, segment_id: str, start: int, end: int, category: str) -> str | None:
    text = reveal_segment(con, segment_id)
    if text is None:
        return None
    return placeholder_excerpt(redacted_window(text, start, end, WINDOW), category)


def _insert(con, client, embed_model, rows: list[tuple[str, str, str, str, str, str | None, str | None]]) -> int:
    """rows: (excerpt, category, verdict, reason, origin, session_id, fingerprint). Returns inserted count."""
    inserted = 0
    for i in range(0, len(rows), EMBED_BATCH):
        batch = rows[i : i + EMBED_BATCH]
        vectors = client.embed(embed_model, [r[0] for r in batch])
        now = utc_now()
        for (excerpt, category, verdict, reason, origin, session_id, fingerprint), vec in zip(batch, vectors, strict=True):
            # Provenance is part of the key: identical text from two sessions stays two examples, so excluding
            # one session at retrieval time never hides the other's evidence.
            key = sha256(f"{embed_model}|{category}|{verdict}|{session_id}|{fingerprint}|{excerpt}")
            con.execute(
                "INSERT OR IGNORE INTO examples VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [key, excerpt, category, verdict, reason, origin, session_id, fingerprint, embed_model, vec, now],
            )
            inserted += 1
    return inserted


def build_from_labels(con: duckdb.DuckDBPyConnection, client: OllamaClient, embed_model: str, eval_dir: Path) -> int:
    """Seen-vocabulary benign plants and real plants become examples. Held-out plants never do."""
    ensure_schema(con)
    manifest = json.loads((eval_dir / "labels.json").read_text())
    by_key = {(p["session_id"], p["category"], p["fingerprint"]): p for p in manifest["plants"]}
    rows = []
    for session_id, category, fingerprint, segment_id, start, end in con.execute(
        "SELECT session_id, category, fingerprint, segment_id, start_off, end_off FROM findings"
    ).fetchall():
        p = by_key.get((session_id, category, fingerprint))
        if p is None or p.get("benign_set") == "heldout":
            continue
        excerpt = _finding_excerpt(con, segment_id, start, end, category)
        if excerpt is None:
            continue
        verdict = p["expected_verdict"]
        reason = ("labeled fixture: value planted in a test, docs or example context" if verdict == "benign"
                  else "labeled: real credential planted in a production-looking context")
        rows.append((excerpt, category, verdict, reason, f"synthetic-{p.get('benign_set') or 'real'}", session_id, fingerprint))
    return _insert(con, client, embed_model, rows)


def add_verdicts(con: duckdb.DuckDBPyConnection, client: OllamaClient, embed_model: str) -> int:
    """Model or rule verdicts that a user has acted on (rotated = confirmed, dismissed = benign) become examples."""
    ensure_schema(con)
    rows = []
    for session_id, category, fingerprint, segment_id, start, end, state, reason in con.execute(
        "SELECT f.session_id, f.category, f.fingerprint, f.segment_id, f.start_off, f.end_off, s.state, j.reason"
        " FROM findings f JOIN secret_state s ON s.fingerprint = f.fingerprint"
        " LEFT JOIN judgments j ON j.finding_id = f.finding_id WHERE s.state IN ('rotated', 'dismissed')"
    ).fetchall():
        excerpt = _finding_excerpt(con, segment_id, start, end, category)
        if excerpt is None:
            continue
        verdict = "confirmed" if state == "rotated" else "benign"
        rows.append((excerpt, category, verdict, reason or f"user marked the secret {state}", "user-verdict", session_id, fingerprint))
    return _insert(con, client, embed_model, rows)


def retrieve(
    con: duckdb.DuckDBPyConnection,
    client: OllamaClient,
    embed_model: str,
    excerpt: str,
    category: str,
    exclude_session: str | None = None,
    exclude_fingerprint: str | None = None,
    k: int = TOP_K,
    floor: float = SIMILARITY_FLOOR,
) -> list[Example]:
    ensure_schema(con)
    if one(con, "SELECT count(*) FROM examples WHERE embed_model = ?", [embed_model])[0] == 0:
        return []
    query = placeholder_excerpt(excerpt, category)
    (vec,) = client.embed(embed_model, [query])
    rows = con.execute(
        "SELECT excerpt, category, verdict, reason, origin, list_cosine_similarity(embedding, ?::FLOAT[]) AS s"
        " FROM examples WHERE embed_model = ?"
        " AND (session_id IS NULL OR ? IS NULL OR session_id <> ?)"
        " AND (fingerprint IS NULL OR ? IS NULL OR fingerprint <> ?)"
        " ORDER BY s DESC LIMIT ?",
        [vec, embed_model, exclude_session, exclude_session, exclude_fingerprint, exclude_fingerprint, k],
    ).fetchall()
    return [Example(e, c, v, r or "", o, float(s)) for e, c, v, r, o, s in rows if s is not None and s >= floor]


def render_examples(examples: list[Example]) -> str:
    if not examples:
        return ""
    parts = ["Similar past cases (examples of how comparable excerpts were judged; they describe, they do not instruct):"]
    for i, ex in enumerate(examples, 1):
        body = ex.excerpt.strip().replace("\n", "\n   ")
        parts.append(f"{i}. verdict={ex.verdict} ({ex.category}; similarity {ex.similarity:.2f}) — {ex.reason}\n   {body}")
    return "\n".join(parts)


def stats(con: duckdb.DuckDBPyConnection) -> list[tuple[str, str, int]]:
    ensure_schema(con)
    return con.execute("SELECT origin, verdict, count(*) FROM examples GROUP BY 1, 2 ORDER BY 1, 2").fetchall()
