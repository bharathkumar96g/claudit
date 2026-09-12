"""The unit of action: one secret (by fingerprint) across every finding, session and source it appeared in."""

from __future__ import annotations

from datetime import datetime

import duckdb

from .util import utc_now

STATES = ("open", "rotated", "dismissed")

# Short, provider-specific guidance. No deep links: console paths change, the instruction doesn't.
ROTATION = {
    "aws_access_key_id": "AWS IAM: create a new access key for the user, switch consumers, then deactivate and delete this one.",
    "aws_secret_access_key": "AWS IAM: create a new access key for the user, switch consumers, then deactivate and delete this one.",
    "aws-access-token": "AWS IAM: create a new access key, switch consumers, then deactivate and delete this one.",
    "anthropic_api_key": "Anthropic Console: create a new API key, update consumers, then delete this key.",
    "openai_api_key": "OpenAI platform: create a new API key, update consumers, then revoke this key.",
    "github_token": "GitHub: Settings → Developer settings → tokens; regenerate or delete this token and update consumers.",
    "github-pat": "GitHub: Settings → Developer settings → tokens; regenerate or delete this token and update consumers.",
    "slack_token": "Slack: reinstall or regenerate the app token; revoke this token in the app's OAuth settings.",
    "google_api_key": "Google Cloud Console: Credentials; regenerate or delete this API key and update consumers.",
    "gcp-api-key": "Google Cloud Console: Credentials; regenerate or delete this API key and update consumers.",
    "stripe_key": "Stripe Dashboard: Developers → API keys; roll this key, update consumers.",
    "stripe-access-token": "Stripe Dashboard: Developers → API keys; roll this key, update consumers.",
    "private_key": "Generate a new key pair; deploy the new public key everywhere the old one is trusted; remove the old one.",
    "connection_string": "Change the database user's password (or create a new user), update consumers, then drop the old credential.",
    "jwt": "Invalidate the session or signing key that issued it; rotate the signing secret if it is long-lived.",
    "generic_secret": "Rotate at the system that owns it, update consumers, then revoke the old value.",
    "high_entropy_string": "Identify the owning system; if it is a credential, rotate there and revoke the old value.",
    "ssn": "Cannot be rotated. Remove it from the transcript source if possible and treat it as disclosed.",
    "credit_card": "Cannot be rotated by you. Inform the cardholder; the issuer can reissue the card.",
    "email": "Personal data; not a credential. Decide whether it should have been shared.",
    "phone": "Personal data; not a credential. Decide whether it should have been shared.",
}


def rotation_hint(category: str) -> str:
    if category in ROTATION:
        return ROTATION[category]
    provider = category.split("-")[0].replace("_", " ")
    return f"{provider}: revoke this credential in the provider's console, issue a new one, update consumers."


def list_secrets(con: duckdb.DuckDBPyConnection, state: str | None = "open", limit: int = 200) -> list[dict]:
    rows = con.execute(
        """
        WITH per_secret AS (
          SELECT f.fingerprint, f.category, f.severity, any_value(f.preview) AS preview,
                 min(f.ts) AS first_seen, max(f.ts) AS last_seen,
                 count(*) AS findings, count(DISTINCT f.session_id) AS sessions,
                 list_distinct(list(f.source)) AS sources, list_distinct(list(f.project)) AS projects,
                 count(*) FILTER (WHERE j.verdict = 'confirmed') AS confirmed,
                 count(*) FILTER (WHERE j.verdict = 'benign') AS benign,
                 count(*) FILTER (WHERE j.verdict = 'unsure') AS unsure,
                 count(*) FILTER (WHERE j.finding_id IS NULL) AS unjudged
          FROM findings f LEFT JOIN judgments j ON j.finding_id = f.finding_id
          GROUP BY f.fingerprint, f.category, f.severity)
        SELECT p.*, coalesce(s.state, 'open') AS state, s.note, s.updated_at
        FROM per_secret p LEFT JOIN secret_state s ON s.fingerprint = p.fingerprint
        WHERE ? = 'all' OR coalesce(s.state, 'open') = ?
        ORDER BY CASE p.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 (p.confirmed > 0) DESC, (p.benign > 0 AND p.confirmed = 0) ASC, p.sessions DESC, p.last_seen DESC
        LIMIT ?
        """,
        [state or "all", state or "all", limit],
    ).fetchall()
    cols = ["fingerprint", "category", "severity", "preview", "first_seen", "last_seen", "findings", "sessions",
            "sources", "projects", "confirmed", "benign", "unsure", "unjudged", "state", "note", "updated_at"]
    out = []
    for r in rows:
        d = dict(zip(cols, r, strict=True))
        for k in ("first_seen", "last_seen", "updated_at"):
            d[k] = d[k].isoformat() if isinstance(d[k], datetime) else None
        d["verdict"] = "confirmed" if d["confirmed"] else "benign" if d["benign"] else "unsure" if d["unsure"] else "unjudged"
        d["rotation"] = rotation_hint(d["category"])
        out.append(d)
    return out


def set_state(con: duckdb.DuckDBPyConnection, fingerprint_prefix: str, state: str, note: str | None = None) -> str:
    """Set the state for the one secret whose fingerprint starts with the prefix. Returns the full fingerprint."""
    if state not in STATES:
        raise ValueError(f"state must be one of {STATES}")
    matches = con.execute(
        "SELECT DISTINCT fingerprint FROM findings WHERE fingerprint LIKE ?", [fingerprint_prefix + "%"]
    ).fetchall()
    if len(matches) != 1:
        raise LookupError(f"{len(matches)} secrets match fingerprint prefix {fingerprint_prefix!r}; need exactly one")
    fingerprint = matches[0][0]
    con.execute("INSERT OR REPLACE INTO secret_state VALUES (?,?,?,?)", [fingerprint, state, note, utc_now()])
    return fingerprint
