from __future__ import annotations

from pathlib import Path

import duckdb

from .util import one

# Everything in the database is derived from the transcripts, so a schema change simply rebuilds it.
SCHEMA_VERSION = 3  # 3: semantic findings carry piece offsets

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   VARCHAR PRIMARY KEY,
    value VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    file_path   VARCHAR PRIMARY KEY,
    byte_offset BIGINT NOT NULL,
    line_no     INTEGER NOT NULL,
    updated_at  TIMESTAMP NOT NULL,
    project     VARCHAR
);

CREATE TABLE IF NOT EXISTS events (
    event_id    VARCHAR PRIMARY KEY,
    file_path   VARCHAR NOT NULL,
    line_no     INTEGER NOT NULL,
    session_id  VARCHAR,
    project     VARCHAR,
    event_type  VARCHAR NOT NULL,
    role        VARCHAR,
    ts          TIMESTAMP,
    cwd         VARCHAR,
    git_branch  VARCHAR,
    model       VARCHAR,
    ingested_at TIMESTAMP NOT NULL
);

-- No transcript text is stored (ADR-0002): metadata only.
CREATE TABLE IF NOT EXISTS segments (
    segment_id  VARCHAR PRIMARY KEY,
    event_id    VARCHAR NOT NULL,
    session_id  VARCHAR,
    project     VARCHAR,
    source      VARCHAR NOT NULL,
    seq         INTEGER NOT NULL,
    path        VARCHAR,
    char_len    INTEGER NOT NULL,
    n_lines     INTEGER NOT NULL,
    text_sha256 VARCHAR NOT NULL,
    ts          TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id       VARCHAR PRIMARY KEY,
    segment_id       VARCHAR NOT NULL,
    event_id         VARCHAR NOT NULL,
    session_id       VARCHAR,
    project          VARCHAR,
    source           VARCHAR NOT NULL,
    category         VARCHAR NOT NULL,
    severity         VARCHAR NOT NULL,
    fingerprint      VARCHAR NOT NULL,
    preview          VARCHAR NOT NULL,
    start_off        INTEGER NOT NULL,
    end_off          INTEGER NOT NULL,
    match_len        INTEGER NOT NULL,
    detector_version INTEGER NOT NULL,
    ts               TIMESTAMP,
    detected_at      TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS judgments (
    finding_id     VARCHAR PRIMARY KEY,
    verdict        VARCHAR NOT NULL,
    confidence     DOUBLE,
    reason         VARCHAR,
    model          VARCHAR NOT NULL,
    prompt_version INTEGER NOT NULL,
    prompt_tokens  INTEGER,
    output_tokens  INTEGER,
    duration_ms    INTEGER,
    judged_at      TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS semantic_scans (
    segment_id     VARCHAR PRIMARY KEY,
    model          VARCHAR NOT NULL,
    prompt_version INTEGER NOT NULL,
    n_pieces       INTEGER NOT NULL,
    n_findings     INTEGER NOT NULL,
    duration_ms    INTEGER,
    scanned_at     TIMESTAMP NOT NULL
);

-- Operational history: one row per scan / judge / semantic / adversarial run. Survives rescans.
CREATE TABLE IF NOT EXISTS runs (
    run_id      VARCHAR PRIMARY KEY,
    kind        VARCHAR NOT NULL,
    started_at  TIMESTAMP NOT NULL,
    duration_ms INTEGER NOT NULL,
    stats       VARCHAR NOT NULL
);

-- The only user-authored data: what was done about a secret. Keyed by fingerprint so it survives rescans.
CREATE TABLE IF NOT EXISTS secret_state (
    fingerprint VARCHAR PRIMARY KEY,
    state       VARCHAR NOT NULL,
    note        VARCHAR,
    updated_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS semantic_findings (
    id         VARCHAR PRIMARY KEY,
    segment_id VARCHAR NOT NULL,
    event_id   VARCHAR NOT NULL,
    session_id VARCHAR,
    project    VARCHAR,
    source     VARCHAR NOT NULL,
    kind       VARCHAR NOT NULL,
    severity   VARCHAR NOT NULL,
    summary    VARCHAR NOT NULL,
    model      VARCHAR NOT NULL,
    piece      INTEGER NOT NULL,
    start_off  INTEGER NOT NULL,
    end_off    INTEGER NOT NULL,
    ts         TIMESTAMP,
    found_at   TIMESTAMP NOT NULL
);
"""

# secret_state is deliberately absent: it is user-authored and must survive a full rescan.
TABLES = ("semantic_findings", "semantic_scans", "judgments", "findings", "segments", "events", "checkpoints")


def _run_schema(con: duckdb.DuckDBPyConnection) -> None:
    for stmt in SCHEMA.split(";"):
        if stmt.strip():
            con.execute(stmt)
    con.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)", [str(SCHEMA_VERSION)])


def _stored_version(con: duckdb.DuckDBPyConnection) -> int | None:
    has_meta = one(con, "SELECT count(*) FROM information_schema.tables WHERE table_name = 'meta'")[0]
    if not has_meta:
        return None
    row = con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    return int(row[0]) if row else None


def connect(db_path: Path) -> duckdb.DuckDBPyConnection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path))
    existing = one(con, "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'main'")[0]
    if existing and _stored_version(con) != SCHEMA_VERSION:
        for table in (*TABLES, "meta"):
            con.execute(f"DROP TABLE IF EXISTS {table}")
    _run_schema(con)
    return con


def truncate_all(con: duckdb.DuckDBPyConnection) -> None:
    for table in TABLES:
        con.execute(f"DELETE FROM {table}")
