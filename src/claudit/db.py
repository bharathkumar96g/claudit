from __future__ import annotations

from pathlib import Path

import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    file_path   VARCHAR PRIMARY KEY,
    byte_offset BIGINT NOT NULL,
    line_no     INTEGER NOT NULL,
    updated_at  TIMESTAMP NOT NULL
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

CREATE TABLE IF NOT EXISTS segments (
    segment_id    VARCHAR PRIMARY KEY,
    event_id      VARCHAR NOT NULL,
    session_id    VARCHAR,
    project       VARCHAR,
    source        VARCHAR NOT NULL,
    seq           INTEGER NOT NULL,
    char_len      INTEGER NOT NULL,
    text_sha256   VARCHAR NOT NULL,
    text_redacted VARCHAR NOT NULL,
    ts            TIMESTAMP
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
    finding_id    VARCHAR PRIMARY KEY,
    verdict       VARCHAR NOT NULL,
    confidence    DOUBLE,
    reason        VARCHAR,
    model         VARCHAR NOT NULL,
    prompt_tokens INTEGER,
    output_tokens INTEGER,
    duration_ms   INTEGER,
    judged_at     TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS semantic_scans (
    segment_id  VARCHAR PRIMARY KEY,
    model       VARCHAR NOT NULL,
    n_findings  INTEGER NOT NULL,
    duration_ms INTEGER,
    scanned_at  TIMESTAMP NOT NULL
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
    ts         TIMESTAMP,
    found_at   TIMESTAMP NOT NULL
);
"""

TABLES = ("semantic_findings", "semantic_scans", "judgments", "findings", "segments", "events", "checkpoints")


def connect(db_path: Path) -> duckdb.DuckDBPyConnection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path))
    for stmt in SCHEMA.split(";"):
        if stmt.strip():
            con.execute(stmt)
    return con


def truncate_all(con: duckdb.DuckDBPyConnection) -> None:
    for table in TABLES:
        con.execute(f"DELETE FROM {table}")
