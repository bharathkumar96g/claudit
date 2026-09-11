from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@dataclass(frozen=True)
class Config:
    transcripts_dir: Path
    db_path: Path


def load_config() -> Config:
    _load_dotenv(Path(".env"))
    return Config(
        transcripts_dir=Path(os.environ.get("CLAUDIT_TRANSCRIPTS_DIR", "~/.claude/projects")).expanduser(),
        db_path=Path(os.environ.get("CLAUDIT_DB_PATH", "data/claudit.duckdb")).expanduser(),
    )
