"""Synthetic Claude Code transcripts with planted, labeled secrets.

Every value here is generated; nothing was ever real. The labels file records
fingerprints and masked previews only, so it is as safe to share as the DB.
"""

from __future__ import annotations

import base64
import json
import random
import string
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .detect import luhn_ok, mask
from .util import sha256

B62 = string.ascii_letters + string.digits
B64 = B62 + "+/"
URLSAFE = B62 + "-_"

# Split so the repo's own secret scanner doesn't flag the generator.
_PK = "PRIVATE KEY"

PROJECTS = ["payments-etl", "clickstream-lakehouse", "ml-feature-store"]
FIRST = ["Priya", "Marcus", "Elena", "Tomas", "Aisha", "Kenji", "Sofia", "Daniel"]
LAST = ["Nair", "Okafor", "Petrova", "Lindqvist", "Rahman", "Tanaka", "Moreau", "Silva"]
DOMAINS = ["northwind-freight.com", "bluefin-retail.co", "orbital-labs.io", "harbor-health.org"]

PROMPTS = [
    "Add a retry with exponential backoff to the S3 upload step in the ingestion DAG.",
    "Why is the dbt incremental model for fct_orders rebuilding from scratch every run?",
    "Write a Spark job that deduplicates click events by (user_id, event_ts) keeping the latest.",
    "Our Airflow task is failing with a Snowflake auth error, can you look at the connection config?",
    "Refactor the Kafka consumer so offsets commit only after the batch is written to Iceberg.",
    "Add Great Expectations checks for null customer_id and duplicate order_id on the silver layer.",
    "Explain the difference between merge-on-read and copy-on-write for our Iceberg tables.",
    "Generate a schema migration to add a currency column to the payments table with a default.",
    "The nightly load is 3x slower since yesterday, help me find the regression.",
    "Set up a Dagster asset that materializes daily revenue by region from the gold tables.",
    "Write unit tests for the timestamp normalization helper.",
    "Convert this pandas transform to Polars and keep the output identical.",
    "This support ticket mentions a double charge, can you trace the order through the pipeline?",
]

ASSISTANT_TEXT = [
    "I'll look at the current implementation first.",
    "The incremental model has no unique_key, so dbt falls back to a full refresh. Adding one now.",
    "Done. Offsets now commit after the Iceberg commit succeeds, so a crash mid-batch replays instead of dropping rows.",
    "I added two expectations and wired them into the silver validation step.",
    "The regression traces to a new join on an unpartitioned column; I pushed the filter before the join.",
    "Tests added and passing locally.",
    "Here's what I found in the config.",
]

DECOYS = [
    "commit 3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
    "request_id=550e8400-e29b-41d4-a716-446655440000",
    "API_KEY=your_api_key_here",
    'password = os.environ["DB_PASSWORD"]',
    "Co-Authored-By: Claude <noreply@anthropic.com>",
    '"timestamp": 1694300000000',
    "max_tokens=4096",
    "token: true",
    "order 2024-000123 total 1234.56",
]

PII = {"ssn", "credit_card", "email", "phone"}

CATEGORIES = [
    "anthropic_api_key", "openai_api_key", "aws_access_key_id", "aws_secret_access_key",
    "github_token", "slack_token", "google_api_key", "stripe_key", "private_key", "jwt",
    "connection_string", "ssn", "credit_card", "email", "phone", "generic_secret",
    "high_entropy_string",
    # covered by the imported gitleaks rules
    "sendgrid-api-token", "twilio-api-key", "npm-access-token", "gitlab-pat", "slack-webhook-url",
    "databricks-api-token", "huggingface-access-token", "digitalocean-pat", "telegram-bot-api-token",
    "mailchimp-api-key",
]
HEX = "0123456789abcdef"

# Categories where a rule-matching value can still be harmless in context; the model layer must tell them apart.
BENIGN_CAPABLE = ("github_token", "openai_api_key", "aws_access_key_id", "generic_secret")
BENIGN_RATE = 0.35


@dataclass
class Plant:
    category: str
    value: str
    embed: str
    source: str
    expected: str
    file_name: str | None = None


def _rs(rng: random.Random, n: int, alphabet: str = B62) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def _card(rng: random.Random) -> str:
    prefix = rng.choice(["4", "51", "55", "6011"])
    body = prefix + _digits(rng, 15 - len(prefix))
    num = next(body + c for c in string.digits if luhn_ok(body + c))
    return " ".join(num[i : i + 4] for i in range(0, 16, 4))


def _entropy_blob(rng: random.Random) -> str:
    chars = list(_rs(rng, 36, URLSAFE + "+") + _digits(rng, 2) + _rs(rng, 2, string.ascii_letters))
    rng.shuffle(chars)
    return "".join(chars)


def _private_key(rng: random.Random) -> str:
    body = "\n".join(_rs(rng, 64, B64) for _ in range(6))
    return f"-----BEGIN RSA {_PK}-----\n{body}\n-----END RSA {_PK}-----"


def _jwt(rng: random.Random) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_json = json.dumps({"sub": _digits(rng, 6), "iat": 1700000000 + rng.randint(0, 10**7)})
    payload = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
    return f"{header}.{payload}.{_rs(rng, 43, URLSAFE)}"


def plant(rng: random.Random, category: str) -> tuple[str, str]:
    """Return (secret value, line embedding it). The value is exactly what a detector should match."""
    if category == "anthropic_api_key":
        v = "sk-ant-api03-" + _rs(rng, 80, URLSAFE)
        return v, f"ANTHROPIC_API_KEY={v}"
    if category == "openai_api_key":
        v = "sk-proj-" + _rs(rng, 48)
        return v, f"OPENAI_API_KEY={v}"
    if category == "aws_access_key_id":
        v = "AKIA" + _rs(rng, 16, string.ascii_uppercase + string.digits)
        return v, f"AWS_ACCESS_KEY_ID={v}"
    if category == "aws_secret_access_key":
        v = _rs(rng, 40, B64)
        return v, f"aws_secret_access_key = {v}"
    if category == "github_token":
        v = "ghp_" + _rs(rng, 36)
        return v, f"GITHUB_TOKEN={v}"
    if category == "slack_token":
        v = f"xoxb-{_digits(rng, 12)}-{_digits(rng, 12)}-{_rs(rng, 24)}"
        return v, f"SLACK_BOT_TOKEN={v}"
    if category == "google_api_key":
        v = "AIza" + _rs(rng, 35, URLSAFE)
        return v, f"GOOGLE_MAPS_KEY={v}"
    if category == "stripe_key":
        v = "sk_live_" + _rs(rng, 24)
        return v, f"STRIPE_SECRET_KEY={v}"
    if category == "private_key":
        v = _private_key(rng)
        return v, v
    if category == "jwt":
        v = _jwt(rng)
        return v, f"Authorization: Bearer {v}"
    if category == "connection_string":
        v = f"postgresql://app_user:{_rs(rng, 18)}@db.internal.{rng.choice(DOMAINS)}:5432/prod"
        return v, f"DATABASE_URL={v}"
    if category == "ssn":
        v = f"{rng.randint(100, 665)}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"
        return v, f"SSN: {v}"
    if category == "credit_card":
        v = _card(rng)
        return v, f"Card on file: {v}"
    if category == "email":
        v = f"{rng.choice(FIRST).lower()}.{rng.choice(LAST).lower()}@{rng.choice(DOMAINS)}"
        return v, f"Contact: {v}"
    if category == "phone":
        v = f"({rng.randint(201, 989)}) 555-{rng.randint(100, 199):04d}"
        return v, f"Callback number: {v}"
    if category == "generic_secret":
        v = _rs(rng, 16, B62 + "!@#%^*")
        return v, f'DB_PASSWORD = "{v}"'
    if category == "high_entropy_string":
        v = _entropy_blob(rng)
        return v, f"Paste this into the webhook dashboard: {v}"
    if category == "sendgrid-api-token":
        v = f"SG.{_rs(rng, 22, URLSAFE)}.{_rs(rng, 43, URLSAFE)}"
        return v, f"SENDGRID_API_KEY={v}"
    if category == "twilio-api-key":
        v = "SK" + _rs(rng, 32, HEX)
        return v, f"TWILIO_API_KEY={v}"
    if category == "npm-access-token":
        v = "npm_" + _rs(rng, 36)
        return v, f"NPM_TOKEN={v}"
    if category == "gitlab-pat":
        v = "glpat-" + _rs(rng, 20, URLSAFE)
        return v, f"GITLAB_TOKEN={v}"
    if category == "slack-webhook-url":
        v = f"https://hooks.slack.com/services/T{_rs(rng, 8, string.ascii_uppercase + string.digits)}/B{_rs(rng, 8, string.ascii_uppercase + string.digits)}/{_rs(rng, 24)}"
        return v, f"SLACK_WEBHOOK_URL={v}"
    if category == "databricks-api-token":
        v = "dapi" + _rs(rng, 32, HEX)
        return v, f"DATABRICKS_TOKEN={v}"
    if category == "huggingface-access-token":
        v = "hf_" + _rs(rng, 34, string.ascii_letters)
        return v, f"HF_TOKEN={v}"
    if category == "digitalocean-pat":
        v = "dop_v1_" + _rs(rng, 64, HEX)
        return v, f"DIGITALOCEAN_TOKEN={v}"
    if category == "telegram-bot-api-token":
        v = f"{_digits(rng, 10)}:A{_rs(rng, 34, URLSAFE)}"
        return v, f"TELEGRAM_BOT_TOKEN={v}"
    if category == "mailchimp-api-key":
        v = f"{_rs(rng, 32, HEX)}-us{rng.randint(10, 21)}"
        return v, f"MAILCHIMP_API_KEY={v}"
    raise ValueError(category)


def benign_plant(rng: random.Random, category: str) -> tuple[str, str, str]:
    """A value the rules will flag, in a context that makes it harmless. Returns (value, embed, file name)."""
    value, _ = plant(rng, category)
    if category == "github_token":
        return value, f'# fixture value for unit tests, not a real token\nFAKE_GITHUB_TOKEN = "{value}"\n', "tests/test_auth.py"
    if category == "openai_api_key":
        return value, (
            f"Set the key in your shell, for example:\n\n    export OPENAI_API_KEY={value}\n\n"
            "The value above is a made-up example; use your own key.\n"
        ), "docs/setup.md"
    if category == "aws_access_key_id":
        return value, (
            f"# .env.example - sample values only, copy to .env and replace\nAWS_ACCESS_KEY_ID={value}\nAWS_REGION=us-east-1\n"
        ), ".env.example"
    if category == "generic_secret":
        return value, f'# throwaway credentials for the local docker test database\nTEST_DB_PASSWORD = "{value}"\n', "tests/conftest.py"
    raise ValueError(category)


def make_plant(rng: random.Random, category: str) -> Plant:
    source = rng.choices(["user_prompt", "tool_result", "tool_input"], [0.4, 0.45, 0.15])[0]
    if category in BENIGN_CAPABLE and rng.random() < BENIGN_RATE:
        value, embed, file_name = benign_plant(rng, category)
        return Plant(category, value, embed, source, "benign", file_name)
    value, embed = plant(rng, category)
    return Plant(category, value, embed, source, "confirmed")


def _file_for(rng: random.Random, p: Plant) -> tuple[str, str]:
    if p.file_name:
        return p.file_name, p.embed
    if p.category == "private_key":
        return "deploy/id_rsa", p.embed + "\n"
    if p.category in PII:
        return "support/ticket_4821.txt", (
            f"Ticket #4821\nCustomer: {rng.choice(FIRST)} {rng.choice(LAST)[0]}.\n"
            f"Issue: charge appeared twice on statement\n{p.embed}\nStatus: open\n"
        )
    return rng.choice(
        [
            (".env", f"APP_ENV=production\nLOG_LEVEL=info\n{p.embed}\nFEATURE_FLAGS=beta_exports\n"),
            ("config/settings.py", f'import os\n\nDEBUG = False\n{p.embed}\nALLOWED_HOSTS = ["api.internal"]\n'),
            ("docker-compose.yml", f"services:\n  api:\n    image: internal/api:1.4\n    environment:\n      - {p.embed}\n"),
        ]
    )


def _benign_file(rng: random.Random) -> tuple[str, str]:
    return rng.choice(
        [
            ("dags/ingest_orders.py", "from airflow import DAG\n\nwith DAG('ingest_orders', schedule='@daily') as dag:\n    pass\n"),
            ("models/fct_orders.sql", "select order_id, customer_id, amount\nfrom {{ ref('stg_orders') }}\n"),
            ("README.md", "# payments-etl\n\nNightly load from the OLTP replica into the lakehouse.\n"),
        ]
    )


def build_session(
    rng: random.Random, project: str, session_id: str, start: datetime, categories: list[str]
) -> tuple[list[dict], list[dict]]:
    cwd = f"/Users/demo/projects/{project}"
    lines: list[dict] = []
    labels: list[dict] = []
    parent: str | None = None
    ts = start

    def uid() -> str:
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))

    def emit(kind: str, message: dict | None = None, **extra: object) -> dict:
        nonlocal parent, ts
        ts += timedelta(seconds=rng.randint(2, 90))
        rec: dict = {
            "type": kind,
            "uuid": uid(),
            "parentUuid": parent,
            "sessionId": session_id,
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "cwd": cwd,
            "gitBranch": "main",
            "version": "2.1.0",
            "isSidechain": False,
            "userType": "external",
        }
        if message is not None:
            rec["message"] = message
        rec.update(extra)
        parent = rec["uuid"]
        lines.append(rec)
        return rec

    def label(p: Plant) -> None:
        labels.append(
            {
                "session_id": session_id,
                "line_no": len(lines),
                "source": p.source,
                "category": p.category,
                "expected_verdict": p.expected,
                "fingerprint": sha256(p.value),
                "preview": mask(p.value, p.category),
            }
        )

    plants = [make_plant(rng, c) for c in categories]
    n_turns = max(len(plants), rng.randint(2, 5))
    turn_of: dict[int, list[Plant]] = {i: [] for i in range(n_turns)}
    for i, p in enumerate(plants):
        turn_of[i % n_turns].append(p)

    emit("system", subtype="init", content="Claude Code session started")

    for turn in range(n_turns):
        here = turn_of[turn]
        prompt = rng.choice(PROMPTS)
        for p in here:
            if p.source == "user_prompt":
                prompt += f"\n\nHere's the relevant {'file' if p.file_name else 'config'}:\n{p.embed}"
        if rng.random() < 0.3:
            prompt += f"\n\nContext: {rng.choice(DECOYS)}"
        emit("user", {"role": "user", "content": prompt})
        for p in here:
            if p.source == "user_prompt":
                label(p)

        tool_id = "toolu_" + _rs(rng, 24)
        read_plants = [p for p in here if p.source == "tool_result"]
        write_plants = [p for p in here if p.source == "tool_input"]
        if write_plants:
            name, content = _file_for(rng, write_plants[0])
            tool_use = {"type": "tool_use", "id": tool_id, "name": "Write",
                        "input": {"file_path": f"{cwd}/{name}", "content": content}}
        else:
            name, content = _file_for(rng, read_plants[0]) if read_plants else _benign_file(rng)
            tool_use = {"type": "tool_use", "id": tool_id, "name": "Read", "input": {"file_path": f"{cwd}/{name}"}}

        emit("assistant", {"role": "assistant", "model": "claude-sonnet-5",
                           "content": [{"type": "text", "text": rng.choice(ASSISTANT_TEXT)}, tool_use]})
        for p in write_plants[:1]:
            label(p)

        if rng.random() < 0.25:
            emit("file-history-snapshot", messageId=parent, snapshot={"trackedFileBackups": {}}, isSnapshotUpdate=False)

        if write_plants:
            result = f"File written: {cwd}/{name}"
        else:
            result = content
            if rng.random() < 0.3:
                result += f"\n# last deploy: {rng.choice(DECOYS)}\n"
        emit("user", {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": result}]},
             toolUseResult={"type": "text", "file": {"filePath": f"{cwd}/{name}"}})
        for p in read_plants[:1]:
            label(p)

        emit("assistant", {"role": "assistant", "model": "claude-sonnet-5",
                           "content": [{"type": "text", "text": rng.choice(ASSISTANT_TEXT)}]})

    return lines, labels


def generate(out: Path, n_sessions: int, seed: int) -> dict:
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.rglob("*.jsonl"):
        stale.unlink()
    for d in sorted((d for d in out.rglob("*") if d.is_dir()), reverse=True):
        if not any(d.iterdir()):
            d.rmdir()
    manifest: dict = {
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sessions": [],
        "plants": [],
    }

    counts = [rng.choice([0, 1, 1, 2, 2, 3]) for _ in range(n_sessions)]
    pool = CATEGORIES[:]
    rng.shuffle(pool)
    while len(pool) < sum(counts):
        pool.append(rng.choice(CATEGORIES))
    pool = pool[: sum(counts)]

    base = datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc)
    for i, n in enumerate(counts):
        project = rng.choice(PROJECTS)
        session_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        categories, pool = pool[:n], pool[n:]
        start = base + timedelta(days=i, minutes=rng.randint(0, 600))
        lines, labels = build_session(rng, project, session_id, start, categories)

        cwd = lines[0]["cwd"]
        path = out / cwd.replace("/", "-") / f"{session_id}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for rec in lines:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        for lab in labels:
            lab.update(file=str(path), project=cwd)
        manifest["sessions"].append(session_id)
        manifest["plants"].extend(labels)

    (out / "labels.json").write_text(json.dumps(manifest, indent=2))
    return manifest
