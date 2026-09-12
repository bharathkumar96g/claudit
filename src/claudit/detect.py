"""Deterministic secret and PII detectors.

A raw matched value exists only inside a Match object in memory. Everything
persisted is derived from it: a SHA-256 fingerprint and a masked preview.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable
from dataclasses import dataclass

DETECTOR_VERSION = 3

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_PK_HEADER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def mask(value: str, category: str) -> str:
    if category == "private_key":
        header = _PK_HEADER.match(value)
        return (header.group(0) if header else "-----BEGIN PRIVATE KEY-----") + "…"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]}"


@dataclass(frozen=True)
class Match:
    category: str
    severity: str
    start: int
    end: int
    value: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()

    @property
    def preview(self) -> str:
        return mask(self.value, self.category)


@dataclass(frozen=True)
class Rule:
    category: str
    severity: str
    pattern: re.Pattern[str]
    priority: int
    group: int = 0
    validate: Callable[[str], bool] | None = None
    keywords: tuple[str, ...] = ()  # lowercase; the regex only runs if one of these occurs in the text
    source: str = "claudit"
    validate_match: Callable[[re.Match[str]], bool] | None = None  # sees the whole match, not just the secret


_PLACEHOLDER = re.compile(
    r"(?i)(your[_\-]?|example|changeme|change_me|placeholder|redacted|dummy|sample|<[^>]*>|x{4,}|\*{3,}|\.{3,})"
)
_CODE_REF = re.compile(
    r"^(?:\$|\{|os\.|process\.|env\b|ENV\b|getenv|config\.|settings\.|self\.|this\.|None$|null$|true$|false$)"
)
_HEXISH = re.compile(r"^[0-9a-fA-F\-]+$")
_UUID_FRAGMENT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-")
_EMAIL_ALLOW = ("example.com", "example.org", "example.net", "localhost", "anthropic.com", "github.com")
# Prose and markdown, never part of a real credential.
_PROSE_CHARS = "…`"


def _valid_generic(v: str) -> bool:
    if _PLACEHOLDER.search(v) or _CODE_REF.match(v) or "(" in v:
        return False
    if any(ch in v for ch in _PROSE_CHARS):
        return False
    return shannon_entropy(v) >= 2.5


def _valid_card(v: str) -> bool:
    digits = re.sub(r"[ \-]", "", v)
    if not digits.isdigit():
        return False
    if v == digits and len(digits) not in (15, 16):
        return False
    if not 13 <= len(digits) <= 19 or digits[0] not in "23456":
        return False
    return luhn_ok(digits)


def _valid_email(v: str) -> bool:
    return not v.lower().rsplit("@", 1)[1].endswith(_EMAIL_ALLOW)


def _valid_entropy(v: str) -> bool:
    if _HEXISH.match(v) or v.startswith(("~", "./")):
        return False
    # Identifiers built from UUIDs (tool names, resource ids) are high-entropy but not secrets.
    if "__" in v or _UUID_FRAGMENT.search(v):
        return False
    if not any(c.isdigit() for c in v) or not any(c.isalpha() for c in v):
        return False
    return shannon_entropy(v) >= 4.0


# Higher priority wins when spans overlap, so specific rules beat generic ones.
RULES: list[Rule] = [
    Rule(
        "private_key",
        "critical",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r"(?:[\s\S]{0,8000}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)?"
        ),
        100,
    ),
    Rule(
        "connection_string",
        "critical",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^\s'\"@/]+:[^\s'\"@]+@[^\s'\"]+"
        ),
        95,
        keywords=("://",),
    ),
    Rule(
        "aws_secret_access_key",
        "critical",
        re.compile(
            r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        92,
        group=1,
        keywords=("aws",),
    ),
    Rule(
        "aws_access_key_id", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 90,
        validate=lambda v: not v.endswith("EXAMPLE"),  # AWS documentation placeholders
        keywords=("akia", "asia"),
    ),
    Rule("anthropic_api_key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), 90, keywords=("sk-ant-",)),
    Rule("openai_api_key", "high", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), 88, keywords=("sk-",)),
    Rule(
        "github_token", "high", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"), 90,
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    ),
    Rule("slack_token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), 90, keywords=("xox",)),
    Rule("google_api_key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 90, keywords=("aiza",)),
    Rule(
        "stripe_key", "high", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"), 90,
        keywords=("_live_", "_test_"),
    ),
    Rule("jwt", "high", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 80, keywords=("eyj",)),
    Rule("ssn", "high", re.compile(r"(?<![\d\-])\d{3}-\d{2}-\d{4}(?![\d\-])"), 70),
    Rule("credit_card", "high", re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"), 60, validate=_valid_card),
    Rule(
        "generic_secret",
        "medium",
        re.compile(
            r"(?i)\b[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key)"
            r"['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})"
        ),
        50,
        group=1,
        validate=_valid_generic,
        keywords=("password", "passwd", "pwd", "secret", "token", "api", "access"),
    ),
    Rule(
        "email",
        "low",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        30,
        validate=_valid_email,
        keywords=("@",),
    ),
    Rule(
        "phone",
        "low",
        re.compile(r"(?<![\d\-])(?:\+?1[ .\-])?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?![\d\-])"),
        20,
    ),
    Rule(
        "high_entropy_string",
        "medium",
        re.compile(r"(?<![A-Za-z0-9+_\-/])[A-Za-z0-9+_\-]{32,128}={0,2}(?![A-Za-z0-9+_\-/=])"),
        10,
        validate=_valid_entropy,
    ),
]

_TRAILING_PUNCT = ";,)]}"
_QUOTES = "\"'`"
SCAN_WINDOW = 65_536
SCAN_OVERLAP = 512


def _scan_span(text: str) -> list[Match]:
    lowered = text.lower()
    candidates: list[tuple[int, int, Match]] = []
    for rule in RULES:
        if rule.keywords and not any(k in lowered for k in rule.keywords):
            continue
        for m in rule.pattern.finditer(text):
            raw = m.group(rule.group)
            if not raw:
                continue
            start = m.start(rule.group)
            # A captured value never includes the quotes around it; imported rules sometimes capture them.
            value = raw.lstrip(_QUOTES)
            start += len(raw) - len(value)
            value = value.rstrip(_QUOTES).rstrip(_TRAILING_PUNCT)
            if not value or (rule.validate and not rule.validate(value)):
                continue
            if rule.validate_match and not rule.validate_match(m):
                continue
            candidates.append(
                (rule.priority, start, Match(rule.category, rule.severity, start, start + len(value), value))
            )

    candidates.sort(key=lambda c: (-c[0], c[1]))
    accepted: list[Match] = []
    for _, _, cand in candidates:
        if any(cand.start < a.end and a.start < cand.end for a in accepted):
            continue
        accepted.append(cand)
    accepted.sort(key=lambda m: m.start)
    return accepted


def scan(text: str) -> list[Match]:
    """Large chunks are scanned in overlapping windows so one 229 KB attachment can't stall the run."""
    if len(text) <= SCAN_WINDOW:
        return _scan_span(text)
    seen: set[tuple[str, int]] = set()
    out: list[Match] = []
    pos = 0
    while pos < len(text):
        window = text[pos : pos + SCAN_WINDOW]
        for m in _scan_span(window):
            key = (m.category, pos + m.start)
            if key in seen:
                continue
            seen.add(key)
            out.append(Match(m.category, m.severity, pos + m.start, pos + m.end, m.value))
        if pos + SCAN_WINDOW >= len(text):
            break
        pos += SCAN_WINDOW - SCAN_OVERLAP
    out.sort(key=lambda m: m.start)
    return out


def redact(text: str, matches: list[Match]) -> str:
    out = text
    for m in sorted(matches, key=lambda m: m.start, reverse=True):
        out = f"{out[:m.start]}[REDACTED:{m.category}]{out[m.end:]}"
    return out


from .rules_gitleaks import load_gitleaks_rules  # noqa: E402  (needs Rule defined above)

GITLEAKS_RULES, GITLEAKS_FAILED = load_gitleaks_rules()
RULES.extend(GITLEAKS_RULES)
