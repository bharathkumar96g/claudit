"""Format-preserving pseudonyms for high-precision credential classes.

A pseudonym keeps the real value's prefix, length, and per-character alphabet (upper stays upper, digit
stays digit), so the same detection rule matches it and the model has no reason to alter it. It is
deterministic within a session (HMAC of the value under a per-session secret) so prompt caching and
multi-turn references keep working, and differs across sessions. The mapping lives only in memory.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
from dataclasses import dataclass, field

from ..detect import Match, scan

# Classes the guard masks: format alone identifies them, so a false positive is rare and a pseudonym is
# unambiguous. Generic passwords, entropy hits and PII stay with the audit layer (Design 03).
GUARD_CATEGORIES = frozenset({
    "anthropic_api_key", "openai_api_key", "aws_access_key_id", "aws_secret_access_key", "github_token",
    "slack_token", "google_api_key", "stripe_key", "private_key", "connection_string",
})

# Literal prefixes to preserve, longest first. The variable part after the prefix is what gets replaced.
_PREFIXES = (
    "sk-ant-api03-", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-", "github_pat_", "ghp_", "gho_", "ghu_",
    "ghs_", "ghr_", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "AIza", "AKIA", "ASIA",
    "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
)
_PK_HEADER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\n")
_PK_FOOTER = re.compile(r"\n-----END [A-Z ]*PRIVATE KEY-----")
_CONN_PASSWORD = re.compile(r"^(?P<head>[A-Za-z+.\-]+://[^\s'\"@/]+:)(?P<pw>[^\s'\"@]+)(?P<tail>@.*)$", re.S)


def _same_class_char(ch: str, byte: int) -> str:
    if ch in string.ascii_uppercase:
        return string.ascii_uppercase[byte % 26]
    if ch in string.ascii_lowercase:
        return string.ascii_lowercase[byte % 26]
    if ch in string.digits:
        return string.digits[byte % 10]
    return ch  # separators and symbols are structure, not entropy


def _substitute(variable: str, key: bytes, salt: bytes) -> str:
    """Replace every letter/digit with one of the same class, driven by an HMAC keystream."""
    out = []
    counter = 0
    stream = b""
    for ch in variable:
        if not stream:
            stream = hmac.new(key, salt + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            counter += 1
        byte, stream = stream[0], stream[1:]
        out.append(_same_class_char(ch, byte))
    return "".join(out)


def pseudonym_for(value: str, category: str, key: bytes) -> str:
    salt = hashlib.sha256(value.encode("utf-8")).digest()
    if category == "private_key":
        head = _PK_HEADER.match(value)
        foot = _PK_FOOTER.search(value)
        if head and foot and foot.start() >= head.end():
            body = value[head.end():foot.start()]
            return value[: head.end()] + _substitute(body, key, salt) + value[foot.start():]
        return value  # header-only match: nothing secret to replace
    if category == "connection_string":
        m = _CONN_PASSWORD.match(value)
        if m:
            return m["head"] + _substitute(m["pw"], key, salt) + m["tail"]
        return value
    prefix = next((p for p in _PREFIXES if value.startswith(p)), "")
    fake = prefix + _substitute(value[len(prefix):], key, salt)
    if fake == value:  # only possible for values with no letters or digits; make it differ anyway
        fake = prefix + _substitute(value[len(prefix):], key, salt + b"!")
    return fake


@dataclass
class Session:
    """One gateway process: a fresh secret, and both directions of the mapping, in memory only."""

    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    real_to_fake: dict[str, str] = field(default_factory=dict)
    fake_to_real: dict[str, str] = field(default_factory=dict)
    masked_by_category: dict[str, int] = field(default_factory=dict)

    def pseudonym(self, value: str, category: str) -> str:
        fake = self.real_to_fake.get(value)
        if fake is None:
            fake = pseudonym_for(value, category, self.key)
            if fake == value:
                return value
            self.real_to_fake[value] = fake
            self.fake_to_real[fake] = value
        return fake

    def mask_text(self, text: str) -> tuple[str, list[Match]]:
        """Replace every guard-class match with its pseudonym. Returns (masked text, matches masked)."""
        matches = [m for m in scan(text) if m.category in GUARD_CATEGORIES]
        out = text
        masked: list[Match] = []
        for m in sorted(matches, key=lambda m: m.start, reverse=True):
            fake = self.pseudonym(m.value, m.category)
            if fake == m.value:
                continue
            out = f"{out[:m.start]}{fake}{out[m.end:]}"
            masked.append(m)
            self.masked_by_category[m.category] = self.masked_by_category.get(m.category, 0) + 1
        return out, masked

    def clear(self) -> None:
        self.real_to_fake.clear()
        self.fake_to_real.clear()
        self.key = b"\x00" * 32
