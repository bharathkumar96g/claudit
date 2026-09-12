"""Load the gitleaks community rule set (MIT, vendored in rules/gitleaks.toml) as claudit rules.

Mapping: rule id -> category; regex -> pattern (capture group 1 is the secret when the regex has
exactly one group); entropy -> validator; keywords -> prefilter; rule and global allowlists ->
validator rejections. Rules claudit already covers with its own, tuned versions are skipped.
"""

from __future__ import annotations

import re
import tomllib
import warnings
from collections.abc import Callable
from pathlib import Path

from .detect import Rule, shannon_entropy

RULES_PATH = Path(__file__).parent / "rules" / "gitleaks.toml"
SKIP = {"generic-api-key", "private-key", "jwt"}
PRIORITY = 60
_MID_FLAG = re.compile(r"(?<!^)\(\?i\)")


def _compile(pattern: str) -> re.Pattern[str] | None:
    pattern = pattern.replace(r"\z", r"\Z")  # Go end-of-text anchor
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)  # "possible nested set" on Go-style [[...]] classes
        try:
            return re.compile(pattern)
        except re.error:
            pass
        # Go allows a bare (?i) mid-pattern; Python doesn't. Drop it and apply IGNORECASE to the whole rule.
        if _MID_FLAG.search(pattern):
            try:
                return re.compile(_MID_FLAG.sub("", pattern), re.IGNORECASE)
            except re.error:
                return None
    return None


def _severity(rule_id: str) -> str:
    if rule_id.endswith("-id") or "pub" in rule_id or "public" in rule_id or "client-id" in rule_id:
        return "medium"
    return "high"


def _validator(
    entropy: float | None, allow_res: list[re.Pattern[str]], stopwords: list[str]
) -> Callable[[str], bool] | None:
    if entropy is None and not allow_res and not stopwords:
        return None
    lowered_stops = [s.lower() for s in stopwords]

    def validate(value: str) -> bool:
        if entropy is not None and shannon_entropy(value) < entropy:
            return False
        if any(r.search(value) for r in allow_res):
            return False
        v = value.lower()
        return not any(s in v for s in lowered_stops)

    return validate


def load_gitleaks_rules(path: Path = RULES_PATH) -> tuple[list[Rule], list[str]]:
    """Returns (rules, ids that could not be loaded)."""
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    global_allow = cfg.get("allowlist", {})
    global_res = [p for p in (_compile(x) for x in global_allow.get("regexes", [])) if p]
    global_stops = list(global_allow.get("stopwords", []))

    rules: list[Rule] = []
    failed: list[str] = []
    for r in cfg.get("rules", []):
        rule_id = r["id"]
        if rule_id in SKIP or "regex" not in r:
            continue
        pattern = _compile(r["regex"])
        if pattern is None:
            failed.append(rule_id)
            continue

        allow_res = list(global_res)
        stopwords = list(global_stops)
        for a in r.get("allowlists", []) or ([r["allowlist"]] if "allowlist" in r else []):
            allow_res += [p for p in (_compile(x) for x in a.get("regexes", [])) if p]
            stopwords += list(a.get("stopwords", []))

        rules.append(
            Rule(
                category=rule_id,
                severity=_severity(rule_id),
                pattern=pattern,
                priority=PRIORITY,
                group=1 if pattern.groups == 1 else int(r.get("secretGroup", 0)),
                validate=_validator(r.get("entropy"), allow_res, stopwords),
                keywords=tuple(k.lower() for k in r.get("keywords", [])),
                source="gitleaks",
            )
        )
    return rules, failed
