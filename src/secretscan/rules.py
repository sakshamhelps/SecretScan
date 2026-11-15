"""Transparent detection rules. Every rule is a plain regex plus a description."""
from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    severity: str = "high"          # high | medium | low
    min_entropy: float | None = None  # applied to capture group "secret" if present

def _r(i, d, p, sev="high", ent=None):
    return Rule(i, d, re.compile(p), sev, ent)

RULES: list[Rule] = [
    _r("aws-access-key-id", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _r("aws-secret-access-key", "AWS secret access key assignment",
       r"(?i)aws.{0,20}(?:secret|private).{0,20}[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?", "high", 3.5),
    _r("github-token", "GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    _r("github-fine-grained", "GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    _r("gitlab-pat", "GitLab personal access token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _r("slack-token", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    _r("stripe-live-key", "Stripe live secret key", r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
    _r("google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "medium"),
    _r("private-key-block", "Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    _r("jwt", "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "medium"),
    _r("url-credentials", "Credentials embedded in URL",
       r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@'\"]+:(?P<secret>[^\s/@'\"]{3,})@[^\s/'\"]+", "high"),
    _r("generic-secret-assignment", "Hard-coded secret-like assignment",
       r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|auth[_-]?key|access[_-]?key)\b['\"]?\s*[:=]\s*['\"](?P<secret>[^'\"\s]{8,})['\"]",
       "medium", 3.0),
]

PLACEHOLDER_WORDS = ("example", "changeme", "change_me", "your", "placeholder", "dummy", "sample",
                     "xxxx", "<", "todo", "test", "fake", "redacted", "insert", "${", "{{", "process.env", "os.environ", "getenv")

def shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())

def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    return any(w in v for w in PLACEHOLDER_WORDS) or len(set(v)) <= 2
