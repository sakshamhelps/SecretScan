"""Scanning engine. Purely local: reads files, never makes network calls."""
from __future__ import annotations
import os
from dataclasses import dataclass, asdict
from .rules import RULES, Rule, shannon_entropy, looks_like_placeholder

DEFAULT_EXCLUDE_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so",
               ".pyc", ".class", ".jar", ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".webp", ".bin"}
MAX_FILE_BYTES = 2 * 1024 * 1024
IGNORE_MARKER = "secretscan:ignore"
SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

@dataclass
class Finding:
    path: str
    line: int
    rule_id: str
    description: str
    severity: str
    preview: str  # redacted

def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]

def scan_text(text: str, path: str = "<text>", rules: list[Rule] | None = None,
              allow_placeholders: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARKER in line or len(line) > 5000:
            continue
        for rule in rules or RULES:
            for m in rule.pattern.finditer(line):
                secret = m.groupdict().get("secret") or m.group(0)
                if rule.min_entropy is not None and shannon_entropy(secret) < rule.min_entropy:
                    continue
                if not allow_placeholders and looks_like_placeholder(secret):
                    continue
                findings.append(Finding(path, lineno, rule.id, rule.description, rule.severity, redact(secret)))
    return findings

def iter_files(roots, exclude_dirs=DEFAULT_EXCLUDE_DIRS, errors=None):
    errors = errors if errors is not None else []
    for root in roots:
        if os.path.isfile(root):
            yield root; continue
        for dp, dns, fns in os.walk(root, onerror=lambda e: errors.append(f"{e.filename}: {e.strerror}")):
            dns[:] = sorted(d for d in dns if d not in exclude_dirs)
            for fn in sorted(fns):
                yield os.path.join(dp, fn)

def scan_paths(roots, exclude_dirs=DEFAULT_EXCLUDE_DIRS, min_severity="low", allow_placeholders=False):
    """Return (findings, errors, files_scanned)."""
    findings, errors, count = [], [], 0
    for p in iter_files(roots, exclude_dirs, errors):
        if os.path.splitext(p)[1].lower() in BINARY_EXTS or os.path.islink(p):
            continue
        try:
            if os.path.getsize(p) > MAX_FILE_BYTES:
                errors.append(f"{p}: skipped (larger than {MAX_FILE_BYTES // 1024 // 1024} MB)"); continue
            with open(p, "rb") as f:
                raw = f.read()
        except OSError as e:
            errors.append(f"{p}: {e.strerror}"); continue
        if b"\x00" in raw[:4096]:
            continue  # binary
        count += 1
        text = raw.decode("utf-8", errors="replace")
        findings += [f for f in scan_text(text, p, allow_placeholders=allow_placeholders)
                     if SEV_ORDER[f.severity] >= SEV_ORDER[min_severity]]
    return findings, errors, count

def to_dicts(findings): return [asdict(f) for f in findings]
