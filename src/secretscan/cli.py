"""SecretScan CLI. Exit codes: 0 clean, 1 findings, 2 usage/runtime error."""
from __future__ import annotations
import argparse, json, os, sys
from . import __version__
from .rules import RULES
from .scanner import scan_paths, to_dicts, DEFAULT_EXCLUDE_DIRS

def build_parser():
    p = argparse.ArgumentParser(prog="secretscan",
        description="Detect potentially exposed secrets using transparent regex rules. Runs fully offline; "
                    "never uploads or modifies scanned files. Expect false positives and false negatives.")
    p.add_argument("--version", action="version", version=f"secretscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan files or directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("--exclude-dir", action="append", default=[], help="extra directory name to skip (repeatable)")
    s.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    s.add_argument("--include-placeholders", action="store_true", help="also report values that look like placeholders")
    s.add_argument("--format", choices=["text", "json"], default="text")
    sub.add_parser("rules", help="list all detection rules and their patterns")
    return p

def _main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        for r in RULES:
            ent = f"  (min entropy {r.min_entropy})" if r.min_entropy else ""
            print(f"{r.id} [{r.severity}] {r.description}{ent}\n    {r.pattern.pattern}")
        return 0
    for p in args.paths:
        if not os.path.exists(p):
            print(f"secretscan: error: path not found: {p}", file=sys.stderr); return 2
    excl = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    findings, errors, n = scan_paths(args.paths, excl, args.min_severity, args.include_placeholders)
    if args.format == "json":
        print(json.dumps({"files_scanned": n, "findings": to_dicts(findings), "errors": errors}, indent=2))
    else:
        for f in findings:
            print(f"{f.path}:{f.line}: [{f.severity}] {f.rule_id}: {f.description} -> {f.preview}")
        for e in errors:
            print(f"warning: {e}", file=sys.stderr)
        print(f"\nScanned {n} file(s); {len(findings)} potential secret(s) found.")
        if findings:
            print("Review each finding: matches may be false positives. Add 'secretscan:ignore' to a line to suppress it.")
    return 1 if findings else 0


def main(argv=None) -> int:
    """Entry point. Exits quietly if the output pipe is closed (e.g. `| head`)."""
    try:
        return _main(argv)
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
