# SecretScan

Detect potentially exposed secrets (API keys, tokens, private keys, credentials in URLs) in source code using **transparent, readable regex rules**. Runs entirely offline: scanned code is never uploaded and files are never modified.

## Install

Python 3.10+, standard library only.

```
pip install .
# or: PYTHONPATH=src python -m secretscan --help
```

## Usage

```
secretscan scan PATH [PATH ...] [--exclude-dir NAME] [--min-severity low|medium|high]
                     [--include-placeholders] [--format text|json]
secretscan rules          # print every rule and its exact regex
```

Exit codes: `0` nothing found, `1` potential secrets found (handy for CI/pre-commit), `2` usage error.

```
$ secretscan scan . --min-severity medium
src/config.py:12: [high] aws-access-key-id: AWS access key ID -> AKIA************MNOP
```

Matched values are always **redacted** in output. Suppress a known-safe line by adding `secretscan:ignore` in a comment on that line.

## Rules

See `secretscan rules` or `src/secretscan/rules.py`. Current rules: AWS key ID / secret, GitHub tokens, GitLab tokens, Slack tokens, Stripe live keys, Google API keys, private-key blocks, JWTs, credentials in URLs, and a generic "secret-like name assigned a string literal" rule (entropy-filtered).

## Limitations and false positives (please read)

- **This is a heuristic scanner, not a guarantee.** A clean result does NOT prove a repository is free of secrets.
- **False positives:** example tokens in docs, test fixtures, hashes, and high-entropy IDs may match. Placeholder-looking values (`example`, `changeme`, `your-...`, env lookups) are skipped by default, which can itself hide real values containing those words.
- **False negatives:** custom or unusual secret formats, secrets split across lines or built at runtime, encoded/encrypted blobs, and secrets in binary files or files over 2 MB are not detected.
- Only the current working tree is scanned, **not Git history**. A secret removed from the latest commit may still be in history.
- If a real secret is found, **rotate it** - deleting it from the code is not enough.

## Tests

```
python -m unittest discover -s tests -v
```

Provider-style test keys are assembled at runtime from fake parts; the few literal fake values in the tests are marked `secretscan:ignore`. `examples/demo.py` deliberately contains demo-only values, so scanning it reports findings by design.

## Licence

MIT, Copyright (c) 2026 BYREX. No third-party dependencies.

The MIT licence covers the code only. The BYREX name and branding are not licensed for use by forks: see [TRADEMARK.md](TRADEMARK.md).
