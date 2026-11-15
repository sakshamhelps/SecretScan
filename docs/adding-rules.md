# Adding or changing rules

Rules live in `src/secretscan/rules.py` as `Rule(id, description, compiled_regex, severity, min_entropy)`.

- Name a capture group `secret` to have placeholder and entropy checks (and redaction) apply to just that part of the match.
- Prefer anchored, provider-specific prefixes (low false positives) over generic patterns.
- Add a test in `tests/test_secretscan.py`; build fake sample values at runtime instead of committing realistic-looking secrets.
