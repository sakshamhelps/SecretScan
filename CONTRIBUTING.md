# Contributing to SecretScan

Thanks for your interest in improving SecretScan!

## Getting started

1. Fork the repository and clone your fork.
2. Create a branch: `git checkout -b my-change`.
3. Make your change in `src/secretscan/` and add or update tests in `tests/`.
4. Run the test suite from the repository root:

   ```
   python -m unittest discover -s tests -v
   ```

5. Open a pull request describing what changed and why.

## Guidelines

- Target Python 3.10+.
- Keep dependencies to a minimum; the standard library is preferred.
- Do not add network access, telemetry or tracking.
- Every behaviour change needs a test.
- Update `CHANGELOG.md` under the "Unreleased" heading.

## Reporting bugs

Open an issue with the command you ran, the input (redacted if sensitive),
the output you expected and the output you got. For security issues see
`SECURITY.md`.

By contributing you agree that your contribution is licensed under the MIT
License used by this project.
