# Release Checklist

Use this checklist before tagging or publishing a LaunchGuardian CLI release.

## v0.1.0 MVP

- [ ] Tests pass with `python -m pytest`.
- [ ] Framework-mode smoke scan passes with `python -m launchguardian.cli scan --target . --framework-mode`.
- [ ] Vulnerable demo scan produces `BLOCKED`.
- [ ] Reports are generated under `reports/launchguardian`.
- [ ] README is updated.
- [ ] Changelog is updated.
- [ ] Version is updated in `pyproject.toml` and `launchguardian/__init__.py`.
- [ ] `launchguardian --version` prints the expected version.
- [ ] No real secrets are present in test or demo fixtures.
- [ ] No offensive scanning behavior has been added.
- [ ] No active web scanning has been added.
- [ ] GitHub remote is confirmed before commit and push.
