# Changelog

## v0.1.1

- Fixed double-encoded em-dashes in scanner gate names (consistent gate counting).
- Added subprocess timeouts for Gitleaks/Semgrep/Trivy; timeouts surface as scanner execution failures (exit 2).
- Added timeout regression test; version test tracks `__version__`.
- Added MIT LICENSE, PyPI metadata, and GitHub Actions trusted-publishing workflow.
- First PyPI release: `pip install launchguardian`.


## v0.1.0 - MVP

Initial LaunchGuardian CLI MVP.

Includes:

- LGF project validation for required LaunchGuardian Framework files.
- High-risk skipped gate validation for required human confirmation fields.
- Gitleaks integration for local secret scanning.
- Semgrep integration for local static code security scanning.
- Trivy integration for local dependency, filesystem, container, and IaC scanning.
- Native Frontend Exposure scanner.
- Native API Surface scanner.
- `launchguardian.yml` scanner configuration and native scanner exclusions.
- Markdown and JSON report generation.
- Normalized findings output.
- GitHub Actions workflow templates for strict and non-strict CI adoption.
- Support for calibrating against the intentionally vulnerable demo repo.

Safety boundaries:

- Local target paths only.
- No active web scanning.
- No offensive exploitation tooling.
- No third-party target scanning.
