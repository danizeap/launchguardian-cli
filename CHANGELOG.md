# Changelog

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
