# Changelog

## Unreleased

- Added exact, reviewed Semgrep finding dispositions for evidence-backed
  `not_applicable` decisions. Findings remain visible with their original
  severity and blocking nature; malformed/wildcard dispositions block,
  unmatched entries are reported, Critical findings refuse disposition, and
  scans that depend on dispositions report `APPROVED_WITH_DISPOSITIONS`.
- Bumped report and normalized-finding schema versions to `0.2.0` for the new
  rule ID, disposition, and status-count fields.
- Pinned external-scanner subprocess text handling and Python child
  environments to UTF-8. Invalidly encoded raw JSON now becomes an explicit
  scanner execution failure instead of a Windows traceback.

## v0.2.0

- **Trifecta awareness (aligns with Drydock v0.4.0's Gate 15).** `validate-lgf` and `scan` now flag an **unmitigated lethal trifecta**: a gate-applicability entry whose `lethal_trifecta` block records all three legs (access to private data + exposure to untrusted content + an outbound channel) with no `broken_leg` and no `mitigation` becomes a High, launch-blocking finding on Gate 15. A recorded, **non-placeholder** mitigation or broken leg clears it (a lazy `TODO`/`none`/`N/A`/`tbd` does NOT silently un-block the lethal gate); partial or `unknown` legs are not flagged — the CLI validates what the project states and does not (yet) infer the legs from the codebase.
- **Fixed report version drift.** Every emitted report hardcoded `launchguardian_version: "0.1.0"` regardless of the installed package. It now tracks `__version__`; the report's JSON `schema_version` (report shape) stays independent and unchanged. Regression-tested.
- Suite: 73 tests (was 58).

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
