# LaunchGuardian CLI

LaunchGuardian CLI is the implementation companion to the LaunchGuardian Framework (LGF). It validates LGF project files and runs local, permission-bound security checks against target paths provided by the user.

Implemented commands:

```bash
launchguardian validate-lgf --target .
launchguardian validate-lgf --target . --framework-mode
launchguardian scan --target .
launchguardian scan --target . --framework-mode
launchguardian scan --target . --skip-lgf-validation
launchguardian scan --target . --strict-scanners
```

Framework/template repos can be validated without pretending templates are project truth:

```bash
launchguardian validate-lgf --target ../sdd-plus-project-starter --framework-mode
```

`validate-lgf` validates required LGF project files, checks skipped high-risk gates for required human confirmation, and writes reports to:

```text
reports/launchguardian/
|-- launchguardian-report.md
`-- launchguardian-report.json
```

`scan` runs LGF validation first by default, then runs the currently supported scanner integrations.

## Current Scope

LaunchGuardian currently supports local Gitleaks secret scanning and local Semgrep static code security scanning. It does not perform active web scanning, exploit testing, credential guessing, or any offensive workflow.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Valid LGF config and no blocking issue. |
| 1 | Invalid LGF config, detected secrets, or blocked launch policy. |
| 2 | Tool/scanner execution failure. |
| 3 | Scope, permission, or configuration error. |

## Required LGF Files

In normal project validation mode, `validate-lgf` looks for these files under the target project:

- `sdd-plus/security/gate-applicability.yml`
- `sdd-plus/security/scope-contract.yml`
- `sdd-plus/security/launch-decision.md` or `sdd-plus/security/launch-decision.yml`

Missing project LGF files mean the project is incomplete for LaunchGuardian validation. The command reports each missing file and exits with code `1`.

If the target is the SDD+ starter or another framework/template repo, use `--framework-mode`. Framework mode validates expected LaunchGuardian specs/templates and does not treat templates as project-specific launch evidence.

For `scan`, `--framework-mode` is more permissive: it treats the target as a framework, template, or tool repo, skips project-specific LGF file requirements, and still runs local scanners.

Use `--skip-lgf-validation` only when you intentionally want scanner results without LGF project records. Reports will set `lgf_validation_skipped: true` and use `SCANNED_WITHOUT_LGF` or `INCOMPLETE` instead of `APPROVED`.

## Reports

Reports are generated under the target project by default:

```text
<target>/reports/launchguardian/
|-- launchguardian-report.md
|-- launchguardian-report.json
|-- normalized-findings.json
`-- raw/
    |-- gitleaks-results.json
    `-- semgrep-results.json
```

The JSON report includes schema metadata, `validation_mode`, `scan_mode`, `lgf_validation_skipped`, `strict_scanners`, LGF config validation result, scanner availability, scanner finding counts, launch status, blocked status, target path, and normalized findings. The Markdown report is the human-readable summary.

Use `--output-dir` to write reports somewhere else:

```bash
launchguardian validate-lgf --target . --output-dir reports/launchguardian
launchguardian scan --target . --output-dir reports/launchguardian
```

## Local Scanning

Run a local scan against a project you control:

```bash
launchguardian scan --target .
launchguardian scan --target . --framework-mode
launchguardian scan --target . --skip-lgf-validation
launchguardian scan --target . --strict-scanners
```

If Gitleaks and Semgrep are installed, LaunchGuardian runs:

- LGF validation.
- Local Gitleaks secret scanning against the target path.
- Local Semgrep static code security scanning against the target path.
- Raw Gitleaks JSON output to `reports/launchguardian/raw/gitleaks-results.json`.
- Raw Semgrep JSON output to `reports/launchguardian/raw/semgrep-results.json`.
- Normalized findings to `reports/launchguardian/normalized-findings.json`.
- Markdown and JSON launch reports.

If Gitleaks is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 4 — Secrets & Config Hygiene`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

If Semgrep is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 3 — Code Security`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

Use `--strict-scanners` when missing expected scanners should block. In strict mode, missing Gitleaks or Semgrep sets `blocks_launch: true` and exits with code `1`.

Secret values are not copied into normalized findings. LaunchGuardian runs Gitleaks with redaction enabled and avoids using raw `Secret` or `Match` values when creating normalized report entries.

## Semgrep Scanning

Install Semgrep before running static code scans:

```bash
python -m pip install semgrep
```

LaunchGuardian invokes Semgrep locally with:

```bash
semgrep scan --config auto --json --output <raw_output_path> <target>
```

Semgrep checks source code for static security signals such as unsafe APIs, injection patterns, auth/session mistakes, and other rule-driven code risks. LaunchGuardian maps High/Critical Semgrep results to blocking High findings, while Medium and Low findings are tracked but do not block by default.

Semgrep findings are static analysis signals and may require human review to confirm impact, false positives, accepted risk, or remediation priority.

## Current Limitations

- Only the Gitleaks and Semgrep scanners are implemented.
- No active web scanning is implemented.
- No offensive tooling is included.
- Semgrep findings are static analysis signals and may require review.
- `validate-lgf` only validates required LGF files and high-risk skipped gate confirmation.
- `validate-lgf --framework-mode` validates template presence only; it is not a project launch decision.
- `scan --framework-mode` scans framework, template, or tool repos without requiring project-specific LGF files.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m launchguardian.cli validate-lgf --target .
python -m launchguardian.cli validate-lgf --target . --framework-mode
python -m launchguardian.cli scan --target .
python -m launchguardian.cli scan --target . --framework-mode
python -m launchguardian.cli scan --target . --skip-lgf-validation
python -m launchguardian.cli scan --target . --strict-scanners
```
