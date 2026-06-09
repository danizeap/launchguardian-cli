# LaunchGuardian CLI

LaunchGuardian CLI is the implementation companion to the LaunchGuardian Framework (LGF). It validates LGF project files and runs local, permission-bound security checks against target paths provided by the user.

Implemented commands:

```bash
launchguardian validate-lgf --target .
launchguardian scan --target .
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

`scan` runs LGF validation first, then runs the currently supported scanner integrations.

## Current Scope

LaunchGuardian currently supports local Gitleaks secret scanning only. It does not perform active web scanning, exploit testing, credential guessing, or any offensive workflow.

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

## Reports

Reports are generated under the target project by default:

```text
<target>/reports/launchguardian/
|-- launchguardian-report.md
|-- launchguardian-report.json
|-- normalized-findings.json
`-- raw/
    `-- gitleaks-results.json
```

The JSON report includes schema metadata, validation mode, LGF config validation result, scanner availability, scanner finding counts, launch status, blocked status, target path, and normalized findings. The Markdown report is the human-readable summary.

Use `--output-dir` to write reports somewhere else:

```bash
launchguardian validate-lgf --target . --output-dir reports/launchguardian
launchguardian scan --target . --output-dir reports/launchguardian
```

## Gitleaks Scanning

Run a local scan against a project you control:

```bash
launchguardian scan --target .
```

If Gitleaks is installed, LaunchGuardian runs:

- LGF validation.
- Local Gitleaks secret scanning against the target path.
- Raw Gitleaks JSON output to `reports/launchguardian/raw/gitleaks-results.json`.
- Normalized findings to `reports/launchguardian/normalized-findings.json`.
- Markdown and JSON launch reports.

If Gitleaks is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 4 — Secrets & Config Hygiene`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

Secret values are not copied into normalized findings. LaunchGuardian runs Gitleaks with redaction enabled and avoids using raw `Secret` or `Match` values when creating normalized report entries.

## Current Limitations

- Only the Gitleaks scanner is implemented.
- No active web scanning is implemented.
- No offensive tooling is included.
- `validate-lgf` only validates required LGF files and high-risk skipped gate confirmation.
- Framework mode validates template presence only; it is not a project launch decision.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m launchguardian.cli validate-lgf --target .
python -m launchguardian.cli scan --target .
```
