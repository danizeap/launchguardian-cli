# LaunchGuardian CLI

LaunchGuardian CLI is the future implementation companion to the LaunchGuardian Framework (LGF). This repo currently contains only the initial safe CLI skeleton.

Implemented command:

```bash
launchguardian validate-lgf --target .
```

Framework/template repos can be validated without pretending templates are project truth:

```bash
launchguardian validate-lgf --target ../sdd-plus-project-starter --framework-mode
```

The command validates required LGF project files, checks skipped high-risk gates for required human confirmation, and writes reports to:

```text
reports/launchguardian/
|-- launchguardian-report.md
`-- launchguardian-report.json
```

## Current Scope

This skeleton does not run scanners yet. It does not perform active web scanning, exploit testing, credential guessing, or any offensive workflow.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Valid LGF config and no blocking issue. |
| 1 | Invalid LGF config or blocked launch policy. |
| 2 | Tool/scanner execution failure. Reserved for future scanner integrations. |
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
`-- launchguardian-report.json
```

The JSON report includes schema metadata, validation mode, blocked status, target path, and normalized findings. The Markdown report is the human-readable summary.

Use `--output-dir` to write reports somewhere else:

```bash
launchguardian validate-lgf --target . --output-dir reports/launchguardian
```

## Current Limitations

- No external scanners are implemented yet.
- No active web scanning is implemented.
- No offensive tooling is included.
- `validate-lgf` only validates required LGF files and high-risk skipped gate confirmation.
- Framework mode validates template presence only; it is not a project launch decision.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m launchguardian.cli validate-lgf --target .
```
