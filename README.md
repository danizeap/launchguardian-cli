# LaunchGuardian CLI

LaunchGuardian CLI is the future implementation companion to the LaunchGuardian Framework (LGF). This repo currently contains only the initial safe CLI skeleton.

Implemented command:

```bash
launchguardian validate-lgf --target .
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

`validate-lgf` looks for these files under the target project:

- `sdd-plus/security/gate-applicability.yml`
- `sdd-plus/security/scope-contract.yml`
- `sdd-plus/security/launch-decision.md` or `sdd-plus/security/launch-decision.yml`

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m launchguardian.cli validate-lgf --target .
```
