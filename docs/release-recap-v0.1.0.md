# LaunchGuardian CLI v0.1.0 Release Recap

This document captures the LaunchGuardian state as of `v0.1.0` so future chats and Codex sessions can continue without re-discovering the foundation.

Tag: `v0.1.0` at `ac33a35d26374ce8cc76823f6414e6c96891a60b`

## Repos Involved

- `sdd-plus-project-starter`
- `launchguardian-cli`
- `launchguardian-demo-vulnerable-app`

## What SDD+ Contains

The SDD+ starter repo contains the LaunchGuardian Framework foundation:

- LGF framework/specs/templates.
- Gate Applicability System.
- Project Onboarding Pack.
- LaunchGuardian CLI product spec.

The starter remains framework documentation and templates only. Scanner implementation lives in `launchguardian-cli`.

## What launchguardian-cli Contains

The CLI repo contains the v0.1.0 MVP implementation:

- `validate-lgf` command for LGF project/framework validation.
- `scan` command for LGF validation plus local scanner orchestration.
- Scanner stack for secrets, code, dependencies, frontend exposure, and API surface heuristics.
- `launchguardian.yml` config system for output directory, scanner enablement, strict scanner behavior, severity policy, and native scanner exclusions.
- Markdown, JSON, normalized findings, and raw scanner output reports.
- GitHub Actions workflow templates.
- MVP docs, CI docs, changelog, and release checklist.
- `v0.1.0` Git tag.

## Scanner Stack

- Gitleaks.
- Semgrep.
- Trivy.
- Frontend Exposure.
- API Surface.

## Current Safe-Use Boundaries

- Local-only scanning.
- No unauthorized scanning.
- No active web scanning.
- No offensive exploitation.
- Heuristic findings require human review.

## Key Commands

```bash
python -m launchguardian.cli --version
python -m launchguardian.cli validate-lgf --target .
python -m launchguardian.cli validate-lgf --target . --framework-mode
python -m launchguardian.cli scan --target .
python -m launchguardian.cli scan --target . --framework-mode
python -m launchguardian.cli scan --target . --strict-scanners
```

## Demo Validation Result

The `launchguardian-demo-vulnerable-app` repo is intentionally vulnerable and local-only. Current calibration result:

- Demo repo scan returns `BLOCKED`.
- `frontend_exposure`: 7 findings.
- `api_surface`: 10 findings.
- 9 blocking findings.

## Current Known Limitations

- External scanners must be installed locally or in CI.
- No ZAP/staging scanner yet.
- No SARIF output yet.
- No packaged PyPI release yet.
- No installer script yet.
- API scanner is heuristic, not proof of vulnerability.
- Frontend scanner is heuristic and may false-positive.

## Recommended Next Roadmap

- Dogfood GitHub Actions.
- Add SARIF output.
- Add installer/dev setup docs.
- Add sample reports from demo.
- Add GitHub Release notes.
- Later add ZAP passive staging scan.
- Later add OpenAPI/API inventory scanner.
