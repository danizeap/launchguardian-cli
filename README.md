# LaunchGuardian CLI

Current version: **v0.1.0 MVP**

LaunchGuardian CLI is the implementation companion to the LaunchGuardian Framework (LGF). It validates LGF project files and runs local, permission-bound security checks against target paths provided by the user.

## Quickstart

For a first local smoke scan against a framework, template, or tool repository:

```bash
python -m launchguardian.cli scan --target . --framework-mode
```

For a project with LGF files:

```bash
python -m launchguardian.cli scan --target .
```

For CI release gates:

```bash
python -m launchguardian.cli scan --target . --strict-scanners
```

More release and usage docs:

- [v0.1.0 release notes](docs/releases/v0.1.0.md)
- [MVP scope](docs/mvp.md)
- [CI usage](docs/ci.md)
- [Changelog](CHANGELOG.md)
- [Release checklist](RELEASE_CHECKLIST.md)

Implemented commands:

```bash
launchguardian --version
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

LaunchGuardian currently supports local Gitleaks secret scanning, local Semgrep static code security scanning, local Trivy dependency/filesystem/container/IaC scanning, a native frontend exposure scanner, and a native API surface scanner. It does not perform active web scanning, exploit testing, credential guessing, or any offensive workflow.

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
    |-- semgrep-results.json
    |-- trivy-results.json
    |-- frontend-exposure-results.json
    `-- api-surface-results.json
```

The JSON report includes schema metadata, `validation_mode`, `scan_mode`, `lgf_validation_skipped`, `strict_scanners`, LGF config validation result, scanner availability, scanner finding counts, launch status, blocked status, target path, and normalized findings. The Markdown report is the human-readable summary.

Use `--output-dir` to write reports somewhere else:

```bash
launchguardian validate-lgf --target . --output-dir reports/launchguardian
launchguardian scan --target . --output-dir reports/launchguardian
```

## Reading The Report

Start with **Launch Decision** and **Executive Summary**. If the report says `BLOCKED`, review **Top Blockers** first; those findings must be fixed, removed from launch scope, or handled through an explicit approved exception before launch.

Use **Scanner Summary** to see which scanners ran, were unavailable, failed, or were disabled by config. Use **Findings By Severity** for remediation priority and **Findings By Gate** to map work back to the LaunchGuardian Framework gates.

Each finding row includes what was detected, whether it blocks launch, where it was found, why it matters, and what to review or fix. The JSON report also includes `counts_by_severity`, `counts_by_scanner`, `counts_by_gate`, and `blocking_findings` for automation.

## Sample Reports

Sample MVP reports generated from the intentionally vulnerable demo app are available under [examples/reports/demo-vulnerable-app](examples/reports/demo-vulnerable-app/). They show a `BLOCKED` scan with expected `frontend_exposure` and `api_surface` findings, without requiring users to run the scanner first.

## CI Usage

LaunchGuardian can run in GitHub Actions before the package is published. Workflow templates live under `templates/github-actions/`:

- `templates/github-actions/launchguardian.yml` runs `launchguardian scan --target . --strict-scanners` and is intended for release-quality CI.
- `templates/github-actions/launchguardian-nonstrict.yml` runs without strict scanner mode and is intended for early adoption only.

Both workflows upload `reports/launchguardian` as a GitHub Actions artifact. See `docs/ci.md` for local repo usage, future pip package usage, framework/tool repo mode, strict scanner behavior, and `launchguardian.yml` tuning guidance.

## Project CI

This repo runs Python tests and a LaunchGuardian framework-mode scan in GitHub Actions. The dogfood scan uploads `reports/launchguardian` as an artifact and intentionally does not use strict scanner mode until external scanner installation is wired into CI.

## Local Scanning

Run a local scan against a project you control:

```bash
launchguardian scan --target .
launchguardian scan --target . --framework-mode
launchguardian scan --target . --skip-lgf-validation
launchguardian scan --target . --strict-scanners
```

LaunchGuardian runs its native frontend exposure and API surface scanners without external dependencies. If Gitleaks, Semgrep, and Trivy are installed, LaunchGuardian also runs those scanner integrations:

- LGF validation.
- Local Gitleaks secret scanning against the target path.
- Local Semgrep static code security scanning against the target path.
- Local Trivy dependency, filesystem, container, and IaC scanning against the target path.
- Native frontend exposure checks against likely frontend source and build output files.
- Native API route, auth, object authorization, injection, CSRF/session, and business-logic heuristic checks.
- Raw Gitleaks JSON output to `reports/launchguardian/raw/gitleaks-results.json`.
- Raw Semgrep JSON output to `reports/launchguardian/raw/semgrep-results.json`.
- Raw Trivy JSON output to `reports/launchguardian/raw/trivy-results.json`.
- Raw frontend exposure JSON output to `reports/launchguardian/raw/frontend-exposure-results.json`.
- Raw API surface JSON output to `reports/launchguardian/raw/api-surface-results.json`.
- Normalized findings to `reports/launchguardian/normalized-findings.json`.
- Markdown and JSON launch reports.

If Gitleaks is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 4 — Secrets & Config Hygiene`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

If Semgrep is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 3 — Code Security`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

If Trivy is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 10 — Dependency, SBOM & Supply Chain`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

Use `--strict-scanners` when missing expected external scanners should block. In strict mode, missing Gitleaks, Semgrep, or Trivy sets `blocks_launch: true` and exits with code `1`.

Secret values are not copied into normalized findings. LaunchGuardian runs Gitleaks with redaction enabled and avoids using raw `Secret` or `Match` values when creating normalized report entries.

## Scanner Configuration

Projects can add `launchguardian.yml` at the target root to control local scan behavior:

```yaml
scan:
  output_dir: reports/launchguardian
  include_tests: true
  strict_scanners: false

exclude:
  paths:
    - node_modules
    - .git
    - reports/launchguardian
  globs:
    - "**/*.min.js"
    - "**/fixtures/**"

scanners:
  gitleaks:
    enabled: true
  semgrep:
    enabled: true
  trivy:
    enabled: true
  frontend_exposure:
    enabled: true
  api_surface:
    enabled: true

severity_policy:
  critical_blocks: true
  high_blocks: true
  medium_blocks: false
  low_blocks: false

finding_dispositions:
  - source: semgrep
    rule_id: python.lang.compatibility.python36.python36-compatibility-Popen1
    status: not_applicable
    reason: "The rule targets Python versions below the supported runtime floor."
    evidence: "pyproject.toml declares requires-python >=3.11."
    approved_by: "Release owner"
    approved_on: "2026-07-25"
```

Config precedence is:

- CLI `--output-dir` overrides `scan.output_dir`.
- CLI `--strict-scanners` overrides `scan.strict_scanners: false`.
- If no `launchguardian.yml` exists, LaunchGuardian uses safe defaults and reports `config file found: false`.

Scanners may be disabled in config, but disabled scanners are shown clearly in Markdown and JSON reports. A disabled external scanner such as Gitleaks, Semgrep, or Trivy is reported as `disabled`, not `unavailable`. In `--strict-scanners` mode, disabling an external scanner creates a blocking finding unless the scanner config includes both `allow_disabled_in_strict: true` and a non-empty `reason`.

Native scanner exclusions apply to `frontend_exposure` and `api_surface`. Exclusions reduce coverage and should be reviewed carefully; they do not hide `launchguardian.yml` or required LGF files from config discovery.

`severity_policy.critical_blocks: false` is not allowed silently. LaunchGuardian emits a blocking config finding because Critical findings are canonical launch blockers.

### Reviewed Finding Dispositions

`finding_dispositions` provides a narrow, auditable alternative to hiding a
reviewed Semgrep result with an inline ignore. The current implementation
supports only:

- `source: semgrep`
- an exact `rule_id` with no wildcard characters
- `status: not_applicable`
- non-placeholder `reason`, `evidence`, and `approved_by` fields
- a valid, non-future ISO `approved_on` date

The raw Semgrep result is never modified. The normalized finding remains in
JSON and Markdown with its original severity and `blocks_launch` value, plus
the disposition record. Its status becomes `not_applicable`, so it is no
longer an *open* blocker. A scan that relies on at least one disposition
reports `APPROVED_WITH_DISPOSITIONS`, not plain `APPROVED`.

Malformed, duplicate, or wildcard dispositions create blocking configuration
findings and change no scanner result. A disposition that matches no current
finding is reported as unused and cannot match a renamed rule. Critical
findings refuse disposition and remain blocking.

The `approved_by` field is auditable project metadata, not authenticated proof
of a human identity. Release reviewers must confirm the record and its
evidence through their normal code-review or change-approval process.

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

## Trivy Scanning

Install Trivy before running dependency, filesystem, container, and IaC scans. On Windows, use the official Trivy install options such as Scoop, Chocolatey, or a downloaded release binary.

LaunchGuardian invokes Trivy locally with:

```bash
trivy fs --format json --output <raw_output_path> <target>
```

Trivy checks dependency manifests, lockfiles, filesystem contents, container-related files, and IaC/configuration files for known vulnerabilities, misconfigurations, and secret findings. LaunchGuardian maps Critical and High Trivy vulnerability findings to blocking findings, Medium and Low vulnerability findings to non-blocking review items, IaC/config misconfigurations to `Gate 11 — Infrastructure, DNS, TLS & Web Hardening`, and Trivy secret findings to Critical blocking findings under `Gate 4 — Secrets & Config Hygiene`.

Trivy findings may require human review. Dependency updates can introduce compatibility changes, so remediation should include appropriate regression testing before release.

## Frontend Exposure Scanning

LaunchGuardian includes a native frontend exposure scanner that does not require external tools. It recursively inspects likely frontend source files and build outputs such as `.html`, `.js`, `.jsx`, `.ts`, `.tsx`, `.map`, `.env*`, `vite.config.*`, `next.config.*`, `package.json`, and files under `public/`, `dist/`, `build/`, `.next/`, and `out/`.

The scanner checks for:

- Source maps committed or shipped in frontend output.
- Secret-looking public frontend environment variable names such as `NEXT_PUBLIC_SECRET`, `VITE_PRIVATE_KEY`, or `REACT_APP_TOKEN`.
- Hardcoded localhost, staging, or debug references.
- Sensitive-looking `localStorage` or `sessionStorage` usage for tokens, JWTs, passwords, secrets, or API keys.
- Private-looking files or `.env` references under public/build output directories.

Public frontend prefixes such as `NEXT_PUBLIC_`, `VITE_`, and `REACT_APP_` are intentionally exposed to browser code by their frameworks. They must never contain secrets, tokens, private keys, passwords, or client secrets. LaunchGuardian reports only the variable name, file path, line number, and safe explanation; it does not copy raw secret values into normalized findings.

## API Surface Scanning

LaunchGuardian includes a native API surface scanner that does not require external tools. It recursively inspects likely backend and API files such as `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.go`, `.java`, `.cs`, `.rb`, `.php`, and route files under `api/`, `app/api/`, `pages/api/`, `routes/`, `controllers/`, `server/`, `backend/`, `functions/`, `supabase/functions/`, `netlify/functions/`, and detectable Vercel function paths.

The scanner checks for heuristic launch-review signals:

- API routes with no nearby recognizable auth guard.
- Admin, billing, payment, invite, role, permission, or organization-management routes with no nearby role/admin check.
- Object lookups by user-controlled IDs without nearby ownership, user, org, tenant, account, or team filters.
- Raw SQL string construction near SQL keywords.
- State-changing cookie/session routes with no nearby CSRF or SameSite signal.
- Business-sensitive endpoints without an explicit nearby policy or guard comment.

API surface findings are static heuristics. They are not proof of a vulnerability, and they are not proof of safety when absent. Treat them as launch-review signals that should be confirmed by a human reviewer against the actual framework, middleware, and authorization architecture.

## Current Limitations

- Only the Gitleaks, Semgrep, Trivy, frontend exposure, and API surface scanners are implemented.
- No active web scanning is implemented.
- No offensive tooling is included.
- Semgrep findings are static analysis signals and may require review.
- Trivy findings may require review, and dependency updates may need compatibility testing.
- Frontend exposure findings may require review to distinguish intentional development-only references from production exposure.
- API surface findings are heuristic review signals, not proof of vulnerability.
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
