# LaunchGuardian CI Usage

LaunchGuardian can run in GitHub Actions before the package is published. Copy one of the workflow templates from `templates/github-actions/` into a project as `.github/workflows/launchguardian.yml`.

Use the strict workflow for release-quality CI:

```text
templates/github-actions/launchguardian.yml
```

Use the non-strict workflow only for early adoption:

```text
templates/github-actions/launchguardian-nonstrict.yml
```

## Local Repo Usage

When the workflow runs inside this implementation repo, install LaunchGuardian from the checked-out source:

```bash
python -m pip install -e .
launchguardian scan --target . --framework-mode
```

For another project before package publishing, install from a pinned GitHub URL:

```bash
python -m pip install "git+https://github.com/danizeap/launchguardian-cli.git@main"
launchguardian scan --target . --strict-scanners
```

Prefer pinning to a tag or commit when using CI as a release gate.

## Future Pip Package Usage

After LaunchGuardian is published, replace the GitHub install command with:

```bash
python -m pip install launchguardian
```

Package publishing is intentionally out of scope for the current CLI.

## Copying The Workflow

1. Copy `templates/github-actions/launchguardian.yml` into the target project as `.github/workflows/launchguardian.yml`.
2. Confirm the target project has LGF project files under `sdd-plus/security/`.
3. Add or review `launchguardian.yml` at the project root for output directory, scanner enablement, and native scanner exclusions.
4. Add approved installation steps for Gitleaks, Semgrep, and Trivy if strict scanner mode should be enforced.
5. Open a pull request and inspect the uploaded `launchguardian-reports` artifact.

Framework, template, or tool repos can use framework mode:

```bash
launchguardian scan --target . --framework-mode
```

This avoids requiring project-specific LGF launch files while still running local scanners.

## Strict Scanner Mode

CI should normally use:

```bash
launchguardian scan --target . --strict-scanners
```

Strict mode makes missing expected external scanners blocking. Today that means Gitleaks, Semgrep, and Trivy must be installed or explicitly disabled with a documented strict-mode allowance in `launchguardian.yml`.

Strict mode is recommended for CI because a green build should not silently skip secret, code, or dependency scanning.

## Report Artifacts

The workflow uploads `reports/launchguardian` as the `launchguardian-reports` artifact. The directory includes:

```text
reports/launchguardian/
|-- launchguardian-report.md
|-- launchguardian-report.json
|-- normalized-findings.json
`-- raw/
```

The Markdown report is for humans. The JSON report and normalized findings file are stable inputs for later CI annotations, dashboards, or release-gate automation.

## Tuning With launchguardian.yml

Use `launchguardian.yml` to tune scan behavior without hiding important checks silently:

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
```

Exclusions currently apply to native scanners: `frontend_exposure` and `api_surface`. Exclusions reduce coverage and should be reviewed like code changes.

Disabled scanners are reported as disabled. In strict mode, disabling Gitleaks, Semgrep, or Trivy blocks unless the config includes `allow_disabled_in_strict: true` and a non-empty `reason`.
