# LaunchGuardian Report

## Launch Decision

**BLOCKED**

Launch is blocked by **9** open blocking finding(s). Fix the issue, remove the affected feature from scope, or document an approved exceptional override before launch.

## Executive Summary

- Target: `<demo-repo>`
- Mode: `project`
- Validation mode: `project`
- Scan mode: `local`
- Generated at: `2026-06-09T16:53:10.532074Z`
- LGF validation status: **valid**
- Strict scanners: **false**
- Total findings: **20**
- Scanner findings: **17**
- Blocking findings: **9**
- Severity counts: **critical**: 1, **high**: 8, **medium**: 9, **low**: 2, **info**: 0

## Scanner Summary

| Scanner | Status | Findings | Blocking Findings |
| --- | --- | ---: | ---: |
| api_surface | ran | 10 | 7 |
| frontend_exposure | ran | 7 | 2 |
| gitleaks | unavailable | 0 | 0 |
| semgrep | unavailable | 0 | 0 |
| trivy | unavailable | 0 | 0 |

## Top Blockers

| Severity | Blocks | Source | Gate | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| critical | yes | frontend_exposure | Gate 4 â€” Secrets & Config Hygiene | .env.local:1 | Frontend-exposed secret-like environment variable | Frontend public environment variables are bundled for browser access and must not contain secrets. | Move the secret to server-side configuration and expose only non-sensitive public values to frontend code. |
| high | yes | frontend_exposure | Gate 8 â€” Auth, Sessions & CSRF | public\app.js:2 | Sensitive-looking browser storage usage | Sensitive values in localStorage or sessionStorage can be exposed to browser-side script access. | Use safer session handling patterns and avoid storing sensitive credentials in browser storage. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:6 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:11 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:21 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:27 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:28 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |
| high | yes | api_surface | Gate 7 â€” Injection & Input Safety | server\routes\demo-routes.js:28 | Raw SQL string construction detected | Constructing SQL with dynamic strings can introduce injection risk. | Use parameterized queries or ORM query builders with bound values. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:42 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |

## Recommended Next Actions

1. Resolve or explicitly remove from launch scope the **9** open blocking finding(s).
2. Restore scanner coverage for: `gitleaks`, `semgrep`, `trivy`.
3. Re-run `launchguardian scan --target .` after remediation and attach the updated report.

## Findings By Severity

### Critical (1)

| Severity | Blocks | Source | Gate | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| critical | yes | frontend_exposure | Gate 4 â€” Secrets & Config Hygiene | .env.local:1 | Frontend-exposed secret-like environment variable | Frontend public environment variables are bundled for browser access and must not contain secrets. | Move the secret to server-side configuration and expose only non-sensitive public values to frontend code. |

### High (8)

| Severity | Blocks | Source | Gate | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| high | yes | frontend_exposure | Gate 8 â€” Auth, Sessions & CSRF | public\app.js:2 | Sensitive-looking browser storage usage | Sensitive values in localStorage or sessionStorage can be exposed to browser-side script access. | Use safer session handling patterns and avoid storing sensitive credentials in browser storage. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:6 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:11 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:21 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:27 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:28 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |
| high | yes | api_surface | Gate 7 â€” Injection & Input Safety | server\routes\demo-routes.js:28 | Raw SQL string construction detected | Constructing SQL with dynamic strings can introduce injection risk. | Use parameterized queries or ORM query builders with bound values. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:42 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |

### Medium (9)

| Severity | Blocks | Source | Gate | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| medium | no | gitleaks | Gate 4 â€” Secrets & Config Hygiene | n/a | Gitleaks scanner unavailable | Secrets may exist in the target repository without being detected by this local scan. | Install Gitleaks and rerun `launchguardian scan --target .` before relying on scan results. |
| medium | no | semgrep | Gate 3 â€” Code Security | n/a | Semgrep scanner unavailable | Code security issues may exist in the target repository without being detected by this local scan. | Install Semgrep and rerun `launchguardian scan --target .` before relying on scan results. |
| medium | no | trivy | Gate 10 â€” Dependency, SBOM & Supply Chain | n/a | Trivy scanner unavailable | Dependency, container, filesystem, or infrastructure configuration issues may exist without being detected by this local scan. | Install Trivy and rerun `launchguardian scan --target .` before relying on scan results. |
| medium | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js:5 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js:11 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js.map | Frontend source map present | Source maps can expose original source structure and implementation details in shipped frontend artifacts. | Confirm source maps are intended for the target environment, or exclude them from production artifacts. |
| medium | no | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:21 | API route has no obvious auth guard | Unauthenticated API routes can expose data or actions if they are intended to be protected. | Confirm the route is public, or add/verify authentication middleware or route-level auth checks. |
| medium | no | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:27 | API route has no obvious auth guard | Unauthenticated API routes can expose data or actions if they are intended to be protected. | Confirm the route is public, or add/verify authentication middleware or route-level auth checks. |
| medium | no | api_surface | Gate 8 â€” Auth, Sessions & CSRF | server\routes\demo-routes.js:33 | State-changing session route lacks obvious CSRF signal | Cookie-backed state changes without CSRF protections may be exposed to cross-site request risks. | Confirm CSRF or SameSite protections exist for cookie-backed state-changing routes. |

### Low (2)

| Severity | Blocks | Source | Gate | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| low | no | frontend_exposure | Gate 5 â€” Frontend Exposure | server.js:13 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| low | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js:4 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |


## Findings By Gate

### Gate 3 â€” Code Security (1)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| medium | no | semgrep | n/a | Semgrep scanner unavailable | Code security issues may exist in the target repository without being detected by this local scan. | Install Semgrep and rerun `launchguardian scan --target .` before relying on scan results. |

### Gate 4 â€” Secrets & Config Hygiene (2)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| medium | no | gitleaks | n/a | Gitleaks scanner unavailable | Secrets may exist in the target repository without being detected by this local scan. | Install Gitleaks and rerun `launchguardian scan --target .` before relying on scan results. |
| critical | yes | frontend_exposure | .env.local:1 | Frontend-exposed secret-like environment variable | Frontend public environment variables are bundled for browser access and must not contain secrets. | Move the secret to server-side configuration and expose only non-sensitive public values to frontend code. |

### Gate 5 â€” Frontend Exposure (5)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| low | no | frontend_exposure | server.js:13 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| low | no | frontend_exposure | public\app.js:4 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | public\app.js:5 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | public\app.js:11 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | public\app.js.map | Frontend source map present | Source maps can expose original source structure and implementation details in shipped frontend artifacts. | Confirm source maps are intended for the target environment, or exclude them from production artifacts. |

### Gate 6 â€” API Auth & Object Authorization (8)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| high | yes | api_surface | server\routes\demo-routes.js:6 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | server\routes\demo-routes.js:11 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| medium | no | api_surface | server\routes\demo-routes.js:21 | API route has no obvious auth guard | Unauthenticated API routes can expose data or actions if they are intended to be protected. | Confirm the route is public, or add/verify authentication middleware or route-level auth checks. |
| high | yes | api_surface | server\routes\demo-routes.js:21 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| medium | no | api_surface | server\routes\demo-routes.js:27 | API route has no obvious auth guard | Unauthenticated API routes can expose data or actions if they are intended to be protected. | Confirm the route is public, or add/verify authentication middleware or route-level auth checks. |
| high | yes | api_surface | server\routes\demo-routes.js:27 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | server\routes\demo-routes.js:28 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |
| high | yes | api_surface | server\routes\demo-routes.js:42 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |

### Gate 7 â€” Injection & Input Safety (1)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| high | yes | api_surface | server\routes\demo-routes.js:28 | Raw SQL string construction detected | Constructing SQL with dynamic strings can introduce injection risk. | Use parameterized queries or ORM query builders with bound values. |

### Gate 8 â€” Auth, Sessions & CSRF (2)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| high | yes | frontend_exposure | public\app.js:2 | Sensitive-looking browser storage usage | Sensitive values in localStorage or sessionStorage can be exposed to browser-side script access. | Use safer session handling patterns and avoid storing sensitive credentials in browser storage. |
| medium | no | api_surface | server\routes\demo-routes.js:33 | State-changing session route lacks obvious CSRF signal | Cookie-backed state changes without CSRF protections may be exposed to cross-site request risks. | Confirm CSRF or SameSite protections exist for cookie-backed state-changing routes. |

### Gate 10 â€” Dependency, SBOM & Supply Chain (1)

| Severity | Blocks | Source | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- |
| medium | no | trivy | n/a | Trivy scanner unavailable | Dependency, container, filesystem, or infrastructure configuration issues may exist without being detected by this local scan. | Install Trivy and rerun `launchguardian scan --target .` before relying on scan results. |


## Configuration

- Config file found: **true**
- Config file: `<demo-repo>\launchguardian.yml`
- Configured output dir: `reports\launchguardian`
- Effective output dir: `<demo-repo>\reports\launchguardian`
- Disabled scanners: `none`
- Active exclusions: `paths=node_modules, .git, reports/launchguardian; globs=**/*.min.js, **/fixtures/**`
- Severity policy: `critical_blocks: true`, `high_blocks: true`, `medium_blocks: false`, `low_blocks: false`
- Config warnings/blockers: **0**

## All Findings

| Severity | Blocks | Source | Gate | Location | Finding | Why It Matters | Review Or Fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| medium | no | gitleaks | Gate 4 â€” Secrets & Config Hygiene | n/a | Gitleaks scanner unavailable | Secrets may exist in the target repository without being detected by this local scan. | Install Gitleaks and rerun `launchguardian scan --target .` before relying on scan results. |
| medium | no | semgrep | Gate 3 â€” Code Security | n/a | Semgrep scanner unavailable | Code security issues may exist in the target repository without being detected by this local scan. | Install Semgrep and rerun `launchguardian scan --target .` before relying on scan results. |
| medium | no | trivy | Gate 10 â€” Dependency, SBOM & Supply Chain | n/a | Trivy scanner unavailable | Dependency, container, filesystem, or infrastructure configuration issues may exist without being detected by this local scan. | Install Trivy and rerun `launchguardian scan --target .` before relying on scan results. |
| critical | yes | frontend_exposure | Gate 4 â€” Secrets & Config Hygiene | .env.local:1 | Frontend-exposed secret-like environment variable | Frontend public environment variables are bundled for browser access and must not contain secrets. | Move the secret to server-side configuration and expose only non-sensitive public values to frontend code. |
| low | no | frontend_exposure | Gate 5 â€” Frontend Exposure | server.js:13 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| high | yes | frontend_exposure | Gate 8 â€” Auth, Sessions & CSRF | public\app.js:2 | Sensitive-looking browser storage usage | Sensitive values in localStorage or sessionStorage can be exposed to browser-side script access. | Use safer session handling patterns and avoid storing sensitive credentials in browser storage. |
| low | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js:4 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js:5 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js:11 | Frontend debug or non-production URL reference | Debug, localhost, or staging references can leak implementation context or break production behavior. | Confirm the reference is intentional and gated from production builds where appropriate. |
| medium | no | frontend_exposure | Gate 5 â€” Frontend Exposure | public\app.js.map | Frontend source map present | Source maps can expose original source structure and implementation details in shipped frontend artifacts. | Confirm source maps are intended for the target environment, or exclude them from production artifacts. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:6 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:11 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| medium | no | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:21 | API route has no obvious auth guard | Unauthenticated API routes can expose data or actions if they are intended to be protected. | Confirm the route is public, or add/verify authentication middleware or route-level auth checks. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:21 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| medium | no | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:27 | API route has no obvious auth guard | Unauthenticated API routes can expose data or actions if they are intended to be protected. | Confirm the route is public, or add/verify authentication middleware or route-level auth checks. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:27 | Sensitive admin route lacks obvious role check | Admin or privileged actions without role checks can allow unauthorized access or privilege escalation. | Add an explicit role, permission, or policy check near the privileged action. |
| medium | no | api_surface | Gate 8 â€” Auth, Sessions & CSRF | server\routes\demo-routes.js:33 | State-changing session route lacks obvious CSRF signal | Cookie-backed state changes without CSRF protections may be exposed to cross-site request risks. | Confirm CSRF or SameSite protections exist for cookie-backed state-changing routes. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:28 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |
| high | yes | api_surface | Gate 7 â€” Injection & Input Safety | server\routes\demo-routes.js:28 | Raw SQL string construction detected | Constructing SQL with dynamic strings can introduce injection risk. | Use parameterized queries or ORM query builders with bound values. |
| high | yes | api_surface | Gate 6 â€” API Auth & Object Authorization | server\routes\demo-routes.js:42 | Object lookup by ID lacks obvious ownership filter | Object lookups without ownership checks can lead to insecure direct object reference issues. | Filter object access by the authenticated user's ownership, organization, tenant, or permission context. |

