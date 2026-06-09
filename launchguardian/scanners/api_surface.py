from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import LaunchGuardianConfig, is_excluded
from ..models import Finding
from .base import ScannerResult


API_AUTH_GATE = "Gate 6 — API Auth & Object Authorization"
INJECTION_GATE = "Gate 7 — Injection & Input Safety"
SESSION_GATE = "Gate 8 — Auth, Sessions & CSRF"
BUSINESS_LOGIC_GATE = "Gate 19 — Business Logic Abuse"

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}
IGNORED_PARTS = {("reports", "launchguardian"), (".next", "cache")}
API_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs", ".rb", ".php"}
API_DIRECTORIES = {
    "api",
    "routes",
    "controllers",
    "server",
    "backend",
    "functions",
}
API_PATH_SEQUENCES = {
    ("app", "api"),
    ("pages", "api"),
    ("supabase", "functions"),
    ("netlify", "functions"),
    ("vercel", "functions"),
}
ROUTE_PATTERN = re.compile(
    r"(@(?:app|router|bp)\.(?:route|get|post|put|patch|delete)\b|"
    r"\b(?:app|router|server)\.(?:get|post|put|patch|delete)\s*\(|"
    r"\b(?:GET|POST|PUT|PATCH|DELETE)\s*\(|"
    r"export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|"
    r"def\s+(?:get|post|put|patch|delete|handler)\b)",
    re.IGNORECASE,
)
STATE_METHOD_PATTERN = re.compile(r"\b(?:post|put|patch|delete|POST|PUT|PATCH|DELETE)\b")
AUTH_PATTERN = re.compile(
    r"(requireAuth|getServerSession|\bauth\s*\(|currentUser|verifyToken|jwt\.verify|middleware\s+auth|"
    r"Depends\s*\(\s*get_current_user\s*\)|request\.user|user\.is_authenticated|@login_required|"
    r"passport\.authenticate|clerkClient|supabase\.auth\.getUser|firebase.*(?:auth|verify))",
    re.IGNORECASE,
)
ADMIN_CONTEXT_PATTERN = re.compile(
    r"(admin|owner|billing|payment|invite|user management|role|permissions|organization settings|org settings)",
    re.IGNORECASE,
)
ROLE_CHECK_PATTERN = re.compile(
    r"(isAdmin|adminOnly|requireAdmin|hasRole|role\s*[!=]=|permissions?\.|can\(|authorize|policy|rbac|"
    r"ownerOnly|billingAdmin|orgAdmin)",
    re.IGNORECASE,
)
ID_LOOKUP_PATTERN = re.compile(
    r"(params\.id|req\.params\.id|request\.args\.get\([\"']id[\"']\)|searchParams\.get\([\"']id[\"']\)|"
    r"query\.id|findUnique\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*id|findById\s*\(\s*id|"
    r"SELECT\b.+\bWHERE\b.+\bid\s*=)",
    re.IGNORECASE,
)
OWNERSHIP_PATTERN = re.compile(
    r"(userId|ownerId|orgId|tenantId|accountId|teamId|createdBy|request\.user|currentUser|session\.user)",
    re.IGNORECASE,
)
SQL_KEYWORD_PATTERN = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
SQL_CONSTRUCTION_PATTERN = re.compile(r"(\$\{|`|f[\"']|%s|\.format\s*\(|\+\s*\w+|\w+\s*\+)")
COOKIE_SESSION_PATTERN = re.compile(r"(cookie|cookies|session)", re.IGNORECASE)
CSRF_PATTERN = re.compile(r"(csrf|csrfToken|sameSite)", re.IGNORECASE)
BUSINESS_CONTEXT_PATTERN = re.compile(
    r"(payment|billing|credits|subscription|invite|role|permission|admin|refund|transfer)",
    re.IGNORECASE,
)
POLICY_GUARD_COMMENT_PATTERN = re.compile(
    r"(policy|guard|authorization|authorize|permission check|business rule|abuse check)",
    re.IGNORECASE,
)


class ApiSurfaceScanner:
    name = "api_surface"

    def __init__(self, config: LaunchGuardianConfig | None = None) -> None:
        self.config = config

    def scan(self, target: Path, report_dir: Path, *, strict_scanners: bool = False) -> ScannerResult:
        raw_dir = report_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / "api-surface-results.json"

        raw_results: list[dict] = []
        findings: list[Finding] = []
        for path in _iter_api_files(target, self.config):
            relative_path = path.relative_to(target)
            lines = list(_safe_read_lines(path))
            route_lines = _route_lines(relative_path, lines)

            for line_number, line in route_lines:
                route = _extract_route(line, relative_path)
                window = _window_text(lines, line_number)
                path_context = str(relative_path)
                if not AUTH_PATTERN.search(window):
                    raw_results.append(_raw_result("api_route_without_obvious_auth", relative_path, line_number, route))
                    findings.append(_missing_auth_finding(relative_path, line_number, route))
                if ADMIN_CONTEXT_PATTERN.search(f"{path_context}\n{window}") and not ROLE_CHECK_PATTERN.search(window):
                    raw_results.append(_raw_result("admin_route_without_role_check", relative_path, line_number, route))
                    findings.append(_admin_role_finding(relative_path, line_number, route))
                if (
                    STATE_METHOD_PATTERN.search(line)
                    and COOKIE_SESSION_PATTERN.search(window)
                    and not CSRF_PATTERN.search(window)
                ):
                    raw_results.append(_raw_result("state_change_missing_csrf_signal", relative_path, line_number, route))
                    findings.append(_csrf_finding(relative_path, line_number, route))
                if (
                    BUSINESS_CONTEXT_PATTERN.search(f"{path_context}\n{window}")
                    and not POLICY_GUARD_COMMENT_PATTERN.search(window)
                ):
                    raw_results.append(_raw_result("business_sensitive_endpoint", relative_path, line_number, route))
                    findings.append(_business_logic_finding(relative_path, line_number, route))

            for line_number, line in lines:
                window = _window_text(lines, line_number)
                route = _nearest_route(relative_path, route_lines, line_number)
                if ID_LOOKUP_PATTERN.search(line) and not OWNERSHIP_PATTERN.search(window):
                    raw_results.append(_raw_result("id_lookup_without_ownership_filter", relative_path, line_number, route))
                    findings.append(_ownership_finding(relative_path, line_number, route))
                if SQL_KEYWORD_PATTERN.search(line) and SQL_CONSTRUCTION_PATTERN.search(line):
                    raw_results.append(_raw_result("raw_sql_string_construction", relative_path, line_number, route))
                    findings.append(_raw_sql_finding(relative_path, line_number, route))

        raw_output_path.write_text(
            json.dumps(
                {
                    "schema_name": "launchguardian.api_surface.raw",
                    "schema_version": "0.1.0",
                    "results": raw_results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return ScannerResult(
            name=self.name,
            available=True,
            findings=_dedupe_findings(findings),
            detected_count=len(_dedupe_findings(findings)),
            raw_output_path=raw_output_path,
        )


def _iter_api_files(target: Path, config: LaunchGuardianConfig | None = None):
    for path in target.rglob("*"):
        if not path.is_file() or _is_ignored(path, target, config):
            continue
        if path.suffix.lower() in API_SUFFIXES and _is_likely_api_file(path, target):
            yield path


def _is_ignored(path: Path, target: Path, config: LaunchGuardianConfig | None = None) -> bool:
    relative_parts = path.relative_to(target).parts
    if any(part in IGNORED_DIRECTORIES for part in relative_parts):
        return True
    if any(_has_part_sequence(relative_parts, ignored) for ignored in IGNORED_PARTS):
        return True
    return bool(config and is_excluded(path, target, config))


def _is_likely_api_file(path: Path, target: Path) -> bool:
    relative_parts = path.relative_to(target).parts
    if any(part in API_DIRECTORIES for part in relative_parts):
        return True
    if any(_has_part_sequence(relative_parts, sequence) for sequence in API_PATH_SEQUENCES):
        return True
    if path.name.lower() in {"route.ts", "route.js", "handler.ts", "handler.js"}:
        return True
    return False


def _has_part_sequence(parts: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    return any(parts[index : index + len(sequence)] == sequence for index in range(len(parts)))


def _safe_read_lines(path: Path):
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle, start=1):
                yield index, line.rstrip("\n")
    except OSError:
        return


def _route_lines(relative_path: Path, lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    found = [(line_number, line) for line_number, line in lines if ROUTE_PATTERN.search(line)]
    if found:
        return found
    if _path_implies_route(relative_path):
        return [(lines[0][0], lines[0][1] if lines else str(relative_path))] if lines else [(1, str(relative_path))]
    return []


def _path_implies_route(relative_path: Path) -> bool:
    parts = relative_path.parts
    return any(part in API_DIRECTORIES for part in parts) or any(
        _has_part_sequence(parts, sequence) for sequence in API_PATH_SEQUENCES
    )


def _window_text(lines: list[tuple[int, str]], line_number: int, radius: int = 8) -> str:
    return "\n".join(
        line for current_line, line in lines if line_number - radius <= current_line <= line_number + radius
    )


def _extract_route(line: str, relative_path: Path) -> str:
    quoted_route = re.search(r"[\"']([^\"']*/[^\"']*)[\"']", line)
    if quoted_route:
        return quoted_route.group(1)
    method = STATE_METHOD_PATTERN.search(line)
    if method:
        return f"{method.group(0).upper()} {relative_path}"
    return str(relative_path)


def _nearest_route(relative_path: Path, route_lines: list[tuple[int, str]], line_number: int) -> str:
    if not route_lines:
        return str(relative_path)
    nearest = min(route_lines, key=lambda item: abs(item[0] - line_number))
    return _extract_route(nearest[1], relative_path)


def _raw_result(pattern_label: str, relative_path: Path, line: int, route: str) -> dict:
    return {
        "pattern_label": pattern_label,
        "file_path": str(relative_path),
        "line": line,
        "endpoint_or_route": route,
    }


def _finding(
    *,
    title: str,
    severity: str,
    category: str,
    relative_path: Path,
    line: int,
    route: str,
    description: str,
    risk: str,
    recommendation: str,
    related_gate: str,
    blocks_launch: bool,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        status="open",
        category=category,
        source="api_surface",
        file_path=str(relative_path),
        line=line,
        endpoint_or_route=route,
        description=description,
        risk=risk,
        recommendation=recommendation,
        related_gate=related_gate,
        blocks_launch=blocks_launch,
    )


def _missing_auth_finding(relative_path: Path, line: int, route: str) -> Finding:
    return _finding(
        title="API route has no obvious auth guard",
        severity="medium",
        category="api_auth",
        relative_path=relative_path,
        line=line,
        route=route,
        description="A likely API route was found without a nearby recognizable authentication guard.",
        risk="Unauthenticated API routes can expose data or actions if they are intended to be protected.",
        recommendation="Confirm the route is public, or add/verify authentication middleware or route-level auth checks.",
        related_gate=API_AUTH_GATE,
        blocks_launch=False,
    )


def _admin_role_finding(relative_path: Path, line: int, route: str) -> Finding:
    return _finding(
        title="Sensitive admin route lacks obvious role check",
        severity="high",
        category="api_authorization",
        relative_path=relative_path,
        line=line,
        route=route,
        description="A sensitive route context was found without a nearby recognizable admin or role authorization check.",
        risk="Admin or privileged actions without role checks can allow unauthorized access or privilege escalation.",
        recommendation="Add an explicit role, permission, or policy check near the privileged action.",
        related_gate=API_AUTH_GATE,
        blocks_launch=True,
    )


def _ownership_finding(relative_path: Path, line: int, route: str) -> Finding:
    return _finding(
        title="Object lookup by ID lacks obvious ownership filter",
        severity="high",
        category="object_authorization",
        relative_path=relative_path,
        line=line,
        route=route,
        description="A user-controlled ID lookup was found without a nearby user, owner, org, tenant, account, or team filter.",
        risk="Object lookups without ownership checks can lead to insecure direct object reference issues.",
        recommendation="Filter object access by the authenticated user's ownership, organization, tenant, or permission context.",
        related_gate=API_AUTH_GATE,
        blocks_launch=True,
    )


def _raw_sql_finding(relative_path: Path, line: int, route: str) -> Finding:
    return _finding(
        title="Raw SQL string construction detected",
        severity="high",
        category="injection",
        relative_path=relative_path,
        line=line,
        route=route,
        description="SQL keyword usage appears near string interpolation or concatenation.",
        risk="Constructing SQL with dynamic strings can introduce injection risk.",
        recommendation="Use parameterized queries or ORM query builders with bound values.",
        related_gate=INJECTION_GATE,
        blocks_launch=True,
    )


def _csrf_finding(relative_path: Path, line: int, route: str) -> Finding:
    return _finding(
        title="State-changing session route lacks obvious CSRF signal",
        severity="medium",
        category="auth_session",
        relative_path=relative_path,
        line=line,
        route=route,
        description="A likely state-changing route references cookies or sessions without a nearby CSRF or SameSite signal.",
        risk="Cookie-backed state changes without CSRF protections may be exposed to cross-site request risks.",
        recommendation="Confirm CSRF or SameSite protections exist for cookie-backed state-changing routes.",
        related_gate=SESSION_GATE,
        blocks_launch=False,
    )


def _business_logic_finding(relative_path: Path, line: int, route: str) -> Finding:
    return _finding(
        title="Business-sensitive endpoint needs policy review",
        severity="medium",
        category="business_logic",
        relative_path=relative_path,
        line=line,
        route=route,
        description="A route appears to handle business-sensitive actions without a nearby explicit policy or guard comment.",
        risk="Payment, billing, role, invite, refund, transfer, or credit flows need explicit abuse and authorization review.",
        recommendation="Document or add the relevant policy, guard, or abuse-control check for this endpoint.",
        related_gate=BUSINESS_LOGIC_GATE,
        blocks_launch=False,
    )


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.title, finding.file_path, finding.line, finding.endpoint_or_route)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
