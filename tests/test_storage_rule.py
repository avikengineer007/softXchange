"""
test_storage_rule.py — Zero Storage API Linting Enforcement

Enforcement contract (enforced by CI):
- No occurrence of `localStorage` or `sessionStorage` anywhere in
  apps/web-unified/static/**/*.{js,html}
- No occurrence of `document.cookie` assigned-to (write) in those files
- No occurrence of `indexedDB.open` in those files

Run: pytest tests/test_storage_rule.py -v
"""
import re
from pathlib import Path

# ── Scope ─────────────────────────────────────────────────────────────────────
WEB_UNIFIED_STATIC = Path(__file__).parent.parent / "apps" / "web-unified" / "static"

EXTENSIONS = {".html", ".js"}

# ── Forbidden patterns ────────────────────────────────────────────────────────
FORBIDDEN = [
    # Web Storage API write calls
    (r"localStorage\s*\.", "localStorage read or write"),
    (r"sessionStorage\s*\.", "sessionStorage read or write"),
    # Cookie writes (reads are acceptable for httpOnly cookies the server sets, but
    # direct JS cookie writes via `document.cookie = ...` are banned)
    (r"document\s*\.\s*cookie\s*=", "document.cookie assignment"),
    # IndexedDB opens (no structured storage)
    (r"indexedDB\s*\.\s*open", "indexedDB.open"),
]

# ── Files to scan ─────────────────────────────────────────────────────────────
def get_target_files():
    if not WEB_UNIFIED_STATIC.exists():
        return []
    return [
        f for f in WEB_UNIFIED_STATIC.rglob("*")
        if f.is_file() and f.suffix in EXTENSIONS
    ]


# ── Test ──────────────────────────────────────────────────────────────────────
def test_no_storage_api_in_web_unified():
    """
    Zero local/session/cookie-write/IndexedDB storage in apps/web-unified.

    This enforces the platform architectural rule:
    'No exception is granted for seller_region or any other key.
     The session is in-memory only via SoftXchangeAuth.'
    """
    target_files = get_target_files()
    assert len(target_files) > 0, (
        f"No HTML/JS files found under {WEB_UNIFIED_STATIC}. "
        "Ensure the web-unified app is present."
    )

    violations: list[tuple[str, int, str, str]] = []

    for filepath in sorted(target_files):
        rel = filepath.relative_to(WEB_UNIFIED_STATIC)
        lines = filepath.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, start=1):
            for pattern, description in FORBIDDEN:
                if re.search(pattern, line):
                    violations.append((str(rel), lineno, description, line.strip()))

    if violations:
        report = "\n".join(
            f"  {rel}:{lineno} [{desc}]\n    → {snippet}"
            for rel, lineno, desc, snippet in violations
        )
        raise AssertionError(
            f"\n\n❌ ZERO-STORAGE RULE VIOLATIONS DETECTED ({len(violations)} total):\n"
            f"{report}\n\n"
            "Fix: Move all state into window.SoftXchangeAuth in-memory session "
            "or derive values from the authenticated backend profile."
        )


def test_auth_js_exposes_required_interface():
    """
    auth.js must expose SoftXchangeAuth with required methods:
    - silentRefresh()
    - fetchWithAuth()
    - logout()
    - getAccessToken()
    """
    auth_js = WEB_UNIFIED_STATIC / "js" / "auth.js"
    assert auth_js.exists(), f"auth.js not found at {auth_js}"

    content = auth_js.read_text(encoding="utf-8")

    required_symbols = [
        ("SoftXchangeAuth", "SoftXchangeAuth global namespace"),
        ("silentRefresh", "silentRefresh() session hydration method"),
        ("fetchWithAuth", "fetchWithAuth() authenticated request wrapper"),
        ("logout", "logout() session teardown method"),
        ("getAccessToken", "getAccessToken() in-memory token accessor"),
    ]

    missing = [desc for sym, desc in required_symbols if sym not in content]
    assert not missing, (
        f"auth.js is missing required interface elements:\n"
        + "\n".join(f"  - {m}" for m in missing)
    )


def test_auth_js_has_no_storage_violations():
    """Dedicated check that auth.js itself — the single session authority — is clean."""
    auth_js = WEB_UNIFIED_STATIC / "js" / "auth.js"
    if not auth_js.exists():
        return  # Covered by test_auth_js_exposes_required_interface

    content = auth_js.read_text(encoding="utf-8")
    for pattern, desc in FORBIDDEN:
        matches = re.findall(pattern, content)
        assert not matches, (
            f"auth.js violates Zero Storage Rule: [{desc}] — "
            "The session authority must remain purely in-memory."
        )


def test_all_html_pages_use_unified_css_tokens():
    """All HTML pages in web-unified must link tokens.css and style.css."""
    html_files = [
        f for f in WEB_UNIFIED_STATIC.rglob("*.html")
        if f.is_file()
    ]
    assert len(html_files) > 0, "No HTML files found in web-unified"

    violations = []
    for filepath in sorted(html_files):
        content = filepath.read_text(encoding="utf-8")
        rel = filepath.relative_to(WEB_UNIFIED_STATIC)
        if "/static/css/tokens.css" not in content:
            violations.append(f"{rel}: missing /static/css/tokens.css link")
        if "/static/css/style.css" not in content:
            violations.append(f"{rel}: missing /static/css/style.css link")

    assert not violations, (
        "Design system CSS missing from HTML pages:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_no_cross_service_absolute_urls_in_html_pages():
    """
    All navigational href links in HTML pages must use root-relative paths,
    not absolute http://localhost:800x/static/... URLs pointing to other services.
    """
    html_files = [
        f for f in WEB_UNIFIED_STATIC.rglob("*.html")
        if f.is_file()
    ]

    cross_service_pattern = re.compile(
        r'href\s*=\s*["\']http://localhost:80(?!00)[0-9]+/static/[^"\']+["\']'
    )

    violations = []
    for filepath in sorted(html_files):
        content = filepath.read_text(encoding="utf-8")
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if cross_service_pattern.search(line):
                rel = filepath.relative_to(WEB_UNIFIED_STATIC)
                violations.append(f"{rel}:{lineno} → {line.strip()}")

    assert not violations, (
        "Cross-service absolute href links found — use root-relative paths:\n"
        + "\n".join(f"  {v}" for v in violations)
    )
