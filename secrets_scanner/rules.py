"""Rule definitions, placeholder filters, and default catalog for secrets scanner."""

import re
from typing import List, Optional, Pattern, Set
from .models import Confidence, Rule, RuleType, Severity

# Placeholder and template patterns to suppress false positives on dummy values
PLACEHOLDER_DENYLIST: Set[str] = {
    "xxx",
    "xxxx",
    "xxxxx",
    "changeme",
    "change_me",
    "change-me",
    "your_api_key_here",
    "your_key_here",
    "your_secret_here",
    "your_token_here",
    "your_password_here",
    "your_access_token_here",
    "your_token",
    "your_key",
    "insert_key_here",
    "insert_api_key_here",
    "insert_secret_here",
    "insert_token_here",
    "enter_your_key_here",
    "enter_your_token_here",
    "enter_key_here",
    "my_secret_key",
    "my_api_key",
    "my_secret",
    "my_token",
    "placeholder",
    "dummy_value",
    "sample_key",
    "sample_token",
    "example_key",
    "example_secret",
    "example_token",
    "test_key",
    "test_secret",
    "fake_key",
    "fake_secret",
    "dummy_token",
    "dummy",
    "fake",
    "test",
    "null",
    "undefined",
    "default_password",
    "password123",
    "secret123",
    "admin123",
    "redacted",
    "<redacted>",
    "[redacted]",
    "{redacted}",
    "00000000",
    "12345678",
}

PLACEHOLDER_REGEX = re.compile(
    r"(?i)^(?:your[_-]?(?:api[_-]?key|secret|token|password|access[_-]?key|client[_-]?secret)[a-z0-9_-]*"
    r"|insert[_-]?(?:api[_-]?key|secret|token|password)[a-z0-9_-]*"
    r"|enter[_-]?(?:your[_-]?)?(?:key|secret|token|password)[a-z0-9_-]*"
    r"|<[a-z0-9_\-\s]+>"
    r"|\[[a-z0-9_\-\s]+\]"
    r"|\{[a-z0-9_\-\s]+\}"
    r"|\$\{[a-z0-9_\-]+\}"
    r"|%[a-z0-9_\-]+%"
    r"|x{3,}"
    r"|\*{3,}"
    r"|#{3,}"
    r"|\-{3,})$"
)


def is_placeholder_value(token: str) -> bool:
    """Checks whether a token represents an obvious placeholder, template, or dummy value.
    
    Args:
        token: Candidate string to inspect.
        
    Returns:
        True if the token is a placeholder and should be suppressed; False otherwise.
    """
    clean_token = token.strip().strip("'\"`")
    if not clean_token:
        return True
    
    normalized = clean_token.lower()
    if normalized in PLACEHOLDER_DENYLIST:
        return True

    # Check bracket-stripped version (e.g. <REDACTED> -> redacted)
    if (normalized.startswith("<") and normalized.endswith(">")) or \
       (normalized.startswith("[") and normalized.endswith("]")) or \
       (normalized.startswith("{") and normalized.endswith("}")):
        inner = normalized[1:-1].strip()
        if inner in PLACEHOLDER_DENYLIST:
            return True
        
    if PLACEHOLDER_REGEX.match(normalized):
        return True
        
    return False


DEFAULT_RULES: List[Rule] = [
    Rule(
        id="AWS_ACCESS_KEY_ID",
        name="AWS Access Key ID",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies standard AWS 20-character Access Key IDs starting with AKIA, ASIA, ABIA, or ACCA.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
    ),
    Rule(
        id="AWS_SECRET_ACCESS_KEY",
        name="AWS Secret Access Key",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies 40-character AWS Secret Access Keys assigned near AWS credential context keywords.",
        rule_type=RuleType.REGEX,
        regex=re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key|aws_secret)\s*(?:=|:|:=|=>)\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        )
    ),
    Rule(
        id="GITHUB_TOKEN",
        name="GitHub Personal Access or OAuth Token",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies classic and fine-grained GitHub personal access tokens, OAuth tokens, and server keys.",
        rule_type=RuleType.REGEX,
        regex=re.compile(
            r"\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b"
        )
    ),
    Rule(
        id="STRIPE_API_KEY",
        name="Stripe API Secret / Restricted Key",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Identifies live and test secret and restricted API keys from Stripe.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b")
    ),
    Rule(
        id="SLACK_TOKEN",
        name="Slack Token",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies Slack user tokens, bot tokens, and app-level tokens.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b(?:xox[baprs]-[0-9a-zA-Z-]{20,72}|xapp-[0-9a-zA-Z-]{20,72})\b")
    ),
    Rule(
        id="GOOGLE_API_KEY",
        name="Google API Key",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Identifies Google Cloud and Google Maps API keys starting with AIza.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")
    ),
    Rule(
        id="NPM_TOKEN",
        name="npm Access Token",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Identifies npm personal access and automation tokens starting with npm_.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b")
    ),
    Rule(
        id="PYPI_TOKEN",
        name="PyPI Upload Token",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Identifies Python Package Index (PyPI) upload API tokens starting with pypi-.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b(pypi-[A-Za-z0-9\-_]{50,200})\b")
    ),
    Rule(
        id="TWILIO_KEY",
        name="Twilio API Key or Account SID",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Identifies Twilio API Keys (SK...) and Account SIDs (AC...).",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\b((?:AC|SK)[0-9a-fA-F]{32})\b")
    ),
    Rule(
        id="SSH_PRIVATE_KEY",
        name="SSH Private Key",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies OpenSSH private key headers and PuTTY private key files.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----|PuTTY-User-Key-File-[0-9]+:")
    ),
    Rule(
        id="PRIVATE_KEY_HEADER",
        name="Private Key Header",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies standard PEM private key header blocks (RSA, EC, DSA, OPENSSH, etc.).",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")
    ),
    Rule(
        id="JWT_TOKEN",
        name="JSON Web Token (JWT)",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="Identifies signed JWT tokens formatted with three Base64URL-encoded segments.",
        rule_type=RuleType.REGEX,
        regex=re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
    ),
    Rule(
        id="DATABASE_CONNECTION_STRING",
        name="Database Connection String with Credentials",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Identifies standard database URIs containing embedded plaintext usernames and passwords.",
        rule_type=RuleType.REGEX,
        regex=re.compile(
            r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|sqlite|mssql|oracle):\/\/[^\s:]+:[^\s@]+@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[^\s]*"
        )
    ),
    Rule(
        id="HARDCODED_PASSWORD",
        name="Hardcoded Password Assignment",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Identifies plaintext password variables and credentials in configuration or code assignments.",
        rule_type=RuleType.REGEX,
        regex=re.compile(
            r"(?i)(?:password|passwd|db_password|db_pass|admin_password|secret_password|auth_pass)\s*(?:=|:|:=|=>)\s*['\"]([^\s'\"`]{8,128})['\"]"
        )
    ),
    Rule(
        id="GENERIC_API_KEY",
        name="Generic API Key or Secret Assignment",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Identifies high-entropy token assignments accompanied by generic credential keywords.",
        rule_type=RuleType.REGEX,
        regex=re.compile(
            r"(?i)(?:api_key|apikey|secret_key|app_secret|auth_token|access_token|client_secret|api_secret|account_key|token_secret|bearer_token|private_token)\s*(?:=|:|:=|=>)\s*['\"]([A-Za-z0-9_\-.~+/=]{16,128})['\"]"
        )
    ),
    Rule(
        id="GENERIC_SECRET_ASSIGNMENT",
        name="Generic Credential Assignment",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Identifies assignments to variables named password, secret, or api_key with non-placeholder values.",
        rule_type=RuleType.REGEX,
        regex=re.compile(
            r"(?i)\b(?:password|secret|api_key)\s*(?:=|:|:=|=>)\s*['\"]?([^\s'\"`]{8,128})['\"]?"
        )
    ),
    Rule(
        id="HIGH_ENTROPY_TOKEN",
        name="High Entropy Token",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        description="Identifies high-entropy string literals or standalone tokens >= 20 characters based on charset-specific Shannon entropy thresholds.",
        rule_type=RuleType.ENTROPY,
        entropy_thresholds={
            "hex": 3.0,
            "base64": 4.5,
            "general": 4.5,
        },
        min_entropy_len=20
    )
]


def get_default_rules() -> List[Rule]:
    """Returns a fresh copy of the default rules catalog."""
    return list(DEFAULT_RULES)
