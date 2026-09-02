"""Rule definitions and calibrated static analysis rule catalog.

Matches the architecture of secrets_scanner rules, specifying:
  - id, name, language, matcher, severity, description, remediation_hint, confidence.

Confidence Discipline:
  - HIGH: Pure pattern matches with zero data-flow ambiguity (curl | sh, ctypes memory writes, unguarded rm -rf).
  - MEDIUM: Syntactic regex approximations of data-flow properties (non-literal eval, dynamic subprocess, context pickle).
  - LOW: Heuristic telemetry/visibility flags (obfuscation detection).
"""

from dataclasses import dataclass
from typing import List, Optional, Set, Union

from secrets_scanner.models import Confidence, Severity
from .matchers import (
    BaseMatcher,
    ContextAwareRegexMatcher,
    ObfuscationMatcher,
    RegexMatcher,
)


@dataclass(frozen=True)
class Rule:
    """Definition of a static analysis rule.
    
    Attributes:
        id: Unique rule identifier (e.g. 'PY_EVAL_NON_LITERAL').
        name: Short human-readable rule name.
        language: Target language ('python', 'javascript', 'typescript', 'shell', or 'any').
                  Can also be comma-separated (e.g. 'javascript,typescript').
        matcher: BaseMatcher instance (RegexMatcher, ContextAwareRegexMatcher, or future AST matcher).
        severity: Finding severity (CRITICAL, HIGH, MEDIUM, LOW) from secrets_scanner.models.
        description: Technical explanation of the issue detected.
        remediation_hint: Clear, actionable guidance shown to the seller.
        confidence: Baseline confidence rating (HIGH, MEDIUM, LOW).
    """
    id: str
    name: str
    language: str
    matcher: BaseMatcher
    severity: Severity
    description: str
    remediation_hint: str
    confidence: Confidence = Confidence.HIGH

    def matches_language(self, file_language: str) -> bool:
        """Determines if this rule applies to the detected file language."""
        if not file_language:
            return False

        target_lang = self.language.strip().lower()
        if target_lang == "any":
            return True

        # Handle comma-separated languages (e.g. "javascript,typescript")
        allowed_languages = {l.strip().lower() for l in target_lang.split(",") if l.strip()}
        return file_language.strip().lower() in allowed_languages


def get_default_rules() -> List[Rule]:
    """Returns the calibrated default catalog of static analysis rules."""
    return [
        # =========================================================================
        # Python Rules
        # =========================================================================
        Rule(
            id="PY_DANGEROUS_CTYPES_MEMORY",
            name="Direct Memory Manipulation via ctypes",
            language="python",
            matcher=RegexMatcher(
                r"(?<!\w)ctypes\.(?:memmove|memset|cast|c_void_p|pointer)|VirtualAlloc|mprotect|WriteProcessMemory"
            ),
            severity=Severity.CRITICAL,
            description="Direct memory manipulation using ctypes (memmove/memset/VirtualAlloc) bypasses Python memory safety and can lead to arbitrary code execution.",
            remediation_hint="Avoid raw memory manipulation via ctypes. Use safe, standard Python abstractions or bytearray/memoryview for binary data handling.",
            confidence=Confidence.HIGH,
        ),
        Rule(
            id="PY_EVAL_NON_LITERAL",
            name="Dynamic Code Execution (eval/exec)",
            language="python",
            matcher=RegexMatcher(
                r"""(?<!\w)(?:eval|exec)\s*\((?!\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|\d+|True|False|None)\s*\))"""
            ),
            severity=Severity.HIGH,
            description="eval() or exec() with dynamic arguments executes arbitrary code at runtime. (Syntactic approximation).",
            remediation_hint="Avoid eval() and exec() with dynamic variables. Parse structured data using json.loads() or ast.literal_eval().",
            confidence=Confidence.MEDIUM,
        ),
        Rule(
            id="PY_SUBPROCESS_DYNAMIC_SHELL",
            name="Command Injection via Dynamic Shell Execution",
            language="python",
            matcher=RegexMatcher(
                r"(?<!\w)os\.system\s*\((?!\s*['\"][^'\"\n]+['\"]\s*\))|(?<!\w)subprocess\.(?:call|check_call|check_output|run|Popen)\s*\([^)]*shell\s*=\s*True",
                exclude_pattern=r"shell\s*=\s*False",
            ),
            severity=Severity.HIGH,
            description="Executing shell commands with shell=True or dynamic variable concatenation is vulnerable to command injection. (Syntactic approximation).",
            remediation_hint="Pass command arguments as a list and set shell=False (default). Avoid interpolating untrusted variables into command strings.",
            confidence=Confidence.MEDIUM,
        ),
        Rule(
            id="PY_UNTRUSTED_PICKLE",
            name="Untrusted Deserialization via pickle",
            language="python",
            matcher=ContextAwareRegexMatcher(
                r"(?<!\w)pickle\.(?:loads?|Unpickler)\s*\(",
                context_keywords={
                    "request", "socket", "network", "recv", "client",
                    "conn", "stream", "payload", "body", "upload", "untrusted", "url"
                },
                context_window_lines=5,
            ),
            severity=Severity.HIGH,
            description="Deserializing data with pickle in the context of network streams, web requests, or untrusted inputs can execute arbitrary code.",
            remediation_hint="Avoid unpickling data received from external inputs, network streams, or untrusted files. Use safe serialization formats such as JSON or Protocol Buffers.",
            confidence=Confidence.MEDIUM,
        ),
        Rule(
            id="PY_INSECURE_BIND_ALL",
            name="Unrestricted Network Interface Binding (0.0.0.0)",
            language="python",
            matcher=RegexMatcher(
                r"(?<!\w)(?:bind\s*\(\s*\(\s*['\"]0\.0\.0\.0['\"]|run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"][^)]*debug\s*=\s*True|host\s*=\s*['\"]0\.0\.0\.0['\"][^)]*debug\s*=\s*True)"
            ),
            severity=Severity.LOW,
            description="Binding to 0.0.0.0 without authentication or with debug enabled exposes the service to all accessible network interfaces.",
            remediation_hint="Bind to 127.0.0.1 for local services or enforce an explicit authentication layer before listening on all interfaces (0.0.0.0).",
            confidence=Confidence.MEDIUM,
        ),

        # =========================================================================
        # JavaScript / TypeScript Rules
        # =========================================================================
        Rule(
            id="JS_EVAL_NON_LITERAL",
            name="Dynamic Code Evaluation (eval/Function)",
            language="javascript,typescript",
            matcher=RegexMatcher(
                r"""(?<!\w)(?:eval\s*\((?!\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`[^`$]*`)\s*\))|new\s+Function\s*\((?!\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')(?:\s*,\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'))*\s*\)))"""
            ),
            severity=Severity.HIGH,
            description="eval() or new Function() with dynamic inputs executes arbitrary JavaScript code. (Syntactic approximation).",
            remediation_hint="Avoid evaluating dynamic strings or creating functions with new Function(). Refactor into static functions or parse data using JSON.parse().",
            confidence=Confidence.MEDIUM,
        ),
        Rule(
            id="JS_CHILD_PROCESS_DYNAMIC_EXEC",
            name="Command Injection via child_process.exec",
            language="javascript,typescript",
            matcher=RegexMatcher(
                r"(?<!\w)child_process\.(?:exec|execSync)\s*\([^)]*(?:\+|`|\$\{)",
                exclude_pattern=r"execFile|spawn",
            ),
            severity=Severity.HIGH,
            description="Passing concatenated strings or template literals to child_process.exec invokes a shell with unescaped arguments, enabling command injection.",
            remediation_hint="Avoid passing concatenated strings or template literals to child_process.exec. Use child_process.execFile or child_process.spawn with an argument array.",
            confidence=Confidence.MEDIUM,
        ),
        Rule(
            id="JS_OBFUSCATED_CODE",
            name="Obfuscated or Packed Code Detected",
            language="javascript,typescript",
            matcher=ObfuscationMatcher(min_line_length=1500, min_hex_escapes=15),
            severity=Severity.LOW,
            description="Obfuscated or packed code was detected outside standard build/dist directories. (Heuristic visibility flag).",
            remediation_hint="Submit readable, unminified source code with reproducible build instructions. Avoid shipping packed or heavily obfuscated scripts.",
            confidence=Confidence.LOW,
        ),

        # =========================================================================
        # Shell Rules
        # =========================================================================
        Rule(
            id="SH_CURL_PIPE_SHELL",
            name="Untrusted Remote Script Piping to Shell",
            language="shell",
            matcher=RegexMatcher(r"(?<!\w)(?:curl|wget)\b[^|\n]*\|\s*(?:ba|z|k)?sh\b"),
            severity=Severity.CRITICAL,
            description="Piping downloaded content from curl/wget directly into a shell interpreter executes unverified remote code.",
            remediation_hint="Avoid piping downloaded scripts directly into a shell interpreter. Download the file, verify checksums or signatures, and review contents before executing.",
            confidence=Confidence.HIGH,
        ),
        Rule(
            id="SH_RM_RF_DYNAMIC_VAR",
            name="Dangerous rm -rf with Variable Expansion",
            language="shell",
            matcher=RegexMatcher(
                r"""(?<!\w)rm\s+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+(?!\$\{[^}:]+:\?\})(?:\$\{[^}]+\}|\$[\w]+|\"\$[\w{][^\"]*\"|\'\$[\w{][^\']*\'|/(?:\*|\s|$))"""
            ),
            severity=Severity.CRITICAL,
            description="rm -rf targeting unguarded variables or root paths can cause catastrophic file deletion if variables are unset or empty.",
            remediation_hint="Avoid using rm -rf with unvalidated variable expansions. If the variable is unset or empty, this can delete the root or home directory. Use explicit guards like ${DIR:?}/.",
            confidence=Confidence.HIGH,
        ),
    ]
