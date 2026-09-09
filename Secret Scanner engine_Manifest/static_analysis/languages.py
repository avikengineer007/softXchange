"""Extensible language detection engine for static analysis.

Detects languages based on file extensions and shebang lines.
Designed with an open registry so additional languages (e.g. Go, Ruby, Rust, Java)
can be registered seamlessly without modifying existing scanner logic.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set, Tuple


class Language(str, Enum):
    """Standard recognized language identifiers."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    SHELL = "shell"
    ANY = "any"


@dataclass(frozen=True)
class LanguageDefinition:
    """Specification of a programming or scripting language.
    
    Attributes:
        name: Canonical language identifier (e.g. 'python', 'javascript').
        extensions: Tuple of file extensions associated with this language (lowercase, with dot).
        shebang_patterns: Regex patterns matching shebang interpreters for this language.
        aliases: Alternative names or aliases for matching rules.
    """
    name: str
    extensions: Tuple[str, ...] = field(default_factory=tuple)
    shebang_patterns: Tuple[Pattern[str], ...] = field(default_factory=tuple)
    aliases: Tuple[str, ...] = field(default_factory=tuple)

    def matches_extension(self, ext: str) -> bool:
        """Checks whether a given extension (e.g. '.py') belongs to this language."""
        return ext.lower() in self.extensions

    def matches_shebang(self, first_line: str) -> bool:
        """Checks whether the first line of a file contains a matching shebang."""
        if not first_line.startswith("#!"):
            return False
        shebang = first_line.strip()
        return any(pattern.search(shebang) is not None for pattern in self.shebang_patterns)


class LanguageRegistry:
    """Registry managing language definitions and language resolution."""

    def __init__(self) -> None:
        self._languages: Dict[str, LanguageDefinition] = {}
        self._extension_map: Dict[str, str] = {}
        self._register_defaults()

    def register(self, definition: LanguageDefinition) -> None:
        """Registers a new language definition without modifying existing logic."""
        lang_key = definition.name.lower()
        self._languages[lang_key] = definition

        for ext in definition.extensions:
            self._extension_map[ext.lower()] = lang_key

    def get_language(self, name: str) -> Optional[LanguageDefinition]:
        """Retrieves a registered language definition by name or alias."""
        norm = name.lower()
        if norm in self._languages:
            return self._languages[norm]
        for lang_def in self._languages.values():
            if norm in [a.lower() for a in lang_def.aliases]:
                return lang_def
        return None

    def detect_language(self, file_path: str, first_line: Optional[str] = None) -> Optional[str]:
        """Detects the language of a file by extension first, then by shebang.
        
        Args:
            file_path: Relative or absolute path to the file.
            first_line: First line of the file content (if available).
            
        Returns:
            Canonical language name (e.g. 'python', 'javascript', 'shell') or None.
        """
        # 1. Match by extension
        _, ext = os.path.splitext(file_path)
        if ext:
            lang = self._extension_map.get(ext.lower())
            if lang:
                return lang

        # 2. Match by shebang if first line is provided
        if first_line and first_line.startswith("#!"):
            for lang_def in self._languages.values():
                if lang_def.matches_shebang(first_line):
                    return lang_def.name

        return None

    def supported_extensions(self) -> Set[str]:
        """Returns all recognized file extensions."""
        return set(self._extension_map.keys())

    def _register_defaults(self) -> None:
        """Registers default language definitions for Python, JS/TS, and Shell."""
        # Python
        self.register(
            LanguageDefinition(
                name=Language.PYTHON.value,
                extensions=(".py", ".pyw", ".pyi"),
                shebang_patterns=(
                    re.compile(r"^#!\s*(?:/usr/bin/env\s+)?python(?:\d+(?:\.\d+)?)?(?:w)?(?:\s|$)", re.IGNORECASE),
                    re.compile(r"^#!\s*(?:/[^/\s]+)+/python(?:\d+(?:\.\d+)?)?(?:w)?(?:\s|$)", re.IGNORECASE),
                ),
                aliases=("py",),
            )
        )

        # JavaScript
        self.register(
            LanguageDefinition(
                name=Language.JAVASCRIPT.value,
                extensions=(".js", ".mjs", ".cjs", ".jsx"),
                shebang_patterns=(
                    re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(?:node|nodejs|bun)(?:\s|$)", re.IGNORECASE),
                    re.compile(r"^#!\s*(?:/[^/\s]+)+/(?:node|nodejs|bun)(?:\s|$)", re.IGNORECASE),
                ),
                aliases=("js", "javascript", "node"),
            )
        )

        # TypeScript
        self.register(
            LanguageDefinition(
                name=Language.TYPESCRIPT.value,
                extensions=(".ts", ".mts", ".cts", ".tsx"),
                shebang_patterns=(
                    re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(?:ts-node|deno)(?:\s|$)", re.IGNORECASE),
                    re.compile(r"^#!\s*(?:/[^/\s]+)+/(?:ts-node|deno)(?:\s|$)", re.IGNORECASE),
                ),
                aliases=("ts", "typescript"),
            )
        )

        # Shell
        self.register(
            LanguageDefinition(
                name=Language.SHELL.value,
                extensions=(".sh", ".bash", ".zsh", ".ksh"),
                shebang_patterns=(
                    re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(?:sh|bash|zsh|ksh|dash)(?:\s|$)", re.IGNORECASE),
                    re.compile(r"^#!\s*(?:/[^/\s]+)+/(?:sh|bash|zsh|ksh|dash)(?:\s|$)", re.IGNORECASE),
                ),
                aliases=("sh", "bash", "zsh", "shellscript"),
            )
        )


# Global default registry instance
DEFAULT_LANGUAGE_REGISTRY = LanguageRegistry()
