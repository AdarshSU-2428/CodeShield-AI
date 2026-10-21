from dataclasses import dataclass, field
import re
from typing import Dict, List, Tuple

@dataclass
class SanitizationResult:
    """Carries sanitized content along with telemetry on redacted secrets."""
    sanitized_text: str
    redacted_count: int
    redacted_categories: List[str] = field(default_factory=list)

class CodeSanitizer:
    """Detects and redacts sensitive local information, secrets, and credentials."""
    def __init__(self):
        # Ordered list of (category_name, compiled_regex_pattern, replacement_token)
        self._patterns: List[Tuple[str, re.Pattern, str]] = self._compile_patterns()

    def _compile_patterns(self) -> List[Tuple[str, re.Pattern, str]]:
        """Compiles regex patterns for high-risk developer secrets and tokens."""
        raw_patterns = [
            # 1. Private Keys (RSA, EC, PGP, OPENSSH)
            (
                "PRIVATE_KEY",
                r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
                "[REDACTED_PRIVATE_KEY]",
            ),
            # 2. Cloud & Service API Keys (OpenAI, Groq, GitHub, Slack, AWS)
            (
                "API_KEY",
                r"\b(?:sk-[a-zA-Z0-9]{32,}|gsk_[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48}|AKIA[0-9A-Z]{16})\b",
                "[REDACTED_API_KEY]",
            ),
            # 3. Connection Strings with Passwords (postgres, mysql, mongodb, redis)
            (
                "DATABASE_URI",
                r"(?:postgresql|postgres|mysql|mysql2|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s]+:([^@\s]+)@[a-zA-Z0-9.-]+",
                lambda m: m.group(0).replace(m.group(1), "[REDACTED_PASSWORD]"),
            ),
            # 4. JWT (JSON Web Tokens)
            (
                "JWT_TOKEN",
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b",
                "[REDACTED_JWT_TOKEN]",
            ),
            # 5. Generic Code Assignments (password = "...", secret_key = "...")
            (
                "GENERIC_SECRET",
                r"""(?i)\b(password|passwd|secret|api_key|apikey|auth_token|access_token|private_key)\s*[:=]\s*["']([^"']{6,})["']""",
                lambda m: f'{m.group(1)} = "[REDACTED_SECRET]"',
            ),
            # 6. Windows / Unix User Home Directory Paths (e.g. C:\Users\Username\...)
            (
                "LOCAL_USER_PATH",
                r"""(?:[a-zA-Z]:\\Users\\[^\s\\/'"]+|/home/[^\s\\/'"]+|/Users/[^\s\\/'"])""",
                "[REDACTED_USER_PATH]",
            ),
        ]
        compiled = []
        for category, pattern, repl in raw_patterns:
            compiled.append((category, re.compile(pattern, re.MULTILINE), repl))
        return compiled

    def sanitize(self, text: str) -> SanitizationResult:
        """
        Sanitize input source code or context string in-memory.
        Returns SanitizationResult with cleaned text and redaction metadata.
        """
        if not text:
            return SanitizationResult(sanitized_text="", redacted_count=0)
        sanitized = text
        total_redacted = 0
        categories_detected: List[str] = []
        for category, regex, replacement in self._patterns:
            matches = list(regex.finditer(sanitized))
            if matches:
                total_redacted += len(matches)
                categories_detected.append(category)
                if callable(replacement):
                    sanitized = regex.sub(replacement, sanitized)
                else:
                    sanitized = regex.sub(replacement, sanitized)
        return SanitizationResult(
            sanitized_text=sanitized,
            redacted_count=total_redacted,
            redacted_categories=categories_detected,
        )

    def is_clean(self, text: str) -> bool:
        """Helper to verify if a text has zero sensitive matches."""
        for _, regex, _ in self._patterns:
            if regex.search(text):
                return False
        return True
        
# Global default sanitizer instance
sanitizer = CodeSanitizer()
