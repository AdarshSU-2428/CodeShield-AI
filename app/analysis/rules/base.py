from abc import ABC, abstractmethod
from typing import Any, List, Optional

from app.core.enums import Confidence, Language, Severity
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile


class SecurityRule(ABC):
    """Abstract base class for static and AST-based security analysis rules."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: Confidence,
        cwe_id: str,
        language: Language,
        recommendation: str,
    ):
        self._rule_id: str = rule_id
        self._title: str = title
        self._description: str = description
        self._severity: Severity = severity
        self._confidence: Confidence = confidence
        self._cwe_id: str = cwe_id
        self._language: Language = language
        self._recommendation: str = recommendation

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def severity(self) -> Severity:
        return self._severity

    @property
    def confidence(self) -> Confidence:
        return self._confidence

    @property
    def cwe_id(self) -> str:
        return self._cwe_id

    @property
    def language(self) -> Language:
        return self._language

    @property
    def recommendation(self) -> str:
        return self._recommendation

    def applies_to(self, language: Language) -> bool:
        """Return True if this rule applies to the given language."""
        if self._language == Language.UNKNOWN:
            return True
        return self._language == language

    @abstractmethod
    def evaluate(
        self,
        source_file: SourceFile,
        ast_tree: Optional[Any] = None,
    ) -> List[AuditFinding]:
        """Scan the source file and return any detected security findings."""
        pass
