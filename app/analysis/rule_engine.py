from typing import Any, List, Optional

from app.analysis.parser import ParserRegistry, parser_registry
from app.analysis.rules.base import SecurityRule
from app.analysis.rules.builtin import get_default_rules
from app.core.enums import Language
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile


class RuleEngine:
    """Orchestrates static and AST-based vulnerability analysis across multilingual codebases."""

    def __init__(
        self,
        rules: Optional[List[SecurityRule]] = None,
        registry: Optional[ParserRegistry] = None,
    ):
        self._rules: List[SecurityRule] = list(rules) if rules is not None else get_default_rules()
        self._parser_registry: ParserRegistry = registry if registry is not None else parser_registry

    @property
    def rules(self) -> List[SecurityRule]:
        """Return a copy of currently registered rules."""
        return list(self._rules)

    def register_rule(self, rule: SecurityRule) -> None:
        """Register an additional security rule into the engine."""
        self._rules.append(rule)

    def get_rules_for_language(self, language: Language) -> List[SecurityRule]:
        """Retrieve all rules that apply to a specific programming language."""
        return [rule for rule in self._rules if rule.applies_to(language)]

    def _parse_source_tree(self, source_file: SourceFile) -> Optional[Any]:
        """Attempt to parse AST tree safely for the given source file."""
        if not self._parser_registry.is_supported(source_file.language):
            return None
        try:
            return self._parser_registry.parse_file(source_file, getattr(source_file, 'content', ''))
        except Exception:
            return None

    def analyze_file(self, source_file: SourceFile) -> List[AuditFinding]:
        """Scan a single source file against all applicable security rules."""
        findings: List[AuditFinding] = []
        ast_tree = self._parse_source_tree(source_file)
        applicable_rules = self.get_rules_for_language(source_file.language)

        for rule in applicable_rules:
            try:
                rule_findings = rule.evaluate(source_file=source_file, ast_tree=ast_tree)
                findings.extend(rule_findings)
            except Exception:
                # Rule execution is isolated: a failure in one rule never halts others
                continue

        return findings

    def analyze_project(self, source_files: List[SourceFile]) -> List[AuditFinding]:
        """Scan a collection of source files and aggregate all detected findings."""
        all_findings: List[AuditFinding] = []
        for file in source_files:
            file_findings = self.analyze_file(file)
            all_findings.extend(file_findings)
        return all_findings


# Singleton default rule engine instance for application-wide use
default_rule_engine = RuleEngine()
