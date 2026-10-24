from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from app.core.interfaces.llm import LLMClient
from app.core.models.audit import (
    AuditFinding,
    Confidence,
    FindingCategory,
    Severity,
)
from app.core.models.code import CodeComponent, SourceFile
from app.infrastructure.llm import GroqLLMClient

if TYPE_CHECKING:
    from app.analysis.cross_file import CrossFileContextResolver


class AIVulnerabilityAnalyzer:
    """Uses Groq LLM Cloud Assistance to detect semantic and cross-file security vulnerabilities."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        cross_file_resolver: Optional["CrossFileContextResolver"] = None,
        max_file_size_chars: int = 50000,
        temperature: float = 0.1,
    ):
        self.llm_client: LLMClient = llm_client if llm_client is not None else GroqLLMClient()
        self.cross_file_resolver: Optional["CrossFileContextResolver"] = cross_file_resolver
        self.max_file_size_chars: int = max_file_size_chars
        self.temperature: float = temperature

    def _parse_severity(self, raw_sev: Any) -> Severity:
        """Safely parse arbitrary severity string into Severity enum."""
        if isinstance(raw_sev, Severity):
            return raw_sev
        val = str(raw_sev).strip().lower()
        for sev in Severity:
            if sev.value == val or sev.name.lower() == val or sev.value in val:
                return sev
        return Severity.MEDIUM

    def _parse_confidence(self, raw_conf: Any) -> Confidence:
        """Safely parse arbitrary confidence string into Confidence enum."""
        if isinstance(raw_conf, Confidence):
            return raw_conf
        val = str(raw_conf).strip().lower()
        for conf in Confidence:
            if conf.value == val or conf.name.lower() == val or conf.value in val:
                return conf
        return Confidence.HIGH

    def build_messages(
        self,
        source_file: SourceFile,
        context_snippets: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, str]]:
        """Construct structured prompt instructing LLM to detect semantic and cross-file vulnerabilities."""
        system_prompt = (
            "You are an expert static application security testing (SAST) auditor. "
            "Analyze the provided source code for deep, semantic security vulnerabilities that cannot be easily caught by static regexes. "
            "Focus on: Server-Side Request Forgery (SSRF), Insecure Deserialization, Broken Access Control, IDOR, "
            "Privilege Escalation, Path Traversal, Complex Injections, and Race Conditions.\n\n"
            "When 'Related Cross-File Context' is provided, trace how untrusted data or unvalidated dependencies flow between the files "
            "to detect cross-file vulnerabilities (e.g. taint propagation, missing authorization in caller, unsafe query execution in callee).\n\n"
            "Return ONLY a valid JSON object matching this schema:\n"
            "{\n"
            '  "vulnerabilities": [\n'
            "    {\n"
            '      "title": "Short Vulnerability Title",\n'
            '      "description": "Detailed explanation of the flaw, exploit mechanism, and data flow.",\n'
            '      "cwe_id": "CWE-XXX",\n'
            '      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
            '      "confidence": "HIGH|MEDIUM|LOW",\n'
            '      "start_line": <integer 1-indexed>,\n'
            '      "end_line": <integer 1-indexed>,\n'
            '      "code_snippet": "vulnerable code line(s)",\n'
            '      "recommendation": "Concrete remediation guidance.",\n'
            '      "is_cross_file": true|false,\n'
            '      "related_files": ["path/to/related/file.py"]\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "If no vulnerabilities are present, return {\"vulnerabilities\": []}."
        )

        code_content = source_file.content
        if len(code_content) > self.max_file_size_chars:
            code_content = code_content[: self.max_file_size_chars] + "\n# [TRUNCATED DUE TO FILE SIZE]"

        user_content = (
            f"File Path: {source_file.relative_path or Path(source_file.file_path).name}\n"
            f"Language: {source_file.language.value if hasattr(source_file.language, 'value') else str(source_file.language)}\n\n"
            f"Source Code:\n```\n{code_content}\n```\n"
        )

        if context_snippets:
            user_content += "\nRelated Cross-File Context:\n"
            for ctx in context_snippets:
                ref_file = ctx.get("file", "unknown")
                ref_snippet = ctx.get("snippet", "")
                user_content += f"- Context from {ref_file}:\n```\n{ref_snippet}\n```\n"

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

    def _parse_findings(
        self,
        raw_response: Dict[str, Any],
        source_file: SourceFile,
        context_snippets: Optional[List[Dict[str, Any]]] = None,
    ) -> List[AuditFinding]:
        """Convert structured JSON dictionary into normalized AuditFinding objects."""
        findings: List[AuditFinding] = []
        raw_list = raw_response.get("vulnerabilities") or raw_response.get("findings") or []
        
        if isinstance(raw_response, list):
            raw_list = raw_response

        # Extract available related filenames for cross-file attribution
        context_files = [c.get("file") for c in (context_snippets or []) if c.get("file")]

        for item in raw_list:
            if not isinstance(item, dict):
                continue

            title = str(item.get("title") or "Potential Security Vulnerability").strip()
            desc = str(item.get("description") or "Security vulnerability detected by AI analysis.").strip()
            cwe_id = str(item.get("cwe_id")).strip() if item.get("cwe_id") else None
            sev = self._parse_severity(item.get("severity", "medium"))
            conf = self._parse_confidence(item.get("confidence", "high"))
            
            try:
                start_line = int(item.get("start_line") or item.get("line_number") or 1)
            except (ValueError, TypeError):
                start_line = 1

            try:
                end_line = int(item.get("end_line") or start_line)
            except (ValueError, TypeError):
                end_line = start_line

            try:
                start_col = int(item.get("start_column") or item.get("column") or 0)
                start_col = start_col if start_col > 0 else None
            except (ValueError, TypeError):
                start_col = None

            try:
                end_col = int(item.get("end_column") or start_col or 0)
                end_col = end_col if end_col > 0 else None
            except (ValueError, TypeError):
                end_col = None

            snippet = item.get("code_snippet") or item.get("snippet")
            rec = item.get("recommendation") or "Review and sanitize input."

            rel_path = str(source_file.relative_path or Path(source_file.file_path).name).replace("\\", "/")

            # Metadata tracking for cross-file auditing
            meta: Dict[str, Any] = {"ai_auditor": "groq_llm"}
            is_cross_file = bool(item.get("is_cross_file") or context_files)
            if is_cross_file:
                meta["cross_file"] = True
                meta["related_files"] = item.get("related_files") or context_files

            finding = AuditFinding(
                title=title,
                description=desc,
                category=FindingCategory.SECURITY,
                severity=sev,
                confidence=conf,
                file_path=source_file.file_path,
                relative_file_path=rel_path,
                start_line=start_line,
                end_line=end_line,
                start_column=start_col,
                end_column=end_col,
                code_snippet=snippet,
                cwe_id=cwe_id,
                recommendation=rec,
                source="ai_llm",
                metadata=meta,
            )
            if getattr(source_file, "content", None):
                finding.extract_context_snippet(source_file.content)

            findings.append(finding)

        return findings

    def analyze_file(
        self,
        source_file: SourceFile,
        context_snippets: Optional[List[Dict[str, Any]]] = None,
        all_project_files: Optional[List[SourceFile]] = None,
        project_id: Optional[str] = None,
    ) -> List[AuditFinding]:
        """Perform semantic and cross-file security vulnerability analysis on a source file."""
        if not source_file.content or not source_file.content.strip():
            return []

        if not self.llm_client.is_available():
            return []

        # Automatically resolve cross-file dependencies if resolver & project files are provided
        effective_context = context_snippets
        if effective_context is None and self.cross_file_resolver and all_project_files:
            effective_context = self.cross_file_resolver.bundle_cross_file_context(
                source_file=source_file,
                all_project_files=all_project_files,
                project_id=project_id,
            )

        messages = self.build_messages(source_file, context_snippets=effective_context)

        try:
            raw_response = self.llm_client.chat_json(
                messages=messages,
                temperature=self.temperature,
            )
            if not isinstance(raw_response, dict):
                return []

            return self._parse_findings(raw_response, source_file, context_snippets=effective_context)

        except Exception:
            return []

    def analyze_component(
        self,
        component: CodeComponent,
        source_file: SourceFile,
    ) -> List[AuditFinding]:
        """Analyze a single isolated function or class component for security flaws."""
        code = getattr(component, "source_content", "")
        if not code or not code.strip():
            return []

        virtual_file = SourceFile(
            file_path=source_file.file_path,
            relative_path=source_file.relative_path,
            language=source_file.language,
            content=code,
        )

        findings = self.analyze_file(virtual_file)
        
        # Adjust line numbers relative to the enclosing component start line
        for finding in findings:
            offset = component.start_line - 1
            finding.start_line += offset
            finding.end_line += offset

        return findings
