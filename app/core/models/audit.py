from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.core.enums import Confidence, FindingCategory, JobStatus, Severity


SEVERITY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value: 10.0,
    Severity.HIGH.value: 8.0,
    Severity.MEDIUM.value: 5.0,
    Severity.LOW.value: 2.5,
    Severity.INFO.value: 1.0,
}

CONFIDENCE_MULTIPLIERS: Dict[str, float] = {
    Confidence.HIGH.value: 1.0,
    Confidence.MEDIUM.value: 0.8,
    Confidence.LOW.value: 0.6,
}


class AuditFinding:
    """Normalized security vulnerability or code quality finding."""

    def __init__(
        self,
        title: str,
        description: str,
        category: FindingCategory = FindingCategory.SECURITY,
        severity: Severity = Severity.MEDIUM,
        confidence: Confidence = Confidence.HIGH,
        file_path: Union[str, Path] = '',
        start_line: int = 1,
        end_line: int = 1,
        code_snippet: Optional[str] = None,
        cwe_id: Optional[str] = None,
        recommendation: Optional[str] = None,
        source: str = 'rule',
        finding_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        rule_id: Optional[str] = None,
        line_number: Optional[int] = None,
        affected_files: Optional[List[str]] = None,
        context_snippet: Optional[str] = None,
        start_column: Optional[int] = None,
        end_column: Optional[int] = None,
        relative_file_path: Optional[str] = None,
        snippet: Optional[str] = None,
        risk_score: Optional[float] = None,
        evidence: Optional[Dict[str, Any]] = None,
        risk_explanation: Optional[str] = None,
        exploit_scenario: Optional[str] = None,
        remediation_code: Optional[str] = None,
        remediation_steps: Optional[List[str]] = None,
        related_components: Optional[List[Dict[str, Any]]] = None,
    ):
        self.finding_id = finding_id if finding_id else str(uuid.uuid4())
        self.title = title
        self.description = description
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.file_path = Path(file_path).as_posix() if file_path else ""
        if relative_file_path:
            self.relative_file_path = Path(relative_file_path).as_posix()
        elif self.file_path and not Path(self.file_path).is_absolute():
            self.relative_file_path = self.file_path
        else:
            self.relative_file_path = self.file_path

        raw_start = int(line_number) if line_number is not None else int(start_line)
        raw_end = int(line_number) if line_number is not None else int(end_line)
        self.start_line = max(1, raw_start)
        self.end_line = max(self.start_line, raw_end)

        self.start_column = max(1, int(start_column)) if start_column is not None else None
        if end_column is not None:
            self.end_column = max(self.start_column or 1, int(end_column))
        else:
            self.end_column = None

        self.code_snippet = snippet if (snippet is not None and not code_snippet) else code_snippet
        self.context_snippet = context_snippet
        if affected_files is not None:
            self.affected_files = [Path(f).as_posix() for f in affected_files]
        else:
            self.affected_files = [self.file_path] if self.file_path else []
        self.cwe_id = cwe_id
        self.recommendation = recommendation
        self.source = source
        self.metadata = metadata if metadata else {}
        if rule_id:
            self.metadata['rule_id'] = rule_id

        # Calculate or assign deterministic risk score (0.0 to 10.0 scale)
        if risk_score is not None:
            self._risk_score = round(max(0.0, min(10.0, float(risk_score))), 2)
        else:
            self._risk_score = self._compute_risk_score()

        # User Story 12: Finding Evidence & Risk Explanations
        self.evidence: Dict[str, Any] = evidence if evidence is not None else {}
        self.risk_explanation: Optional[str] = risk_explanation
        self.exploit_scenario: Optional[str] = exploit_scenario

        # User Story 14: Secure Remediation Generation
        self.remediation_code: Optional[str] = remediation_code
        self.remediation_steps: List[str] = list(remediation_steps) if remediation_steps is not None else []

        # User Story 17: Contextual Findings with Multi-Component Linking
        self.related_components: List[Dict[str, Any]] = (
            [dict(c) for c in related_components] if related_components is not None else []
        )

    def _compute_risk_score(self) -> float:
        """Compute standard CVSS-aligned risk score based on severity and confidence."""
        sev_key = self.severity.value if hasattr(self.severity, "value") else str(self.severity).lower()
        conf_key = self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence).lower()

        base_weight = SEVERITY_WEIGHTS.get(sev_key, 5.0)
        multiplier = CONFIDENCE_MULTIPLIERS.get(conf_key, 1.0)
        return round(base_weight * multiplier, 2)

    @property
    def risk_score(self) -> float:
        """Return the calculated risk/priority score (0.0 - 10.0)."""
        return self._risk_score

    @risk_score.setter
    def risk_score(self, value: float) -> None:
        self._risk_score = round(max(0.0, min(10.0, float(value))), 2)

    @property
    def priority_score(self) -> float:
        """Alias for risk_score."""
        return self._risk_score

    @property
    def line_number(self) -> int:
        return self.start_line

    @property
    def snippet(self) -> Optional[str]:
        """Convenience alias for code_snippet."""
        return self.code_snippet

    @snippet.setter
    def snippet(self, val: Optional[str]) -> None:
        self.code_snippet = val

    def add_related_component(
        self,
        component_name: str,
        component_type: str,
        file_path: Union[str, Path],
        line_number: int = 1,
        relation: str = "related",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a linked repository component (function, class, caller, callee, import)."""
        comp = {
            "component_name": component_name,
            "component_type": component_type,
            "file_path": Path(file_path).as_posix() if file_path else "",
            "line_number": max(1, int(line_number)),
            "relation": relation,
            "metadata": metadata if metadata is not None else {},
        }
        self.related_components.append(comp)

    def extract_context_snippet(self, file_content: str, context_lines: int = 2) -> str:
        """
        Extract code snippet surrounding [start_line, end_line] with line numbers and a pointer marker '>'.
        """
        if not file_content:
            return ""
        lines = file_content.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return ""

        # Clamp lines
        start_idx = max(1, self.start_line)
        end_idx = min(total_lines, max(start_idx, self.end_line))

        window_start = max(1, start_idx - context_lines)
        window_end = min(total_lines, end_idx + context_lines)

        formatted_lines = []
        for line_no in range(window_start, window_end + 1):
            line_text = lines[line_no - 1]
            marker = ">" if (start_idx <= line_no <= end_idx) else " "
            formatted_lines.append(f"{marker} {line_no:4d} | {line_text}")

        self.context_snippet = "\n".join(formatted_lines)
        if not self.code_snippet:
            self.code_snippet = "\n".join(lines[start_idx - 1:end_idx])

        return self.context_snippet

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to JSON-serializable dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value if hasattr(self.category, "value") else str(self.category),
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
            "risk_score": self.risk_score,
            "priority_score": self.priority_score,
            "file_path": self.file_path,
            "relative_file_path": self.relative_file_path,
            "affected_files": self.affected_files,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
            "code_snippet": self.code_snippet,
            "snippet": self.snippet,
            "context_snippet": self.context_snippet,
            "cwe_id": self.cwe_id,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "risk_explanation": self.risk_explanation,
            "exploit_scenario": self.exploit_scenario,
            "remediation_code": self.remediation_code,
            "remediation_steps": self.remediation_steps,
            "related_components": self.related_components,
            "source": self.source,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"<AuditFinding title='{self.title}' severity='{self.severity}' risk={self.risk_score} file='{self.file_path}:{self.start_line}'>"


class AuditProgress:
    """Live progress telemetry for real-time WebSocket streaming."""

    def __init__(
        self,
        current_step: str = "queued",
        percentage: float = 0.0,
        current_file: Optional[str] = None,
        scanned_files_count: int = 0,
        total_files_count: int = 0,
        findings_count: int = 0,
    ):
        self.current_step = current_step
        self.percentage = float(percentage)
        self.current_file = current_file
        self.scanned_files_count = int(scanned_files_count)
        self.total_files_count = int(total_files_count)
        self.findings_count = int(findings_count)

    def to_dict(self) -> Dict[str, Any]:
        """Convert telemetry to JSON-serializable dictionary."""
        return {
            "current_step": self.current_step,
            "percentage": round(self.percentage, 1),
            "current_file": self.current_file,
            "scanned_files_count": self.scanned_files_count,
            "total_files_count": self.total_files_count,
            "findings_count": self.findings_count,
        }

    def __repr__(self) -> str:
        return f"<AuditProgress step='{self.current_step}' {self.percentage:.1f}%>"


class AuditJob:
    """Represents an ongoing or completed audit job."""

    def __init__(
        self,
        job_id: Optional[str] = None,
        project_id: str = "",
        status: JobStatus = JobStatus.QUEUED,
        created_at: Optional[datetime] = None,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        error_message: Optional[str] = None,
        progress: Optional[AuditProgress] = None,
        findings: Optional[List[AuditFinding]] = None,
    ):
        self.job_id = job_id if job_id else str(uuid.uuid4())
        self.project_id = str(project_id)
        self.status = status
        self.created_at = created_at if created_at else datetime.now(timezone.utc)
        self.started_at = started_at
        self.completed_at = completed_at
        self.error_message = error_message
        self.progress = progress if progress else AuditProgress()
        self.findings = findings if findings else []

    def to_dict(self) -> Dict[str, Any]:
        """Convert job representation to JSON-friendly dictionary."""
        return {
            "job_id": self.job_id,
            "project_id": self.project_id,
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "progress": self.progress.to_dict(),
            "findings_count": len(self.findings),
        }

    def __repr__(self) -> str:
        return f"<AuditJob id='{self.job_id}' status='{self.status}'>"


class AuditReport:
    """Consolidated audit outcome encompassing prioritized findings and metrics."""

    def __init__(
        self,
        job_id: str,
        project_id: str,
        findings: Optional[List[AuditFinding]] = None,
        report_id: Optional[str] = None,
        generated_at: Optional[datetime] = None,
        summary: str = "",
        warnings: Optional[List[str]] = None,
    ):
        self.report_id = report_id if report_id else str(uuid.uuid4())
        self.job_id = str(job_id)
        self.project_id = str(project_id)
        self.findings = findings if findings else []
        self.generated_at = generated_at if generated_at else datetime.now(timezone.utc)
        self.summary = summary
        self.warnings: List[str] = list(warnings) if warnings else []

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def findings_by_category(self) -> Dict[str, int]:
        counts = {c.value: 0 for c in FindingCategory}
        for f in self.findings:
            key = f.category.value if hasattr(f.category, "value") else str(f.category)
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def findings_by_priority(self) -> Dict[str, List[AuditFinding]]:
        """Group findings into priority categories sorted by risk score within each."""
        grouped: Dict[str, List[AuditFinding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            key = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
            if key in grouped:
                grouped[key].append(f)
            else:
                grouped.setdefault(key, []).append(f)
        for key in grouped:
            grouped[key].sort(key=lambda x: x.risk_score, reverse=True)
        return grouped

    @property
    def average_risk_score(self) -> float:
        """Return average risk score across all findings."""
        if not self.findings:
            return 0.0
        return round(sum(f.risk_score for f in self.findings) / len(self.findings), 2)

    @property
    def max_risk_score(self) -> float:
        """Return the highest individual risk score in the report."""
        if not self.findings:
            return 0.0
        return max(f.risk_score for f in self.findings)

    def get_prioritized_findings(
        self,
        min_severity: Optional[Severity] = None,
        min_risk_score: Optional[float] = None,
    ) -> List[AuditFinding]:
        """Return all findings sorted in descending order of risk score, with optional filtering."""
        filtered = self.findings

        if min_severity is not None:
            min_weight = SEVERITY_WEIGHTS.get(min_severity.value, 0.0)
            filtered = [
                f for f in filtered
                if SEVERITY_WEIGHTS.get(
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower(), 0.0
                ) >= min_weight
            ]

        if min_risk_score is not None:
            filtered = [f for f in filtered if f.risk_score >= min_risk_score]

        return sorted(filtered, key=lambda f: f.risk_score, reverse=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit report to dictionary."""
        return {
            "report_id": self.report_id,
            "job_id": self.job_id,
            "project_id": self.project_id,
            "generated_at": self.generated_at.isoformat(),
            "total_findings": self.total_findings,
            "average_risk_score": self.average_risk_score,
            "max_risk_score": self.max_risk_score,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "summary": self.summary,
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.get_prioritized_findings()],
        }

    def __repr__(self) -> str:
        return f"<AuditReport id='{self.report_id}' job='{self.job_id}' findings={self.total_findings} max_risk={self.max_risk_score}>"