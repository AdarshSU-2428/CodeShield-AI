from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.core.enums import Confidence, FindingCategory, JobStatus, Severity


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
    ):
        self.finding_id = finding_id if finding_id else str(uuid.uuid4())
        self.title = title
        self.description = description
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.file_path = Path(file_path).as_posix() if file_path else ""
        self.start_line = int(line_number) if line_number is not None else int(start_line)
        self.end_line = int(line_number) if line_number is not None else int(end_line)
        self.code_snippet = code_snippet
        self.cwe_id = cwe_id
        self.recommendation = recommendation
        self.source = source
        self.metadata = metadata if metadata else {}
        if rule_id:
            self.metadata['rule_id'] = rule_id

    @property
    def line_number(self) -> int:
        return self.start_line

    @property
    def rule_id(self) -> str:
        return self.metadata.get("rule_id", "")

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to JSON-serializable dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value if hasattr(self.category, "value") else str(self.category),
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "recommendation": self.recommendation,
            "source": self.source,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"<AuditFinding title='{self.title}' severity='{self.severity}' file='{self.file_path}:{self.start_line}'>"


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
        project_id: str,
        job_id: Optional[str] = None,
        status: JobStatus = JobStatus.QUEUED,
        progress: Optional[AuditProgress] = None,
        created_at: Optional[datetime] = None,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        error_message: Optional[str] = None,
        findings: Optional[List[AuditFinding]] = None,
    ):
        self.job_id = job_id if job_id else str(uuid.uuid4())
        self.project_id = str(project_id)
        self.status = status
        self.progress = progress if progress else AuditProgress()
        self.created_at = created_at if created_at else datetime.now(timezone.utc)
        self.started_at = started_at
        self.completed_at = completed_at
        self.error_message = error_message
        self.findings = findings if findings else []

    def to_dict(self) -> Dict[str, Any]:
        """Convert job model to dictionary."""
        return {
            "job_id": self.job_id,
            "project_id": self.project_id,
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "progress": self.progress.to_dict(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    def __repr__(self) -> str:
        return f"<AuditJob id='{self.job_id}' status='{self.status}' findings={len(self.findings)}>"


class AuditReport:
    """Consolidated summary report generated upon audit completion."""

    def __init__(
        self,
        job_id: str,
        project_id: str,
        findings: Optional[List[AuditFinding]] = None,
        report_id: Optional[str] = None,
        generated_at: Optional[datetime] = None,
        summary: str = "",
    ):
        self.report_id = report_id if report_id else str(uuid.uuid4())
        self.job_id = str(job_id)
        self.project_id = str(project_id)
        self.findings = findings if findings else []
        self.generated_at = generated_at if generated_at else datetime.now(timezone.utc)
        self.summary = summary

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

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit report to dictionary."""
        return {
            "report_id": self.report_id,
            "job_id": self.job_id,
            "project_id": self.project_id,
            "generated_at": self.generated_at.isoformat(),
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }

    def __repr__(self) -> str:
        return f"<AuditReport id='{self.report_id}' job='{self.job_id}' findings={self.total_findings}>"