import threading
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Response, status
from fastapi.responses import JSONResponse

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.quality_analyzer import CodeQualityAnalyzer
from app.analysis.rule_engine import RuleEngine
from app.api.routes.project import project_service
from app.api.schemas import (
    AuditFindingResponse,
    AuditJobResponse,
    AuditResultsResponse,
    AuditStartRequest,
)
from app.core.enums import Severity
from app.core.models.audit import AuditFinding, AuditJob, AuditReport
from app.infrastructure.filesystem import LocalFileSystem
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/audit", tags=["Audit"])

# Singleton AuditService initialized with production static and AI analyzers
_fs = LocalFileSystem()
_rule_engine = RuleEngine()
_quality_analyzer = CodeQualityAnalyzer()
_ai_analyzer = AIVulnerabilityAnalyzer()

audit_service = AuditService(
    filesystem=_fs,
    rule_engine=_rule_engine,
    quality_analyzer=_quality_analyzer,
    ai_analyzer=_ai_analyzer,
)


def _serialize_finding(f: AuditFinding) -> AuditFindingResponse:
    """Map domain AuditFinding to Pydantic AuditFindingResponse."""
    d = f.to_dict()
    return AuditFindingResponse(
        finding_id=f.finding_id,
        title=f.title,
        description=f.description,
        category=f.category.value if hasattr(f.category, "value") else str(f.category),
        severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
        file_path=str(f.file_path),
        relative_file_path=str(f.relative_file_path) if f.relative_file_path else None,
        start_line=f.start_line,
        end_line=f.end_line,
        start_column=f.start_column,
        end_column=f.end_column,
        code_snippet=f.code_snippet,
        cwe_id=f.cwe_id,
        risk_score=float(f.risk_score),
        recommendation=f.recommendation,
        remediation_code=f.remediation_code,
        remediation_steps=f.remediation_steps or [],
        risk_explanation=f.risk_explanation,
        exploit_scenario=f.exploit_scenario,
        evidence=f.evidence or {},
        source=f.source or "static_sast",
        metadata=f.metadata or {},
    )


def _serialize_job(job: AuditJob) -> AuditJobResponse:
    """Map domain AuditJob to Pydantic AuditJobResponse."""
    d = job.to_dict()
    return AuditJobResponse(
        job_id=job.job_id,
        project_id=job.project_id,
        status=job.status.value,
        progress_percentage=round(job.progress.percentage, 1),
        current_stage=job.progress.current_step,
        files_scanned=job.progress.scanned_files_count,
        total_files=job.progress.total_files_count,
        findings_count=job.progress.findings_count,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        error_message=job.error_message,
        warnings=getattr(job, "warnings", []),
    )


def _execute_audit_in_background(
    job_id: str,
    project,
    enable_ai: bool = False,
    enable_smells: bool = True,
    include_tests: bool = False,
):
    """Worker function executed in background thread."""
    try:
        audit_service.run_audit(
            job_id=job_id,
            project=project,
            enable_ai=enable_ai,
            enable_smells=enable_smells,
            include_tests=include_tests,
        )
    except Exception:
        # Errors are captured directly in the AuditJob state
        pass


@router.post("/start", response_model=AuditJobResponse, status_code=status.HTTP_202_ACCEPTED)
def start_audit(req: AuditStartRequest, background_tasks: BackgroundTasks):
    """
    Initiate an automated code quality & security audit job in the background.
    Returns immediately with the created job ID so the frontend can poll live progress.
    """
    project = project_service.get_project(req.project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{req.project_id}' not found. Please register the project first.",
        )

    # Create job in PENDING state
    job = audit_service.create_job(project)

    # Launch audit in background
    thread = threading.Thread(
        target=_execute_audit_in_background,
        args=(job.job_id, project, req.enable_ai, req.enable_smells, req.include_tests),
        daemon=True,
    )
    thread.start()

    return _serialize_job(job)


@router.get("/jobs/{job_id}", response_model=AuditJobResponse)
def get_job_status(job_id: str):
    """
    Poll the live execution status and progress percentage of an audit job.
    Used by the UI Live Progress HUD.
    """
    job = audit_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Audit job '{job_id}' not found.")
    return _serialize_job(job)


@router.get("/jobs/{job_id}/results", response_model=AuditResultsResponse)
def get_audit_results(job_id: str):
    """
    Retrieve consolidated findings, severity counts, and overall health score
    for a completed audit job.
    """
    job = audit_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Audit job '{job_id}' not found.")

    report = audit_service.get_report(job_id)
    if not report:
        if job.status.value in ("pending", "in_progress"):
            raise HTTPException(
                status_code=status.HTTP_425_TOO_EARLY,
                detail=f"Audit job '{job_id}' is still in progress ({job.progress.percentage:.1f}%).",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No audit report generated for job '{job_id}'. Status: {job.status.value}.",
        )

    # Compute severity counts
    sev_counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0, Severity.INFO: 0}
    for f in report.findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity.MEDIUM
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Project health score: 100 - (CRIT*20 + HIGH*10 + MED*4 + LOW*1) clamped to [0.0, 100.0]
    penalty = (
        sev_counts[Severity.CRITICAL] * 20.0
        + sev_counts[Severity.HIGH] * 10.0
        + sev_counts[Severity.MEDIUM] * 4.0
        + sev_counts[Severity.LOW] * 1.0
    )
    health_score = max(0.0, min(100.0, round(100.0 - penalty, 1)))

    serialized_findings = [_serialize_finding(f) for f in report.findings]

    return AuditResultsResponse(
        job_id=report.job_id,
        project_id=report.project_id,
        health_score=health_score,
        findings_count=len(report.findings),
        critical_count=sev_counts[Severity.CRITICAL],
        high_count=sev_counts[Severity.HIGH],
        medium_count=sev_counts[Severity.MEDIUM],
        low_count=sev_counts[Severity.LOW],
        info_count=sev_counts[Severity.INFO],
        findings=serialized_findings,
        summary_markdown=report.to_markdown() if hasattr(report, "to_markdown") else None,
    )


@router.get("/jobs/{job_id}/sarif")
def download_sarif(job_id: str):
    """
    Export audit findings in industry-standard SARIF v2.1.0 format.
    Suitable for importing directly into VS Code, GitHub Security, or CI/CD pipelines.
    """
    report = audit_service.get_report(job_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report for job '{job_id}' not found.")

    sarif_data = report.to_sarif()
    return JSONResponse(
        content=sarif_data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="codeshield_{job_id}.sarif"'},
    )


@router.get("/jobs/{job_id}/markdown")
def download_markdown(job_id: str):
    """
    Export a human-readable Markdown summary report of all detected vulnerabilities.
    """
    report = audit_service.get_report(job_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report for job '{job_id}' not found.")

    md_content = report.to_markdown()
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="codeshield_{job_id}_report.md"'},
    )


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    """Cancel an in-progress audit job."""
    success = audit_service.cancel_job(job_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job '{job_id}'. It may have already completed or failed.",
        )
    return {"job_id": job_id, "status": "cancelled", "message": "Audit job cancelled successfully."}
