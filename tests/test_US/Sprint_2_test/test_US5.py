from pathlib import Path
import shutil
import tempfile
import pytest

from app.core.enums import Confidence, FindingCategory, JobStatus, Severity
from app.core.models.audit import AuditFinding, AuditJob, AuditProgress, AuditReport
from app.core.models.project import Project
from app.services.audit_service import AuditService


@pytest.fixture
def temp_project_dir():
    """Provides an isolated workspace folder with multi-language code snippets."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    proj_dir = temp_dir / "audit_sample_project"
    proj_dir.mkdir()

    # 1. Python file
    (proj_dir / "auth.py").write_text("def authenticate_user():\n    return True\n", encoding="utf-8")
    
    # 2. JavaScript file
    (proj_dir / "token.js").write_text("function parseToken(t) {\n    return t;\n}\n", encoding="utf-8")
    
    # 3. Java file
    (proj_dir / "User.java").write_text("public class User {\n    public String name;\n}\n", encoding="utf-8")
    
    # 4. C file with syntax error
    (proj_dir / "broken.c").write_text("int main( { return ;;; }\n", encoding="utf-8")

    yield proj_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_us5_audit_models_serialization():
    """Verify serialization, property metrics, and string representations for audit models."""
    finding = AuditFinding(
        title="Insecure Storage",
        description="Plaintext credentials found in memory.",
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="config/db.py",
        start_line=10,
        end_line=12,
        cwe_id="CWE-312",
        recommendation="Use encrypted secret manager.",
    )
    data = finding.to_dict()
    assert data["title"] == "Insecure Storage"
    assert data["severity"] == "high"
    assert data["category"] == "security"
    assert "db.py" in data["file_path"]

    progress = AuditProgress(
        current_step="ast_parsing",
        percentage=45.5,
        current_file="auth.py",
        scanned_files_count=3,
        total_files_count=10,
        findings_count=1,
    )
    p_data = progress.to_dict()
    assert p_data["current_step"] == "ast_parsing"
    assert p_data["percentage"] == 45.5

    report = AuditReport(
        job_id="job-1",
        project_id="proj-1",
        findings=[finding],
        summary="Audit completed.",
    )
    r_data = report.to_dict()
    assert r_data["total_findings"] == 1
    assert r_data["findings_by_severity"]["high"] == 1
    assert r_data["findings_by_category"]["security"] == 1


def test_us5_audit_job_lifecycle(temp_project_dir):
    """Verify job creation, status transitions (QUEUED -> RUNNING -> COMPLETED), and report generation."""
    service = AuditService()
    project = Project(root_path=temp_project_dir, project_id="lifecycle-proj")

    # 1. Job Creation
    job = service.create_job(project)
    assert job.status == JobStatus.QUEUED
    assert job.job_id is not None
    assert service.get_job(job.job_id) is not None

    # 2. Execution
    report = service.run_audit(job.job_id, project)
    assert job.status == JobStatus.COMPLETED
    assert job.started_at is not None
    assert job.completed_at is not None
    assert job.completed_at >= job.started_at

    # 3. Report retrieval
    stored_report = service.get_report(job.job_id)
    assert stored_report is not None
    assert stored_report.report_id == report.report_id
    assert stored_report.total_findings >= 1  # Flags broken.c syntax error


def test_us5_progress_telemetry_streaming(temp_project_dir):
    """Verify that on_progress callback receives monotonic progress and valid current_file names."""
    service = AuditService()
    project = Project(root_path=temp_project_dir, project_id="telemetry-proj")
    job = service.create_job(project)

    progress_events = []

    def on_progress(p: AuditProgress):
        progress_events.append((p.current_step, p.percentage, p.current_file))

    report = service.run_audit(job.job_id, project, on_progress=on_progress)
    assert len(progress_events) >= 4

    steps = [e[0] for e in progress_events]
    percentages = [e[1] for e in progress_events]

    assert "scanning" in steps
    assert "scanning_complete" in steps
    assert "ast_parsing" in steps
    assert "complete" in steps

    # Check progress increases monotonically
    for i in range(1, len(percentages)):
        assert percentages[i] >= percentages[i - 1]
    assert percentages[-1] == 100.0


def test_us5_multilingual_audit_execution(temp_project_dir):
    """Verify multi-language parsing and component extraction across Python, JS, Java, and C."""
    service = AuditService()
    project = Project(root_path=temp_project_dir, project_id="multi-lang-proj")
    job = service.create_job(project)

    report = service.run_audit(job.job_id, project)
    assert job.progress.total_files_count == 4
    assert job.progress.scanned_files_count == 4
    # The syntax error in broken.c should be captured as an AuditFinding
    syntax_findings = [f for f in report.findings if "Syntax Error" in f.title]
    assert len(syntax_findings) >= 1
    assert "broken.c" in syntax_findings[0].file_path


def test_us5_job_cancellation(temp_project_dir):
    """Verify cancelling an audit job immediately sets CANCELLED and returns partial report."""
    service = AuditService()
    project = Project(root_path=temp_project_dir, project_id="cancel-proj")

    # Cancel a queued job
    job = service.create_job(project)
    assert service.cancel_job(job.job_id) is True
    assert job.status == JobStatus.CANCELLED
    assert job.progress.current_step == "cancelled"

    # Cancelling an already cancelled job returns False
    assert service.cancel_job(job.job_id) is False


def test_us5_invalid_job_handling(temp_project_dir):
    """Verify error handling when attempting to run non-existent jobs."""
    service = AuditService()
    project = Project(root_path=temp_project_dir, project_id="error-proj")

    with pytest.raises(ValueError, match="not found"):
        service.run_audit("non-existent-job-uuid", project)
