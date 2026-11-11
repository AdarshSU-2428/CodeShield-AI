from pathlib import Path
import pytest
from unittest.mock import MagicMock

from app.core.enums import Confidence, FileStatus, FindingCategory, JobStatus, Language, Severity
from app.core.models.audit import AuditFinding, AuditReport
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.services.audit_service import AuditService


def test_us10_severity_weight_and_confidence_scoring():
    """US 10: Verifies deterministic CVSS-aligned risk_score calculation based on severity & confidence."""
    # Critical Severity (10.0) * High Confidence (1.0) = 10.0
    f_crit_high = AuditFinding(
        title="Critical RCE",
        description="Remote code execution flaw",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    )
    assert f_crit_high.risk_score == 10.0
    assert f_crit_high.priority_score == 10.0

    # Critical Severity (10.0) * Medium Confidence (0.8) = 8.0
    f_crit_med = AuditFinding(
        title="Likely RCE",
        description="Possible remote code execution",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
    )
    assert f_crit_med.risk_score == 8.0

    # High Severity (8.0) * High Confidence (1.0) = 8.0
    f_high_high = AuditFinding(
        title="SQL Injection",
        description="Unsanitized query formatting",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )
    assert f_high_high.risk_score == 8.0

    # Medium Severity (5.0) * Low Confidence (0.6) = 3.0
    f_med_low = AuditFinding(
        title="Information Disclosure",
        description="Header leak",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
    )
    assert f_med_low.risk_score == 3.0

    # Info Severity (1.0) * Low Confidence (0.6) = 0.6
    f_info = AuditFinding(
        title="Todo Comment",
        description="Leftover todo",
        severity=Severity.INFO,
        confidence=Confidence.LOW,
    )
    assert f_info.risk_score == 0.6


def test_us10_custom_risk_score_override():
    """US 10: Verifies manual override of risk_score and clamping between 0.0 and 10.0."""
    f_custom = AuditFinding(
        title="Custom Score Finding",
        description="Explicit score assigned",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        risk_score=9.75,
    )
    assert f_custom.risk_score == 9.75

    # Setter update
    f_custom.risk_score = 4.2
    assert f_custom.risk_score == 4.2

    # Clamping out-of-range values
    f_custom.risk_score = 999.0
    assert f_custom.risk_score == 10.0

    f_custom.risk_score = -5.0
    assert f_custom.risk_score == 0.0


def test_us10_audit_finding_serialization():
    """US 10: Verifies risk_score and priority_score serialization in to_dict()."""
    finding = AuditFinding(
        title="Hardcoded Credential",
        description="AWS access key exposed",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="config/aws.py",
        start_line=12,
        end_line=12,
    )

    data = finding.to_dict()
    assert "risk_score" in data
    assert "priority_score" in data
    assert data["risk_score"] == 8.0
    assert data["priority_score"] == 8.0


def test_us10_report_get_prioritized_findings():
    """US 10: Verifies AuditReport returns findings strictly sorted by risk_score in descending order."""
    f1 = AuditFinding(title="F1-Low", description="", severity=Severity.LOW, confidence=Confidence.LOW)      # 1.5
    f2 = AuditFinding(title="F2-Crit", description="", severity=Severity.CRITICAL, confidence=Confidence.HIGH) # 10.0
    f3 = AuditFinding(title="F3-Med", description="", severity=Severity.MEDIUM, confidence=Confidence.HIGH)   # 5.0
    f4 = AuditFinding(title="F4-High", description="", severity=Severity.HIGH, confidence=Confidence.HIGH)     # 8.0

    report = AuditReport(
        job_id="job-prioritize",
        project_id="proj-1",
        findings=[f1, f2, f3, f4],
    )

    prioritized = report.get_prioritized_findings()
    titles = [f.title for f in prioritized]
    assert titles == ["F2-Crit", "F4-High", "F3-Med", "F1-Low"]
    assert report.max_risk_score == 10.0
    assert report.average_risk_score == round((1.5 + 10.0 + 5.0 + 8.0) / 4, 2)


def test_us10_report_filter_by_min_severity_and_score():
    """US 10: Verifies filtering prioritized findings by min_severity and min_risk_score."""
    f_crit = AuditFinding(title="Crit", description="", severity=Severity.CRITICAL, confidence=Confidence.HIGH)  # 10.0
    f_high = AuditFinding(title="High", description="", severity=Severity.HIGH, confidence=Confidence.HIGH)      # 8.0
    f_med = AuditFinding(title="Med", description="", severity=Severity.MEDIUM, confidence=Confidence.HIGH)       # 5.0
    f_low = AuditFinding(title="Low", description="", severity=Severity.LOW, confidence=Confidence.LOW)           # 1.5

    report = AuditReport(
        job_id="job-filter",
        project_id="proj-1",
        findings=[f_low, f_med, f_high, f_crit],
    )

    # Filter min_severity=HIGH (should only return CRITICAL and HIGH)
    high_or_above = report.get_prioritized_findings(min_severity=Severity.HIGH)
    assert [f.title for f in high_or_above] == ["Crit", "High"]

    # Filter min_risk_score=7.0
    score_filtered = report.get_prioritized_findings(min_risk_score=7.0)
    assert [f.title for f in score_filtered] == ["Crit", "High"]


def test_us10_findings_grouped_by_priority():
    """US 10: Verifies findings_by_priority groups findings into severity buckets sorted internally."""
    f_crit1 = AuditFinding(title="Crit-1", description="", severity=Severity.CRITICAL, confidence=Confidence.HIGH)   # 10.0
    f_crit2 = AuditFinding(title="Crit-2", description="", severity=Severity.CRITICAL, confidence=Confidence.MEDIUM) # 8.0
    f_med = AuditFinding(title="Med", description="", severity=Severity.MEDIUM, confidence=Confidence.HIGH)          # 5.0

    report = AuditReport(
        job_id="job-group",
        project_id="proj-1",
        findings=[f_crit2, f_med, f_crit1],
    )

    grouped = report.findings_by_priority
    assert len(grouped["critical"]) == 2
    assert grouped["critical"][0].title == "Crit-1"  # 10.0 comes before 8.0
    assert grouped["critical"][1].title == "Crit-2"
    assert len(grouped["medium"]) == 1
    assert len(grouped["low"]) == 0


def test_us10_audit_service_end_to_end_prioritization():
    """US 10: Verifies AuditService.run_audit() automatically sorts final findings by priority."""
    mock_scanner = MagicMock()
    mock_fs = MagicMock()
    mock_rule_engine = MagicMock()

    f_low = AuditFinding(title="Low Finding", description="", severity=Severity.LOW, confidence=Confidence.LOW)
    f_crit = AuditFinding(title="Crit Finding", description="", severity=Severity.CRITICAL, confidence=Confidence.HIGH)
    f_high = AuditFinding(title="High Finding", description="", severity=Severity.HIGH, confidence=Confidence.HIGH)

    mock_rule_engine.analyze_file.return_value = [f_low, f_crit, f_high]

    sf = SourceFile(
        file_path="app/main.py",
        relative_path="main.py",
        language=Language.PYTHON,
        status=FileStatus.UNCHANGED,
        content="x = 1\n",
    )

    mock_scanner.scan_project.return_value = [sf]
    mock_fs.exists.return_value = True
    mock_fs.read_text.return_value = "x = 1\n"

    service = AuditService(
        scanner=mock_scanner,
        filesystem=mock_fs,
        rule_engine=mock_rule_engine,
        auto_save_report=False,
    )

    project = Project(root_path="fake_project", name="PrioritizeTest")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    report_titles = [f.title for f in report.findings]
    assert report_titles[0] == "Crit Finding"
    assert report_titles[1] == "High Finding"
    assert report_titles[2] == "Low Finding"