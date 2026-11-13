import json
from pathlib import Path
import pytest

from app.ai.finding_validator import FindingValidator
from app.core.enums import Confidence, FindingCategory, Severity
from app.core.models.audit import AuditFinding, AuditReport


def test_us19_canonical_schema_validation_success():
    """Verify that a fully structured canonical AuditFinding passes schema validation cleanly."""
    finding = AuditFinding(
        title="Path Traversal Vulnerability",
        description="User input passed directly into open() without path validation.",
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app/storage.py",
        start_line=20,
        end_line=22,
        cwe_id="CWE-22",
        evidence={"vulnerable_call": "open(file_path)", "sink": "storage_read"},
        remediation_steps=[
            "Resolve absolute path using Path.resolve()",
            "Verify the target path begins within the safe storage root directory",
        ],
    )

    validator = FindingValidator()
    is_valid, errors = validator.validate_finding(finding)

    assert is_valid is True
    assert len(errors) == 0


def test_us19_canonical_schema_validation_rejection_on_corrupt_fields():
    """Verify FindingValidator detects and rejects missing fields, negative lines, and bad enums."""
    validator = FindingValidator()

    # Case 1: end_line < start_line
    bad_coords = {
        "title": "Bad Coords",
        "description": "Lines are inverted",
        "category": "security",
        "severity": "medium",
        "confidence": "high",
        "file_path": "a.py",
        "start_line": 50,
        "end_line": 20,
    }
    valid, errors = validator.validate_finding(bad_coords)
    assert valid is False
    assert any("Inconsistent line coordinates" in err for err in errors)

    # Case 2: Boolean line numbers (in Python, isinstance(True, int) is True!)
    bool_lines = {
        "title": "Boolean Line",
        "description": "Invalid boolean",
        "category": "security",
        "severity": "critical",
        "confidence": "high",
        "file_path": "a.py",
        "start_line": True,
        "end_line": 10,
    }
    valid, errors = validator.validate_finding(bool_lines)
    assert valid is False
    assert any("start_line" in err for err in errors)

    # Case 3: Invalid severity enum
    bad_sev = {
        "title": "Bad Severity",
        "description": "Unknown severity level",
        "category": "security",
        "severity": "super_catastrophic",
        "confidence": "high",
        "file_path": "a.py",
        "start_line": 1,
        "end_line": 5,
    }
    valid, errors = validator.validate_finding(bad_sev)
    assert valid is False
    assert any("Invalid severity" in err for err in errors)


def test_us19_unstructured_ai_response_normalization():
    """Verify FindingValidator normalizes unstructured/loose model dicts into valid AuditFinding."""
    raw_ai_payload = {
        "title": "  Insecure Deserialization   ",
        "description": "Pickle load used on untrusted network stream",
        "severity": "critical",
        "confidence": "high",
        "category": "security",
        "file": "worker/job.py",
        "start_line": "45",       # string instead of int
        "end_line": "48",         # string instead of int
        "remediation_steps": "Use JSON or protocol buffers instead of pickle", # str instead of list
        "cwe_id": "CWE-502",
    }

    validator = FindingValidator()
    finding = validator.normalize_raw_finding(raw_ai_payload)

    assert finding.title == "Insecure Deserialization"
    assert finding.severity == Severity.CRITICAL
    assert finding.start_line == 45
    assert finding.end_line == 48
    assert finding.file_path == "worker/job.py"
    assert finding.remediation_steps == ["Use JSON or protocol buffers instead of pickle"]
    assert isinstance(finding.evidence, dict)

    # Validate that normalized finding now passes strict schema checks
    is_valid, errors = validator.validate_finding(finding)
    assert is_valid is True
    assert len(errors) == 0


def test_us19_audit_report_sarif_v210_export_compliance():
    """Verify AuditReport.to_sarif() adheres to standard SARIF v2.1.0 specifications."""
    f1 = AuditFinding(
        title="SQL Injection",
        description="Unsanitized query in cursor.execute",
        category=FindingCategory.SECURITY,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="app/db.py",
        relative_file_path="app/db.py",
        start_line=10,
        end_line=12,
        cwe_id="CWE-89",
        code_snippet="cursor.execute('SELECT * FROM users WHERE id=' + uid)",
    )
    f2 = AuditFinding(
        title="Hardcoded Secret",
        description="API key embedded in source",
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app/config.py",
        relative_file_path="app/config.py",
        start_line=5,
        end_line=5,
        cwe_id="CWE-798",
    )
    f3 = AuditFinding(
        title="God Class Architectural Smell",
        description="Class exceeds 300 lines",
        category=FindingCategory.ARCHITECTURE,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        file_path="app/monolith.py",
        relative_file_path="app/monolith.py",
        start_line=1,
        end_line=300,
    )

    report = AuditReport(job_id="job-sarif-test", project_id="proj-sarif-test", findings=[f1, f2, f3])
    sarif = report.to_sarif()

    # 1. Spec compliance
    assert sarif["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeShield AI"
    assert len(run["tool"]["driver"]["rules"]) >= 2

    # 2. Results mapping
    results = run["results"]
    assert len(results) == 3

    # CRITICAL -> "error"
    res1 = next(r for r in results if r["ruleId"] == "CWE-89")
    assert res1["level"] == "error"
    assert res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/db.py"
    assert res1["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

    # MEDIUM -> "warning"
    res3 = next(r for r in results if "monolith.py" in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
    assert res3["level"] == "warning"

    # 3. Ensure JSON serializability
    json_str = json.dumps(sarif)
    assert len(json_str) > 0


def test_us19_audit_report_markdown_export():
    """Verify AuditReport.to_markdown() produces publication-ready Markdown audit report."""
    f = AuditFinding(
        title="Command Injection",
        description="os.system call with unescaped input",
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="server/cmd.py",
        start_line=14,
        end_line=15,
        cwe_id="CWE-78",
        risk_explanation="Attackers can execute arbitrary shell commands.",
        exploit_scenario="curl http://target/exec?cmd=rm+-rf",
        code_snippet="os.system(cmd)",
        remediation_code="subprocess.run(['safe_cmd', arg], check=True)",
        remediation_steps=["Replace os.system with subprocess.run", "Avoid shell=True"],
    )

    report = AuditReport(
        job_id="job-md-test",
        project_id="proj-md-test",
        findings=[f],
        warnings=["Cloud model took 2.5s"],
    )

    md = report.to_markdown()

    assert "# CodeShield AI Security & Quality Audit Report" in md
    assert "Job ID" in md
    assert "| **HIGH** | 1 |" in md
    assert "## System Warnings & Telemetry" in md
    assert "Cloud model took 2.5s" in md
    assert "[HIGH] Command Injection (Risk: 8.0/10)" in md
    assert "Attackers can execute arbitrary shell commands" in md
    assert "subprocess.run(['safe_cmd', arg], check=True)" in md
    assert "- Replace os.system with subprocess.run" in md


def test_us19_full_report_validation():
    """Verify FindingValidator.validate_report() validates consolidated audit reports."""
    f1 = AuditFinding(
        title="Valid Finding",
        description="Clean issue",
        file_path="test.py",
        start_line=1,
        end_line=2,
    )
    report = AuditReport(job_id="job-1", project_id="proj-1", findings=[f1])

    validator = FindingValidator()
    is_valid, errors = validator.validate_report(report)

    assert is_valid is True
    assert len(errors) == 0


def test_us19_empty_findings_sarif_and_markdown_graceful_handling():
    """Verify clean SARIF and Markdown exports when zero findings are detected."""
    clean_report = AuditReport(job_id="job-clean", project_id="proj-clean", findings=[])

    sarif = clean_report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []

    md = clean_report.to_markdown()
    assert "Total Findings**: 0" in md
    assert "No findings detected. Codebase passed all security and quality checks." in md