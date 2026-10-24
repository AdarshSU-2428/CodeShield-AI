import os
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from app.analysis.attribution_helper import FindingAttributionHelper
from app.analysis.quality_analyzer import CodeQualityAnalyzer, ArchitecturalSmellDetector
from app.core.enums import Confidence, FileStatus, FindingCategory, JobStatus, Language, Severity
from app.core.models.audit import AuditFinding, AuditJob, AuditReport
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.services.audit_service import AuditService


def test_us16_line_number_normalization_and_clamping():
    """US 16: Verifies 1-indexed line clamping and end_line >= start_line enforcement."""
    # Test 1: Negative / zero start line clamps to 1
    f1 = AuditFinding(
        title="Invalid Line Finding",
        description="Line numbers were <= 0",
        file_path="app/main.py",
        start_line=-5,
        end_line=-1,
    )
    assert f1.start_line == 1
    assert f1.end_line == 1

    # Test 2: Inverted start/end lines enforce end_line >= start_line
    f2 = AuditFinding(
        title="Inverted Range Finding",
        description="end_line was less than start_line",
        file_path="app/main.py",
        start_line=15,
        end_line=10,
    )
    assert f2.start_line == 15
    assert f2.end_line == 15

    # Test 3: Clamping against actual file line count via FindingAttributionHelper
    helper = FindingAttributionHelper()
    file_content = "line 1\nline 2\nline 3\nline 4\nline 5\n"
    f3 = AuditFinding(
        title="Overshot Range Finding",
        description="Target range exceeds total lines",
        file_path="app/main.py",
        start_line=4,
        end_line=999,
    )
    helper.hydrate_finding(f3, file_content=file_content)
    assert f3.start_line == 4
    assert f3.end_line == 5


def test_us16_code_snippet_extraction():
    """US 16: Extracts the exact bounded lines corresponding to start_line and end_line."""
    helper = FindingAttributionHelper()
    code = (
        "def authenticate(user, password):\n"
        "    query = f\"SELECT * FROM users WHERE u='{user}'\"\n"
        "    db.execute(query)\n"
        "    return True\n"
    )

    finding = AuditFinding(
        title="SQL Injection Vulnerability",
        description="Raw string formatting in SQL query",
        file_path="app/auth.py",
        start_line=2,
        end_line=3,
    )

    helper.hydrate_finding(finding, file_content=code)
    expected_snippet = (
        '    query = f"SELECT * FROM users WHERE u=\'{user}\'"\n'
        "    db.execute(query)"
    )
    assert finding.code_snippet == expected_snippet


def test_us16_context_snippet_generation():
    """US 16: Generates multi-line context window with line numbers and pointer markers."""
    helper = FindingAttributionHelper()
    code = (
        "# Header comment\n"
        "import os\n"
        "import sys\n"
        "\n"
        "def risky_shell(cmd):\n"
        "    os.system(cmd)\n"
        "    print('executed')\n"
        "\n"
        "# Footer comment\n"
    )

    finding = AuditFinding(
        title="Command Injection",
        description="Unsanitized call to os.system",
        file_path="app/shell.py",
        start_line=6,
        end_line=6,
    )

    helper.hydrate_finding(finding, file_content=code, context_lines=2)

    assert finding.context_snippet is not None
    lines = finding.context_snippet.splitlines()

    # Context window for line 6 with 2 lines padding = lines 4, 5, 6, 7, 8
    assert len(lines) == 5
    # Pointer marker '>' on line 6
    assert any(line.startswith(">    6 |     os.system(cmd)") for line in lines)
    # Surrounding lines with leading space
    assert any(line.startswith("     5 | def risky_shell(cmd):") for line in lines)
    assert any(line.startswith("     7 |     print('executed')") for line in lines)


def test_us16_multi_file_attribution():
    """US 16: Verifies multi-file attribution tracking for circular dependencies and cross-file smells."""
    helper = FindingAttributionHelper()

    # Circular dependency finding affecting two files
    finding = AuditFinding(
        title="Circular Dependency Detected",
        description="Circular import between service_a and service_b",
        file_path="app/service_a.py",
        metadata={"cycle_files": ["app/service_a.py", "app/service_b.py"]},
    )

    helper.hydrate_finding(finding, file_content="import service_b\n")

    assert "app/service_a.py" in finding.affected_files
    assert "app/service_b.py" in finding.affected_files
    assert len(finding.affected_files) == 2


def test_us16_finding_to_dict_serialization():
    """US 16: Verifies affected_files and context_snippet are properly serialized."""
    finding = AuditFinding(
        title="Test Finding",
        description="Description text",
        file_path="src/utils.py",
        start_line=2,
        end_line=4,
        code_snippet="x = 1\ny = 2\nz = 3",
        context_snippet=">    2 | x = 1\n>    3 | y = 2\n>    4 | z = 3",
        affected_files=["src/utils.py", "src/helpers.py"],
    )

    data = finding.to_dict()
    assert data["file_path"] == "src/utils.py"
    assert data["start_line"] == 2
    assert data["end_line"] == 4
    assert data["code_snippet"] == "x = 1\ny = 2\nz = 3"
    assert ">    2 | x = 1" in data["context_snippet"]
    assert data["affected_files"] == ["src/utils.py", "src/helpers.py"]


def test_us16_batch_hydration_via_filesystem():
    """US 16: Tests batch hydration of findings across multiple source files."""
    mock_fs = MagicMock()
    file_a = "def foo():\n    return 42\n"
    file_b = "class Bar:\n    pass\n"

    def mock_read_text(path):
        if "foo.py" in str(path):
            return file_a
        return file_b

    mock_fs.exists.return_value = True
    mock_fs.read_text.side_effect = mock_read_text

    helper = FindingAttributionHelper(filesystem=mock_fs)

    findings = [
        AuditFinding(title="F1", description="D1", file_path="app/foo.py", start_line=2, end_line=2),
        AuditFinding(title="F2", description="D2", file_path="app/bar.py", start_line=1, end_line=1),
    ]

    hydrated = helper.hydrate_findings(findings, context_lines=1)

    assert hydrated[0].code_snippet == "    return 42"
    assert ">    2 |     return 42" in hydrated[0].context_snippet
    assert hydrated[1].code_snippet == "class Bar:"
    assert ">    1 | class Bar:" in hydrated[1].context_snippet


def test_us16_audit_service_end_to_end_attribution():
    """US 16: Verifies AuditService automatically hydrates findings with snippets and context in Phase 3."""
    mock_scanner = MagicMock()
    mock_fs = MagicMock()
    mock_rule_engine = MagicMock()
    mock_rule_engine.analyze_file.return_value = []

    file_code = (
        "def execute_op(x):\n"
        "    try:\n"
        "        calc(x)\n"
        "    except:\n"
        "        pass\n"
    )

    sf = SourceFile(
        file_path="app/executor.py",
        relative_path="executor.py",
        language=Language.PYTHON,
        status=FileStatus.UNCHANGED,
        content=file_code,
    )

    mock_scanner.scan_project.return_value = [sf]
    mock_fs.exists.return_value = True
    mock_fs.read_text.return_value = file_code

    service = AuditService(
        scanner=mock_scanner,
        filesystem=mock_fs,
        rule_engine=mock_rule_engine,
        quality_analyzer=CodeQualityAnalyzer(),
        architecture_detector=ArchitecturalSmellDetector(),
        auto_save_report=False,
    )

    project = Project(root_path="fake_proj", name="AttributionTestProject")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    assert len(report.findings) >= 1
    for finding in report.findings:
        assert finding.file_path.endswith("app/executor.py")
        assert finding.start_line >= 1
        assert finding.end_line >= finding.start_line
        assert finding.code_snippet is not None
        assert finding.context_snippet is not None
        assert ">" in finding.context_snippet
        assert any(f.endswith("app/executor.py") for f in finding.affected_files)


def test_us16_start_end_column_offsets_and_snippet_alias():
    """US 16: Verifies start_column, end_column, 1-indexing, clamping, and .snippet property alias."""
    # Test column initialization and clamping
    f = AuditFinding(
        title="Column Test Finding",
        description="Testing column offsets and snippet alias",
        file_path="app/core.py",
        relative_file_path="core.py",
        start_line=10,
        end_line=10,
        start_column=5,
        end_column=25,
        snippet="password = 'secret'",
    )

    assert f.start_column == 5
    assert f.end_column == 25
    assert f.relative_file_path == "core.py"
    # .snippet property alias
    assert f.snippet == "password = 'secret'"
    assert f.code_snippet == "password = 'secret'"

    # Test snippet setter
    f.snippet = "new_secret_val"
    assert f.code_snippet == "new_secret_val"

    # Test serialization includes all attribution fields
    d = f.to_dict()
    assert d["start_column"] == 5
    assert d["end_column"] == 25
    assert d["relative_file_path"] == "core.py"
    assert d["snippet"] == "new_secret_val"

    # Column clamping on inverted or zero values
    f_clamped = AuditFinding(
        title="Clamped Column",
        description="Negative and inverted columns",
        file_path="app/test.py",
        start_column=-3,
        end_column=0,
    )
    assert f_clamped.start_column == 1
    assert f_clamped.end_column >= 1


def test_us16_rule_engine_direct_attribution_and_snippet_enrichment():
    """US 16: Verifies RuleEngine directly hydrates findings with column offsets, snippets, and relative paths."""
    from app.analysis.rule_engine import RuleEngine
    from app.analysis.rules.builtin import CommandInjectionRule, HardcodedSecretRule

    engine = RuleEngine(rules=[CommandInjectionRule(), HardcodedSecretRule()])
    source_code = (
        "# Security test module\n"
        "import os\n"
        "def run_command(param):\n"
        "    os.system(param)\n"
        "    api_key = \"AKIA1234567890ABCDEF\"\n"
        "    return True\n"
    )

    sf = SourceFile(
        file_path="C:/workspace/project/app/services/runner.py",
        relative_path="app/services/runner.py",
        language=Language.PYTHON,
        content=source_code,
    )

    findings = engine.analyze_file(sf)
    assert len(findings) == 2

    cmd_finding = next((f for f in findings if "Command Injection" in f.title), None)
    assert cmd_finding is not None
    assert cmd_finding.start_line == 4
    assert cmd_finding.end_line == 4
    assert cmd_finding.start_column is not None
    assert cmd_finding.end_column is not None
    assert cmd_finding.start_column > 1  # Indented on line 4
    assert cmd_finding.relative_file_path == "app/services/runner.py"
    assert "os.system(param)" in cmd_finding.code_snippet
    assert ">    4 |     os.system(param)" in cmd_finding.context_snippet

    secret_finding = next((f for f in findings if "Secret" in f.title or "Credential" in f.title), None)
    assert secret_finding is not None
    assert secret_finding.start_line == 5
    assert secret_finding.start_column is not None
    assert secret_finding.end_column is not None
    assert secret_finding.relative_file_path == "app/services/runner.py"
    assert "AKIA1234567890ABCDEF" in secret_finding.code_snippet
    assert ">    5 |     api_key = \"AKIA1234567890ABCDEF\"" in secret_finding.context_snippet


def test_us16_ai_analyzer_column_and_context_attribution():
    """US 16: Verifies AIVulnerabilityAnalyzer parses column offsets and enriches relative paths & context."""
    from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer

    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Server-Side Request Forgery",
                "description": "Unvalidated HTTP request to user-controlled URL.",
                "cwe_id": "CWE-918",
                "severity": "HIGH",
                "confidence": "HIGH",
                "start_line": 3,
                "end_line": 3,
                "start_column": 9,
                "end_column": 35,
                "code_snippet": "requests.get(url, timeout=5)",
                "recommendation": "Validate against an allowlist.",
            }
        ]
    }

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    code = (
        "import requests\n"
        "def fetch_data(url):\n"
        "    res = requests.get(url, timeout=5)\n"
        "    return res.text\n"
    )

    sf = SourceFile(
        file_path="C:/proj/app/fetcher.py",
        relative_path="app/fetcher.py",
        language=Language.PYTHON,
        content=code,
    )

    findings = analyzer.analyze_file(sf)
    assert len(findings) == 1
    f = findings[0]
    assert f.start_line == 3
    assert f.end_line == 3
    assert f.start_column == 9
    assert f.end_column == 35
    assert f.relative_file_path == "app/fetcher.py"
    assert f.file_path == "C:/proj/app/fetcher.py"
    assert f.code_snippet == "requests.get(url, timeout=5)"
    assert ">    3 |     res = requests.get(url, timeout=5)" in f.context_snippet


def test_us16_multiline_span_and_boundary_checking():
    """US 16: Tests multi-line spanning and boundary conditions in context snippet generation."""
    helper = FindingAttributionHelper()
    lines = [f"line_{i} = {i}" for i in range(1, 21)]
    code = "\n".join(lines)

    # Multi-line span from line 8 to line 12
    finding = AuditFinding(
        title="Multi-line Smell",
        description="Function exceeds complexity across lines 8-12",
        file_path="app/complex.py",
        start_line=8,
        end_line=12,
    )

    helper.hydrate_finding(finding, file_content=code, context_lines=2)

    assert finding.start_line == 8
    assert finding.end_line == 12
    # Snippet contains all 5 lines
    assert len(finding.code_snippet.splitlines()) == 5
    # Context lines: 6, 7, [8, 9, 10, 11, 12], 13, 14 -> 9 lines total
    ctx_lines = finding.context_snippet.splitlines()
    assert len(ctx_lines) == 9

    # Check marker '>' on lines 8 through 12
    for line_no in range(8, 13):
        assert any(l.startswith(f">   {line_no:2d} |") for l in ctx_lines)
    # Check lines 6, 7, 13, 14 do NOT have marker '>'
    for line_no in [6, 7, 13, 14]:
        assert any(l.startswith(f"    {line_no:2d} |") for l in ctx_lines)
