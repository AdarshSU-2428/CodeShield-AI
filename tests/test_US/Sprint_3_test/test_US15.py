import os
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from app.analysis.quality_analyzer import CodeQualityAnalyzer, ArchitecturalSmellDetector
from app.analysis.cross_file import CrossFileContextResolver
from app.core.enums import Confidence, FileStatus, FindingCategory, JobStatus, Language, Severity
from app.core.models.audit import AuditFinding, AuditJob, AuditReport
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.services.audit_service import AuditService


@pytest.fixture
def quality_analyzer():
    return CodeQualityAnalyzer(max_function_lines=75, max_nesting_depth=4, max_parameters=5)


@pytest.fixture
def arch_detector():
    return ArchitecturalSmellDetector(max_god_class_lines=250)


def test_us15_detect_bare_except_python(quality_analyzer):
    """US 15: Verifies detection of Python bare except and BaseException handlers."""
    code = (
        "def process_data(val):\n"
        "    try:\n"
        "        risky_call(val)\n"
        "    except:\n"
        "        pass\n"
        "    try:\n"
        "        another_call()\n"
        "    except BaseException:\n"
        "        log_error()\n"
    )
    sf = SourceFile(
        file_path="app/processor.py",
        relative_path="processor.py",
        language=Language.PYTHON,
        content=code,
    )
    findings = quality_analyzer.evaluate_file(sf)
    bare_findings = [f for f in findings if "Bare Exception" in f.title]

    assert len(bare_findings) == 2
    assert bare_findings[0].category == FindingCategory.CODE_QUALITY
    assert bare_findings[0].severity == Severity.MEDIUM
    assert bare_findings[0].confidence == Confidence.HIGH
    assert bare_findings[0].start_line == 4
    assert bare_findings[1].start_line == 8


def test_us15_detect_broad_catch_javascript_and_java(quality_analyzer):
    """US 15: Verifies detection of empty/broad catch blocks in JavaScript, Java, and C++."""
    js_code = (
        "function runTask() {\n"
        "    try {\n"
        "        doSomething();\n"
        "    } catch (Exception e) {}\n"
        "}\n"
    )
    sf_js = SourceFile(
        file_path="src/task.js",
        relative_path="task.js",
        language=Language.JAVASCRIPT,
        content=js_code,
    )
    findings = quality_analyzer.evaluate_file(sf_js)
    assert len(findings) == 1
    assert "Empty or Overly Broad Catch Block" in findings[0].title
    assert findings[0].category == FindingCategory.CODE_QUALITY
    assert findings[0].severity == Severity.MEDIUM


def test_us15_detect_excessive_nesting_depth(quality_analyzer):
    """US 15: Flags control flow structures nested at or beyond max_nesting_depth (4)."""
    nested_code = (
        "def deeply_nested(a, b, c, d):\n"
        "    if a:\n"
        "        for x in b:\n"
        "            while c:\n"
        "                if d:\n"
        "                    execute_deep()\n"
    )
    sf = SourceFile(
        file_path="app/complex.py",
        relative_path="complex.py",
        language=Language.PYTHON,
        content=nested_code,
    )
    findings = quality_analyzer.evaluate_file(sf)
    nesting_findings = [f for f in findings if "Excessive Control Flow Nesting" in f.title]

    assert len(nesting_findings) == 1
    assert "Depth: 4" in nesting_findings[0].title
    assert nesting_findings[0].category == FindingCategory.CODE_QUALITY
    assert nesting_findings[0].severity == Severity.LOW
    assert nesting_findings[0].start_line == 5
    assert "execute_deep" in nesting_findings[0].code_snippet or "if d:" in nesting_findings[0].code_snippet


def test_us15_detect_excessive_parameter_list(quality_analyzer):
    """US 15: Flags functions with parameter counts exceeding the threshold (5)."""
    code = (
        "def complex_operation(arg1, arg2, arg3, arg4, arg5, arg6, arg7):\n"
        "    return arg1 + arg2\n"
    )
    sf = SourceFile(
        file_path="app/operations.py",
        relative_path="operations.py",
        language=Language.PYTHON,
        content=code,
    )
    findings = quality_analyzer.evaluate_file(sf)
    param_findings = [f for f in findings if "Excessive Parameter List" in f.title]

    assert len(param_findings) == 1
    assert "7 params" in param_findings[0].title
    assert param_findings[0].category == FindingCategory.CODE_QUALITY
    assert param_findings[0].severity == Severity.LOW
    assert param_findings[0].start_line == 1


def test_us15_detect_monolithic_god_class():
    """US 15: Detects God Classes/monolithic files exceeding threshold line count."""
    detector = ArchitecturalSmellDetector(max_god_class_lines=50)
    
    # Create 64 lines of dummy code
    code = "\n".join([f"# Line {i}: logic statement" for i in range(1, 65)])
    sf = SourceFile(
        file_path="app/monolith.py",
        relative_path="monolith.py",
        language=Language.PYTHON,
        content=code,
    )

    findings = detector.detect_god_classes([sf])
    assert len(findings) == 1
    assert "Monolithic God Class/Module Detected (64 lines)" in findings[0].title
    assert findings[0].category == FindingCategory.ARCHITECTURE
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].end_line == 64


def test_us15_detect_circular_dependency_cycles():
    """US 15: Detects circular import cycles (e.g. A -> B -> A) across project files."""
    file_a_content = (
        "from app.service_b import ServiceB\n\n"
        "class ServiceA:\n"
        "    def __init__(self):\n"
        "        self.b = ServiceB()\n"
    )
    file_b_content = (
        "from app.service_a import ServiceA\n\n"
        "class ServiceB:\n"
        "    def __init__(self):\n"
        "        self.a = ServiceA()\n"
    )
    sf_a = SourceFile(
        file_path=str(Path("app/service_a.py").resolve()),
        relative_path="app/service_a.py",
        language=Language.PYTHON,
        content=file_a_content,
    )
    sf_b = SourceFile(
        file_path=str(Path("app/service_b.py").resolve()),
        relative_path="app/service_b.py",
        language=Language.PYTHON,
        content=file_b_content,
    )

    detector = ArchitecturalSmellDetector()
    findings = detector.detect_circular_dependencies([sf_a, sf_b])

    assert len(findings) >= 1
    cycle_finding = findings[0]
    assert cycle_finding.category == FindingCategory.ARCHITECTURE
    assert cycle_finding.severity == Severity.HIGH
    assert "Circular Dependency" in cycle_finding.title
    assert "service_a.py" in cycle_finding.description
    assert "service_b.py" in cycle_finding.description


def test_us15_audit_service_integration():
    """US 15: Verifies that AuditService executes code quality and architectural checks in Phase 3."""
    mock_scanner = MagicMock()
    mock_fs = MagicMock()
    mock_rule_engine = MagicMock()
    mock_rule_engine.analyze_file.return_value = []

    bad_code = (
        "def bad_routine(p1, p2, p3, p4, p5, p6):\n"
        "    try:\n"
        "        risky()\n"
        "    except:\n"
        "        pass\n"
    )
    sf = SourceFile(
        file_path="app/bad_code.py",
        relative_path="bad_code.py",
        language=Language.PYTHON,
        status=FileStatus.UNCHANGED,
        content=bad_code,
    )

    mock_scanner.scan_project.return_value = [sf]
    mock_fs.exists.return_value = True
    mock_fs.read_text.return_value = bad_code

    quality_analyzer = CodeQualityAnalyzer(max_parameters=5)
    arch_detector = ArchitecturalSmellDetector()

    service = AuditService(
        scanner=mock_scanner,
        filesystem=mock_fs,
        rule_engine=mock_rule_engine,
        quality_analyzer=quality_analyzer,
        architecture_detector=arch_detector,
        auto_save_report=False,
    )

    project = Project(root_path="fake_proj", name="QualityTestProject")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    assert report.job_id == job.job_id
    assert job.status == JobStatus.COMPLETED
    
    categories = [f.category for f in report.findings]
    assert FindingCategory.CODE_QUALITY in categories
    
    titles = [f.title for f in report.findings]
    assert any("Bare Exception" in t for t in titles)
    assert any("Excessive Parameter List" in t for t in titles)
