from pathlib import Path
from unittest.mock import MagicMock
import pytest

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.rule_engine import RuleEngine
from app.core.enums import Language
from app.core.interfaces.llm import LLMClient
from app.core.models.audit import (
    AuditFinding,
    Confidence,
    FindingCategory,
    Severity,
)
from app.core.models.code import CodeComponent, SourceFile
from app.core.models.project import Project
from app.services.audit_service import AuditService


def test_us9_ai_analyzer_unconfigured_client_graceful_noop():
    """Verify analyzer returns empty list when LLM client is unavailable without raising errors."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = False

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    source = SourceFile(
        file_path="app/vulnerable.py",
        relative_path="vulnerable.py",
        language=Language.PYTHON,
        content="import requests\ndef fetch(url): return requests.get(url)",
    )

    findings = analyzer.analyze_file(source)

    assert findings == []
    mock_llm.chat_json.assert_not_called()


def test_us9_ai_analyzer_detects_semantic_vulnerabilities():
    """Verify semantic vulnerability detection and AuditFinding attribute mapping."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True

    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Server-Side Request Forgery (SSRF)",
                "description": "User supplied URL is directly passed to HTTP client without allowlist validation.",
                "cwe_id": "CWE-918",
                "severity": "HIGH",
                "confidence": "HIGH",
                "start_line": 15,
                "end_line": 16,
                "code_snippet": "resp = requests.get(target_url)",
                "recommendation": "Validate destination IP against a private network allowlist.",
            },
            {
                "title": "Insecure Deserialization via pickle.loads",
                "description": "Untrusted binary stream is deserialized using pickle allowing remote code execution.",
                "cwe_id": "CWE-502",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "start_line": 28,
                "end_line": 28,
                "code_snippet": "data = pickle.loads(raw_stream)",
                "recommendation": "Use safer data interchange formats like JSON.",
            },
        ]
    }

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    source = SourceFile(
        file_path="app/api.py",
        relative_path="api.py",
        language=Language.PYTHON,
        content="# API source code with vulnerabilities",
    )

    findings = analyzer.analyze_file(source)

    assert len(findings) == 2

    # Verify Finding 1: SSRF
    f1 = findings[0]
    assert isinstance(f1, AuditFinding)
    assert f1.title == "Server-Side Request Forgery (SSRF)"
    assert f1.category == FindingCategory.SECURITY
    assert f1.severity == Severity.HIGH
    assert f1.confidence == Confidence.HIGH
    assert f1.cwe_id == "CWE-918"
    assert f1.source == "ai_llm"
    assert f1.start_line == 15
    assert f1.end_line == 16
    assert f1.code_snippet == "resp = requests.get(target_url)"
    assert "private network" in f1.recommendation

    # Verify Finding 2: Insecure Deserialization
    f2 = findings[1]
    assert f2.title == "Insecure Deserialization via pickle.loads"
    assert f2.severity == Severity.CRITICAL
    assert f2.cwe_id == "CWE-502"
    assert f2.start_line == 28


def test_us9_ai_analyzer_prompt_structure_and_temperature():
    """Verify prompt formatting, system role definition, and temperature settings."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {"vulnerabilities": []}

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm, temperature=0.1)
    source = SourceFile(
        file_path="src/service.py",
        relative_path="service.py",
        language=Language.PYTHON,
        content="x = 10\n",
    )

    messages = analyzer.build_messages(
        source,
        context_snippets=[{"file": "src/config.py", "snippet": "DEBUG = True"}],
    )

    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert "SAST" in messages[0]["content"]
    assert "CWE" in messages[0]["content"]

    assert messages[1]["role"] == "user"
    assert "service.py" in messages[1]["content"]
    assert "Related Cross-File Context:" in messages[1]["content"]
    assert "src/config.py" in messages[1]["content"]

    analyzer.analyze_file(source, context_snippets=[{"file": "src/config.py", "snippet": "DEBUG = True"}])
    mock_llm.chat_json.assert_called_once_with(messages=messages, temperature=0.1)


def test_us9_ai_analyzer_malformed_json_fallback_resilience():
    """Verify graceful handling when LLM returns unexpected JSON schema or raises exception."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    source = SourceFile(
        file_path="app/test.py",
        relative_path="test.py",
        language=Language.PYTHON,
        content="x = 1\n",
    )

    # 1. Non-dict or unexpected schema
    mock_llm.chat_json.return_value = {"status": "ok", "unexpected_key": 123}
    findings = analyzer.analyze_file(source)
    assert findings == []

    # 2. LLM client throws RuntimeError / Network failure
    mock_llm.chat_json.side_effect = RuntimeError("Groq Cloud unreachable")
    findings = analyzer.analyze_file(source)
    assert findings == []


def test_us9_ai_analyzer_component_level_analysis_offsets():
    """Verify component-level analysis offsets line numbers accurately to the enclosing file."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Auth Bypass",
                "description": "Missing check on token validity",
                "cwe_id": "CWE-287",
                "severity": "HIGH",
                "start_line": 3,
                "end_line": 3,
            }
        ]
    }

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    source = SourceFile(
        file_path="auth/handler.py",
        relative_path="handler.py",
        language=Language.PYTHON,
        content="# Enclosing file content\n",
    )
    component = CodeComponent(
        name="authenticate_user",
        component_type="function",
        start_line=50,
        end_line=70,
        source_content="def authenticate_user():\n    # Vulnerability at line 3\n    pass",
        file_path="auth/handler.py",
    )

    findings = analyzer.analyze_component(component, source)

    assert len(findings) == 1
    # Line 3 within function starting at line 50 must become 50 + 3 - 1 = 52
    assert findings[0].start_line == 52
    assert findings[0].end_line == 52


def test_us9_ai_analyzer_integration_with_audit_service(tmp_path: Path):
    """Verify AuditService aggregates both static rule findings and AI findings."""
    project_dir = tmp_path / "hybrid_project"
    project_dir.mkdir()
    target_file = project_dir / "service.py"
    # Content with both a hardcoded secret (rule engine) and an SSRF function (AI analyzer)
    target_file.write_text(
        "api_key = 'super_secret_token_12345'\n"
        "def fetch_remote(url):\n"
        "    import requests\n"
        "    return requests.get(url)\n",
        encoding="utf-8",
    )

    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "SSRF Vulnerability",
                "description": "Unchecked request to remote url",
                "cwe_id": "CWE-918",
                "severity": "HIGH",
                "start_line": 4,
                "end_line": 4,
            }
        ]
    }

    ai_analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    audit_service = AuditService(rule_engine=RuleEngine(), ai_analyzer=ai_analyzer)

    project = Project(root_path=project_dir, name="HybridProject")
    job = audit_service.create_job(project)
    report = audit_service.run_audit(job.job_id, project)

    sources = [f.source for f in report.findings]
    assert "rule" in sources
    assert "ai_llm" in sources
    assert any(f.cwe_id == "CWE-798" for f in report.findings)
    assert any(f.cwe_id == "CWE-918" for f in report.findings)


def test_us9_ai_analyzer_severity_confidence_and_truncation():
    """Verify parsing of various severity/confidence casing and oversized file truncation."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm, max_file_size_chars=100)

    # Test Severity parsing
    assert analyzer._parse_severity("CRITICAL") == Severity.CRITICAL
    assert analyzer._parse_severity("critical") == Severity.CRITICAL
    assert analyzer._parse_severity("low") == Severity.LOW
    assert analyzer._parse_severity("UNKNOWN_VALUE") == Severity.MEDIUM

    # Test Confidence parsing
    assert analyzer._parse_confidence("HIGH") == Confidence.HIGH
    assert analyzer._parse_confidence("low") == Confidence.LOW
    assert analyzer._parse_confidence("unknown") == Confidence.HIGH

    # Test oversized truncation
    large_source = SourceFile(
        file_path="large.py",
        relative_path="large.py",
        language=Language.PYTHON,
        content="x = 10\n" * 50,  # 350 chars > 100 limit
    )

    messages = analyzer.build_messages(large_source)
    assert "[TRUNCATED DUE TO FILE SIZE]" in messages[1]["content"]
