from unittest.mock import MagicMock
import pytest

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.core.enums import Language
from app.core.interfaces.llm import LLMClient, LLMResponse
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.infrastructure.llm import GroqLLMClient
from app.services.audit_service import AuditService


class BrokenCloudLLMClient(LLMClient):
    """Mock LLM client simulating complete cloud outages and fatal API crashes."""

    def __init__(self, error_to_raise=RuntimeError("Cloud connection timeout")):
        super().__init__(model_name="mock-broken")
        self.error_to_raise = error_to_raise

    def is_available(self) -> bool:
        return True

    def chat(self, messages, **kwargs):
        raise self.error_to_raise

    def chat_json(self, messages, **kwargs):
        raise self.error_to_raise


class MalformedResponseLLMClient(LLMClient):
    """Mock LLM client returning raw truncated or malformed responses."""

    def __init__(self, raw_content: str):
        super().__init__(model_name="mock-malformed")
        self.raw_content = raw_content

    def is_available(self) -> bool:
        return True

    def chat(self, messages, **kwargs):
        return LLMResponse(content=self.raw_content, model="mock-malformed")

    def chat_json(self, messages, **kwargs):
        from app.infrastructure.llm import GroqLLMClient
        cleaned = GroqLLMClient._clean_markdown_json(None, self.raw_content)
        import json
        return json.loads(cleaned)


def test_us22_cloud_timeout_graceful_degradation():
    """Verify that cloud timeout errors degrade cleanly to empty findings without raising."""
    client = BrokenCloudLLMClient(TimeoutError("Read timed out after 30s"))
    analyzer = AIVulnerabilityAnalyzer(llm_client=client)

    sf = SourceFile(file_path="app/test.py", relative_path="app/test.py", content="x = 1\n", language=Language.PYTHON)
    findings = analyzer.analyze_file(sf)

    assert findings == []
    assert analyzer.last_error is not None
    assert "timed out" in analyzer.last_error.lower()
    assert len(analyzer.warnings) >= 1


def test_us22_malformed_truncated_json_graceful_recovery():
    """Verify analyzer survives truncated or broken JSON strings."""
    client = BrokenCloudLLMClient(ValueError("Failed to parse LLM response as JSON. Content received: '{\"vulnerabilities\": [{'"))
    analyzer = AIVulnerabilityAnalyzer(llm_client=client)

    sf = SourceFile(file_path="app/test.py", relative_path="app/test.py", content="eval(payload)\n", language=Language.PYTHON)
    findings = analyzer.analyze_file(sf)

    assert findings == []
    assert analyzer.last_error is not None


def test_us22_conversational_prose_json_cleaning():
    """Verify clean extraction when LLM returns conversational prose surrounding JSON."""
    raw = (
        "Here is the security report requested:\n\n"
        "```json\n"
        '{"vulnerabilities": [{"title": "Command Injection", "start_line": 2, "severity": "HIGH"}]}\n'
        "```\n\n"
        "Please let me know if you need more help!"
    )
    client = MalformedResponseLLMClient(raw)
    analyzer = AIVulnerabilityAnalyzer(llm_client=client)

    sf = SourceFile(file_path="app/test.py", relative_path="app/test.py", content="os.system(cmd)\n", language=Language.PYTHON)
    findings = analyzer.analyze_file(sf)

    assert len(findings) == 1
    assert findings[0].title == "Command Injection"


def test_us22_corrupted_schema_types_safety():
    """Verify analyzer tolerates corrupt schema types (string line numbers, missing fields, NaNs)."""
    corrupt_response = {
        "vulnerabilities": [
            {
                "title": None,  # null title
                "description": None,
                "start_line": "invalid_line_number",  # string line
                "end_line": None,
                "severity": "unknown_invalid_level",  # invalid severity
                "confidence": 12345,  # invalid confidence
                "evidence": 42,  # integer evidence
                "remediation_steps": "just fix it",  # string instead of list
            },
            "totally_not_a_dict",  # corrupt non-dict element
        ]
    }

    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = corrupt_response

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(file_path="app/test.py", relative_path="app/test.py", content="code()\n", language=Language.PYTHON)
    findings = analyzer.analyze_file(sf)

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Potential Security Vulnerability"
    assert f.start_line == 1
    assert f.severity.value == "medium"
    assert f.evidence == {"trigger": "42"}
    assert f.remediation_steps == ["just fix it"]


def test_us22_raw_list_response_support():
    """Verify analyzer accepts raw list JSON responses without vulnerabilities wrapper."""
    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = [
        {"title": "Path Traversal", "start_line": 5, "severity": "HIGH"}
    ]

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(file_path="app/test.py", relative_path="app/test.py", content="open(path)\n", language=Language.PYTHON)
    findings = analyzer.analyze_file(sf)

    assert len(findings) == 1
    assert findings[0].title == "Path Traversal"


def test_us22_audit_service_survives_cloud_llm_outage(tmp_path):
    """Verify entire AuditService completes static analysis and captures AI warnings in AuditReport."""
    broken_client = BrokenCloudLLMClient(ConnectionError("503 Service Unavailable: Groq API Down"))
    analyzer = AIVulnerabilityAnalyzer(llm_client=broken_client)

    test_file = tmp_path / "vulnerable.py"
    test_file.write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")

    class SingleFileScanner:
        def scan_project(self, project):
            return [
                SourceFile(
                    file_path=test_file,
                    relative_path="vulnerable.py",
                    content=test_file.read_text(encoding="utf-8"),
                    language=Language.PYTHON,
                )
            ]

    service = AuditService(
        scanner=SingleFileScanner(),
        filesystem=LocalFileSystem(),
        ai_analyzer=analyzer,
    )

    project = Project(name="ResilienceTest", root_path=tmp_path)
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    assert report is not None
    assert len(report.warnings) >= 1
    assert "AI degraded" in report.warnings[0]
    assert "AI warning(s)" in report.summary

    # Static security rule SEC-003 (Command Injection) must still be detected by the rule engine!
    cmd_finding = next((f for f in report.findings if "Command" in f.title), None)
    assert cmd_finding is not None
    assert cmd_finding.source in ("rule", "rule_engine")


def test_us22_groq_client_retry_and_fallback_resilience():
    """Verify GroqLLMClient attempts retry and fails over to fallback model on persistent 429."""
    from groq import RateLimitError

    mock_client = MagicMock()
    primary_mock = MagicMock(side_effect=RateLimitError("Rate limit exceeded", response=MagicMock(status_code=429), body=None))
    fallback_mock = MagicMock(
        choices=[MagicMock(message=MagicMock(content="{}"), finish_reason="stop")],
        model="llama-3.1-8b-instant",
    )

    def dispatch(*args, **kwargs):
        if kwargs.get("model") == "primary-model":
            return primary_mock(*args, **kwargs)
        return fallback_mock

    mock_client.chat.completions.create.side_effect = dispatch

    client = GroqLLMClient(
        api_key="gsk_test_12345",
        model_name="primary-model",
        fallback_model="llama-3.1-8b-instant",
        max_retries=1,
        retry_delay=0.01,
        client=mock_client,
    )

    resp = client.chat(messages=[{"role": "user", "content": "test"}])
    assert resp.content == "{}"
    assert resp.model == "llama-3.1-8b-instant"

