from pathlib import Path
import pytest
from unittest.mock import MagicMock

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.rules.builtin import (
    CommandInjectionRule,
    DangerousFunctionRule,
    HardcodedSecretRule,
    SQLInjectionRule,
    WeakCryptoRule,
)
from app.core.enums import Confidence, FindingCategory, Language, Severity
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile


def test_us12_hardcoded_secret_evidence_and_explanation():
    """US 12: Verifies HardcodedSecretRule populates evidence, risk_explanation, and exploit_scenario."""
    rule = HardcodedSecretRule()
    sf = SourceFile(
        file_path="app/config.py",
        relative_path="config.py",
        language=Language.PYTHON,
        content="db_password = 'SuperSecretProductionPassword!2026'\n",
    )

    findings = rule.evaluate(sf)
    assert len(findings) == 1
    f = findings[0]

    assert f.evidence is not None
    assert f.evidence.get("rule_id") == "SEC-001"
    assert f.evidence.get("matched_identifier") == "db_password"
    assert f.evidence.get("secret_length") == len("SuperSecretProductionPassword!2026")
    assert "credential literal" in f.risk_explanation
    assert "leaked repository history" in f.exploit_scenario


def test_us12_sql_injection_evidence_and_explanation():
    """US 12: Verifies SQLInjectionRule populates evidence, risk_explanation, and exploit_scenario."""
    rule = SQLInjectionRule()
    sf = SourceFile(
        file_path="app/db.py",
        relative_path="db.py",
        language=Language.PYTHON,
        content="cursor.execute(f'SELECT * FROM accounts WHERE id = {acc_id}')\n",
    )

    findings = rule.evaluate(sf)
    assert len(findings) == 1
    f = findings[0]

    assert "matched_pattern" in f.evidence
    assert "f'SELECT * FROM accounts WHERE id = {" in f.evidence["matched_pattern"]
    assert "dynamic formatting" in f.risk_explanation
    assert "admin' --" in f.exploit_scenario


def test_us12_command_injection_evidence_and_explanation():
    """US 12: Verifies CommandInjectionRule populates evidence, risk_explanation, and exploit_scenario."""
    rule = CommandInjectionRule()
    sf = SourceFile(
        file_path="app/runner.py",
        relative_path="runner.py",
        language=Language.PYTHON,
        content="os.system('cat ' + user_file)\n",
    )

    findings = rule.evaluate(sf)
    assert len(findings) == 1
    f = findings[0]

    assert "invocation" in f.evidence
    assert "os.system" in f.evidence["invocation"]
    assert "command separators" in f.risk_explanation
    assert "malware" in f.exploit_scenario or "compromise" in f.exploit_scenario


def test_us12_dangerous_function_evidence_and_explanation():
    """US 12: Verifies DangerousFunctionRule populates evidence, risk_explanation, and exploit_scenario."""
    rule = DangerousFunctionRule()
    sf = SourceFile(
        file_path="src/parser.c",
        relative_path="parser.c",
        language=Language.C,
        content="strcpy(target, source);\n",
    )

    findings = rule.evaluate(sf)
    assert len(findings) == 1
    f = findings[0]

    assert "dangerous_function" in f.evidence
    assert "strcpy(" in f.evidence["dangerous_function"]
    assert "buffer boundary" in f.risk_explanation
    assert "instruction pointers" in f.exploit_scenario


def test_us12_weak_crypto_evidence_and_explanation():
    """US 12: Verifies WeakCryptoRule populates evidence, risk_explanation, and exploit_scenario."""
    rule = WeakCryptoRule()
    sf = SourceFile(
        file_path="src/hash.py",
        relative_path="hash.py",
        language=Language.PYTHON,
        content="digest = hashlib.md5(payload).hexdigest()\n",
    )

    findings = rule.evaluate(sf)
    assert len(findings) == 1
    f = findings[0]

    assert "algorithm_match" in f.evidence
    assert "hashlib.md5" in f.evidence["algorithm_match"]
    assert "collision" in f.risk_explanation
    assert "spoof" in f.exploit_scenario


def test_us12_ai_analyzer_parses_evidence_and_exploit_scenario():
    """US 12: Verifies AIVulnerabilityAnalyzer parses structured evidence, risk explanation, and exploit scenario."""
    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Path Traversal via Zip Slip",
                "description": "Archive extraction allows writing outside target directory.",
                "cwe_id": "CWE-22",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "start_line": 10,
                "end_line": 10,
                "code_snippet": "zip_ref.extract(member, target_dir)",
                "evidence": {
                    "source": "zip_ref.namelist()",
                    "sink": "zip_ref.extract",
                    "unvalidated_member": "member.filename",
                },
                "risk_explanation": "Extracted filenames containing '../' traverse out of the extraction root.",
                "exploit_scenario": "An attacker uploads a ZIP with '../../etc/cron.d/evil' to achieve code execution.",
                "recommendation": "Validate that destination path starts with target_dir.",
            }
        ]
    }

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(
        file_path="app/archiver.py",
        relative_path="archiver.py",
        language=Language.PYTHON,
        content="def extract(zip_ref, target_dir):\n    zip_ref.extract(member, target_dir)\n",
    )

    findings = analyzer.analyze_file(sf)
    assert len(findings) == 1
    f = findings[0]

    assert f.evidence.get("sink") == "zip_ref.extract"
    assert "traverse out" in f.risk_explanation
    assert "/etc/cron.d/evil" in f.exploit_scenario


def test_us12_finding_to_dict_preserves_evidence_fields():
    """US 12: Verifies serialization preserves evidence, risk_explanation, and exploit_scenario in dictionary."""
    finding = AuditFinding(
        title="IDOR Flaw",
        description="Direct reference to user record without permission check",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app/views.py",
        start_line=15,
        end_line=15,
        evidence={"object_id": "req.params.id", "auth_check": "missing"},
        risk_explanation="Parameter tampering allows querying records belonging to other tenants.",
        exploit_scenario="Changing ID from 100 to 101 retrieves victim's private profile.",
    )

    data = finding.to_dict()
    assert data["evidence"] == {"object_id": "req.params.id", "auth_check": "missing"}
    assert "Parameter tampering" in data["risk_explanation"]
    assert "Changing ID from 100 to 101" in data["exploit_scenario"]