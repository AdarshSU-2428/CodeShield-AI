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
from app.core.enums import Confidence, Language, Severity
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile
from app.patches.generator import PatchGenerator


def test_us14_builtin_rules_provide_remediation_code_and_steps():
    """US 14: Verifies all built-in rules generate concrete remediation_code and numbered steps."""
    # 1. Secret Rule
    sf_sec = SourceFile(
        file_path="app/secret.py",
        relative_path="secret.py",
        language=Language.PYTHON,
        content="auth_token = 'SuperSecretToken12345'\n",
    )
    f_sec = HardcodedSecretRule().evaluate(sf_sec)[0]
    assert "os.getenv" in f_sec.remediation_code
    assert len(f_sec.remediation_steps) >= 2
    assert any("AUTH_TOKEN" in s for s in f_sec.remediation_steps)

    # 2. SQL Injection Rule
    sf_sql = SourceFile(
        file_path="app/db.py",
        relative_path="db.py",
        language=Language.PYTHON,
        content="cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
    )
    f_sql = SQLInjectionRule().evaluate(sf_sql)[0]
    assert "%s" in f_sql.remediation_code or "?" in f_sql.remediation_code
    assert len(f_sql.remediation_steps) >= 2

    # 3. Command Injection Rule
    sf_cmd = SourceFile(
        file_path="app/exec.py",
        relative_path="exec.py",
        language=Language.PYTHON,
        content="os.system('ping ' + host)\n",
    )
    f_cmd = CommandInjectionRule().evaluate(sf_cmd)[0]
    assert "subprocess.run" in f_cmd.remediation_code
    assert "shell=False" in f_cmd.remediation_code
    assert len(f_cmd.remediation_steps) >= 2

    # 4. Dangerous Function Rule
    sf_c = SourceFile(
        file_path="app/mem.c",
        relative_path="mem.c",
        language=Language.C,
        content="strcpy(dst, src);\n",
    )
    f_c = DangerousFunctionRule().evaluate(sf_c)[0]
    assert "strncpy" in f_c.remediation_code
    assert len(f_c.remediation_steps) >= 2

    # 5. Weak Crypto Rule
    sf_hash = SourceFile(
        file_path="app/crypto.py",
        relative_path="crypto.py",
        language=Language.PYTHON,
        content="h = hashlib.md5(b'input').digest()\n",
    )
    f_hash = WeakCryptoRule().evaluate(sf_hash)[0]
    assert "sha256" in f_hash.remediation_code
    assert len(f_hash.remediation_steps) >= 2


def test_us14_ai_analyzer_parses_remediation_code_and_steps():
    """US 14: Verifies AIVulnerabilityAnalyzer extracts remediation_code and remediation_steps from LLM payload."""
    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Insecure Deserialization",
                "description": "Unpickling untrusted payload",
                "cwe_id": "CWE-502",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "start_line": 4,
                "end_line": 4,
                "code_snippet": "obj = pickle.loads(user_data)",
                "remediation_code": "obj = json.loads(user_data)",
                "remediation_steps": [
                    "1. Deprecate pickle for untrusted network input.",
                    "2. Serialize data using JSON or Protocol Buffers.",
                    "3. Validate the payload against a strict schema.",
                ],
                "recommendation": "Use json.loads instead of pickle.",
            }
        ]
    }

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(
        file_path="app/receiver.py",
        relative_path="receiver.py",
        language=Language.PYTHON,
        content="import pickle\ndef parse(user_data):\n    # line 3\n    obj = pickle.loads(user_data)\n    return obj\n",
    )

    findings = analyzer.analyze_file(sf)
    assert len(findings) == 1
    f = findings[0]

    assert f.remediation_code == "obj = json.loads(user_data)"
    assert len(f.remediation_steps) == 3
    assert "Deprecate pickle" in f.remediation_steps[0]


def test_us14_patch_generator_inline_remediation_indentation():
    """US 14: Verifies PatchGenerator replaces offending lines while preserving code indentation."""
    gen = PatchGenerator()
    original_code = (
        "class AuthManager:\n"
        "    def check_user(self, uid):\n"
        "        query = f'SELECT * FROM users WHERE id = {uid}'\n"
        "        return db.execute(query)\n"
    )

    finding = AuditFinding(
        title="SQLi",
        description="SQL injection in query",
        start_line=3,
        end_line=3,
        remediation_code="query = 'SELECT * FROM users WHERE id = %s'\nparams = (uid,)",
    )

    modified_code, diff = gen.generate_remediation(original_code, finding, file_name="auth.py")

    assert "        query = 'SELECT * FROM users WHERE id = %s'" in modified_code
    assert "        params = (uid,)" in modified_code
    assert diff.additions_count >= 2
    assert diff.deletions_count >= 1


def test_us14_patch_generator_generates_diff_from_finding():
    """US 14: Verifies PatchGenerator creates standard unified diff with valid hunks."""
    gen = PatchGenerator()
    original_code = (
        "import os\n"
        "def backup(fn):\n"
        "    os.system('tar -czf ' + fn)\n"
    )

    finding = AuditFinding(
        title="Command Injection",
        description="os.system call",
        start_line=3,
        end_line=3,
        remediation_code="subprocess.run(['tar', '-czf', fn], check=True)",
    )

    modified_code, diff = gen.generate_remediation(original_code, finding, file_name="backup.py")

    assert "subprocess.run(['tar', '-czf', fn], check=True)" in modified_code
    assert "--- a/backup.py" in diff.raw_diff
    assert "+++ b/backup.py" in diff.raw_diff
    assert len(diff.hunks) >= 1
    assert diff.additions_count == 1
    assert diff.deletions_count == 1


def test_us14_patch_generator_multiline_remediation_replacement():
    """US 14: Verifies replacing multi-line spans (e.g. lines 2 to 4) with single or multi-line fix."""
    gen = PatchGenerator()
    original_code = (
        "def calculate():\n"
        "    a = 1\n"
        "    b = 2\n"
        "    c = 3\n"
        "    return a + b + c\n"
    )

    finding = AuditFinding(
        title="Inefficient",
        description="Multi-line replacement",
        start_line=2,
        end_line=4,
        remediation_code="total = sum([1, 2, 3])",
    )

    modified_code, diff = gen.generate_remediation(original_code, finding, file_name="calc.py")

    assert "    total = sum([1, 2, 3])" in modified_code
    assert "a = 1" not in modified_code
    assert "b = 2" not in modified_code
    assert "c = 3" not in modified_code
    assert diff.deletions_count == 3
    assert diff.additions_count == 1


def test_us14_finding_to_dict_includes_remediation_fields():
    """US 14: Verifies serialization preserves remediation_code and remediation_steps."""
    finding = AuditFinding(
        title="Weak Hash",
        description="MD5 in use",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        remediation_code="hashlib.sha256(data).digest()",
        remediation_steps=["1. Replace md5 with sha256.", "2. Update tests."],
    )

    data = finding.to_dict()
    assert data["remediation_code"] == "hashlib.sha256(data).digest()"
    assert data["remediation_steps"] == ["1. Replace md5 with sha256.", "2. Update tests."]


def test_us14_patch_generator_missing_remediation_raises_value_error():
    """US 14: Verifies PatchGenerator raises ValueError when finding lacks remediation code."""
    gen = PatchGenerator()
    finding = AuditFinding(title="No Fix", description="", start_line=1, end_line=1)

    with pytest.raises(ValueError, match="No remediation code available"):
        gen.generate_remediation("code = 1\n", finding)