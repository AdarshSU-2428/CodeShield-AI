from pathlib import Path
import pytest

from app.analysis.rule_engine import RuleEngine, default_rule_engine
from app.analysis.rules.base import SecurityRule
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


def create_source_file(relative_path: str, content: str, language: Language) -> SourceFile:
    """Helper to construct in-memory SourceFile instances for testing."""
    return SourceFile(
        file_path=Path(relative_path),
        relative_path=relative_path,
        content=content,
        language=language,
        size_bytes=len(content.encode("utf-8")),
    )


def test_us7_hardcoded_secret_detection():
    """Verify CWE-798 detects genuine secrets while ignoring benign placeholders."""
    vulnerable_py = create_source_file(
        "auth/config.py",
        """
        # Configuration file
        db_password = "SuperSecretDbPassword!2026"
        aws_api_key = "AKIA1234567890EXAMPLEKEY"
        safe_var = "test"
        dummy_key = "your_key_here"
        """,
        Language.PYTHON,
    )

    rule = HardcodedSecretRule()
    findings = rule.evaluate(vulnerable_py)

    assert len(findings) == 2
    cwes = [f.cwe_id for f in findings]
    assert cwes == ["CWE-798", "CWE-798"]
    assert findings[0].line_number == 3
    assert findings[1].line_number == 4


def test_us7_sql_injection_detection():
    """Verify CWE-89 detects unparameterized dynamic queries while allowing safe parameterized queries."""
    vuln_code = create_source_file(
        "repo/user_dao.py",
        """
        def get_user(cursor, user_id):
            # Vulnerable string formatting
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            # Vulnerable concatenation
            cursor.execute("SELECT name FROM accounts WHERE acc_id = " + user_id)
            # Safe parameterized query
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        """,
        Language.PYTHON,
    )

    rule = SQLInjectionRule()
    findings = rule.evaluate(vuln_code)

    assert len(findings) == 2
    assert all(f.cwe_id == "CWE-89" for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)
    assert findings[0].line_number == 4
    assert findings[1].line_number == 6


def test_us7_command_injection_detection():
    """Verify CWE-78 detects command injection across Python, JavaScript, and C."""
    py_file = create_source_file(
        "scripts/deploy.py",
        """
        import os, subprocess
        os.system("rm -rf " + target_dir)
        subprocess.run(f"echo {user_input}", shell=True)
        # Safe call
        subprocess.run(["ls", "-la"])
        """,
        Language.PYTHON,
    )

    js_file = create_source_file(
        "server/runner.js",
        """
        const { exec } = require('child_process');
        child_process.exec(userCommand);
        """,
        Language.JAVASCRIPT,
    )

    c_file = create_source_file(
        "native/shell.c",
        """
        #include <stdlib.h>
        int main() {
            system(user_command);
            return 0;
        }
        """,
        Language.C,
    )

    rule = CommandInjectionRule()
    py_findings = rule.evaluate(py_file)
    js_findings = rule.evaluate(js_file)
    c_findings = rule.evaluate(c_file)

    assert len(py_findings) == 2
    assert len(js_findings) == 1
    assert len(c_findings) == 1
    assert py_findings[0].cwe_id == "CWE-78"
    assert js_findings[0].cwe_id == "CWE-78"
    assert c_findings[0].cwe_id == "CWE-78"


def test_us7_dangerous_functions_c_and_python():
    """Verify CWE-676 flags buffer-overflow prone C APIs and unsafe Python deserialization."""
    c_code = create_source_file(
        "parser/buffer.c",
        """
        void copy_data(char *src) {
            char dest[64];
            strcpy(dest, src);
            gets(dest);
        }
        """,
        Language.C,
    )

    py_code = create_source_file(
        "worker/tasks.py",
        """
        import pickle
        def process(payload):
            obj = pickle.loads(payload)
            return eval("2 + 2")
        """,
        Language.PYTHON,
    )

    rule = DangerousFunctionRule()
    c_findings = rule.evaluate(c_code)
    py_findings = rule.evaluate(py_code)

    assert len(c_findings) == 2  # strcpy, gets
    assert len(py_findings) == 2  # pickle.loads, eval
    assert all(f.cwe_id == "CWE-676" for f in c_findings)
    assert all(f.cwe_id == "CWE-676" for f in py_findings)


def test_us7_weak_crypto_detection():
    """Verify CWE-327 catches MD5 and SHA1 usage while ignoring SHA-256."""
    code = create_source_file(
        "auth/hasher.py",
        """
        import hashlib
        def hash_password(pwd):
            # Broken
            md5_hash = hashlib.md5(pwd.encode()).hexdigest()
            sha1_hash = hashlib.sha1(pwd.encode()).hexdigest()
            # Safe
            sha256_hash = hashlib.sha256(pwd.encode()).hexdigest()
            return sha256_hash
        """,
        Language.PYTHON,
    )

    rule = WeakCryptoRule()
    findings = rule.evaluate(code)

    assert len(findings) == 2
    assert all(f.cwe_id == "CWE-327" for f in findings)
    assert all(f.severity == Severity.MEDIUM for f in findings)


def test_us7_rule_engine_multilingual_project_scan():
    """Verify RuleEngine aggregates findings across a complete multilingual codebase."""
    engine = RuleEngine()

    files = [
        create_source_file(
            "backend/app.py",
            "db_pass = 'SecretPassword1234!'\nos.system('dir ' + folder)",
            Language.PYTHON,
        ),
        create_source_file(
            "frontend/api.js",
            "const h = crypto.createHash('md5');\nchild_process.exec(cmd);",
            Language.JAVASCRIPT,
        ),
        create_source_file(
            "native/fast.c",
            "strcpy(buf, input);\nsystem(cmd);",
            Language.C,
        ),
    ]

    findings = engine.analyze_project(files)

    # 2 in Python (Secret + os.system) + 2 in JS (md5 + exec) + 2 in C (strcpy + system) = 6 total
    assert len(findings) == 6
    paths = {f.file_path for f in findings}
    assert paths == {"backend/app.py", "frontend/api.js", "native/fast.c"}


def test_us7_rule_isolation_on_faulty_rule():
    """Verify engine isolates a crashed/faulty rule without interrupting analysis."""
    class FaultyRule(SecurityRule):
        def __init__(self):
            super().__init__(
                rule_id="BUG-001",
                title="Buggy Rule",
                description="Simulates an unhandled crash in evaluation",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                cwe_id="CWE-000",
                language=Language.UNKNOWN,
                recommendation="None",
            )

        def evaluate(self, source_file: SourceFile, ast_tree=None):
            raise ZeroDivisionError("Unexpected runtime rule exception")

    engine = RuleEngine(rules=[FaultyRule(), HardcodedSecretRule()])
    test_file = create_source_file(
        "secret.py",
        "api_key = 'SuperSecretToken12345'",
        Language.PYTHON,
    )

    # Must complete safely and return the finding from the healthy rule
    findings = engine.analyze_file(test_file)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-798"
