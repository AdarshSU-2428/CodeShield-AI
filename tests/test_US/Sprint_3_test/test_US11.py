from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.cross_file import CrossFileContextResolver
from app.core.enums import Language
from app.core.interfaces.llm import LLMClient
from app.core.interfaces.vector_store import VectorStore
from app.core.models.audit import AuditFinding, FindingCategory, Severity
from app.core.models.code import SourceFile


def test_us11_extract_imports_across_multiple_languages():
    """Verify import parsing across Python, JavaScript, Java, and C/C++."""
    resolver = CrossFileContextResolver()

    # 1. Python imports
    py_code = (
        "import os\n"
        "import auth\n"
        "from services.database import execute_query\n"
        "from utils.helpers import sanitize\n"
    )
    py_imports = resolver.extract_imports(py_code, Language.PYTHON)
    assert "auth" in py_imports
    assert "services" in py_imports
    assert "services/database" in py_imports
    assert "utils" in py_imports

    # 2. JavaScript / TypeScript imports
    js_code = (
        "import React from 'react';\n"
        "import dbHandler from './dbHandler';\n"
        "const authService = require('../services/authService');\n"
    )
    js_imports = resolver.extract_imports(js_code, Language.JAVASCRIPT)
    assert "dbHandler" in js_imports
    assert "authService" in js_imports

    # 3. C / C++ includes
    c_code = (
        '#include <stdio.h>\n'
        '#include "crypto_helper.h"\n'
        '#include "network/socket_util.h"\n'
    )
    c_imports = resolver.extract_imports(c_code, Language.C)
    assert "crypto_helper" in c_imports
    assert "socket_util" in c_imports

    # 4. Java imports
    java_code = (
        "package com.example.app;\n"
        "import java.util.List;\n"
        "import com.example.services.PaymentService;\n"
        "import static com.example.utils.Validator.checkNull;\n"
    )
    java_imports = resolver.extract_imports(java_code, Language.JAVA)
    assert "PaymentService" in java_imports
    assert "Validator" in java_imports


def test_us11_resolve_import_to_project_file():
    """Verify resolving imported module string to matching project SourceFile."""
    resolver = CrossFileContextResolver()

    file_a = SourceFile(
        file_path="src/controllers/user_controller.py",
        relative_path="controllers/user_controller.py",
        language=Language.PYTHON,
        content="from services.db_service import get_user",
    )
    file_b = SourceFile(
        file_path="src/services/db_service.py",
        relative_path="services/db_service.py",
        language=Language.PYTHON,
        content="def get_user(id): pass",
    )
    file_c = SourceFile(
        file_path="src/utils/crypto.py",
        relative_path="utils/crypto.py",
        language=Language.PYTHON,
        content="def hash(x): pass",
    )

    available = [file_a, file_b, file_c]

    # Resolve "db_service" or "services.db_service"
    match = resolver.resolve_import_to_file("db_service", file_a.file_path, available)
    assert match is not None
    assert match.file_path == file_b.file_path

    # Ignore self-import
    self_match = resolver.resolve_import_to_file("user_controller", file_a.file_path, available)
    assert self_match is None

    # Third party package that doesn't exist in project
    missing_match = resolver.resolve_import_to_file("requests", file_a.file_path, available)
    assert missing_match is None


def test_us11_get_imported_context_bundle_and_truncation():
    """Verify context extraction from imported files and safe size truncation."""
    resolver = CrossFileContextResolver(max_context_chars_per_file=100)

    caller_file = SourceFile(
        file_path="app/main.py",
        relative_path="main.py",
        language=Language.PYTHON,
        content="from utils import format_data\n",
    )
    # Long helper file exceeding 100 chars
    helper_file = SourceFile(
        file_path="app/utils.py",
        relative_path="utils.py",
        language=Language.PYTHON,
        content="def format_data(data):\n" + ("    # padding line\n" * 15),
    )

    context = resolver.get_imported_context(caller_file, [caller_file, helper_file])

    assert len(context) == 1
    assert context[0]["file"] == "utils.py"
    assert context[0]["type"] == "import_dependency"
    assert "[TRUNCATED CONTEXT]" in context[0]["snippet"]


def test_us11_get_semantic_context_with_mock_vector_store():
    """Verify querying ChromaDB vector store for related code snippets."""
    mock_vstore = MagicMock(spec=VectorStore)
    mock_vstore.query_similar.return_value = [
        {
            "content": "def authenticate(user, password): pass",
            "metadata": {"relative_path": "auth/service.py", "file_path": "src/auth/service.py"},
        },
        {
            # Should be excluded because it matches current file
            "content": "current file content",
            "metadata": {"relative_path": "routes/login.py", "file_path": "src/routes/login.py"},
        },
    ]

    resolver = CrossFileContextResolver(vector_store=mock_vstore)
    results = resolver.get_semantic_context(
        query="authenticate user password",
        project_id="test_proj",
        exclude_file_path="src/routes/login.py",
        top_k=2,
    )

    assert len(results) == 1
    assert results[0]["file"] == "auth/service.py"
    assert results[0]["type"] == "semantic_similarity"
    assert "authenticate" in results[0]["snippet"]


def test_us11_bundle_cross_file_context_merging():
    """Verify seamless combination of import-driven and vector-driven context."""
    mock_vstore = MagicMock(spec=VectorStore)
    mock_vstore.query_similar.return_value = [
        {
            "content": "def hash_password(pwd): pass",
            "metadata": {"relative_path": "security/hasher.py", "file_path": "src/security/hasher.py"},
        }
    ]

    resolver = CrossFileContextResolver(vector_store=mock_vstore, max_related_files=3)

    caller = SourceFile(
        file_path="app/routes.py",
        relative_path="routes.py",
        language=Language.PYTHON,
        content="import database\n",
    )
    imported_file = SourceFile(
        file_path="app/database.py",
        relative_path="database.py",
        language=Language.PYTHON,
        content="def query(sql): pass\n",
    )

    bundled = resolver.bundle_cross_file_context(
        source_file=caller,
        all_project_files=[caller, imported_file],
        project_id="proj1",
        semantic_query="security credentials",
    )

    assert len(bundled) == 2
    files = [b["file"] for b in bundled]
    assert "database.py" in files
    assert "security/hasher.py" in files


def test_us11_ai_analyzer_end_to_end_cross_file_vulnerability_detection():
    """Verify end-to-end cross-file vulnerability detection with related_files attribution."""
    mock_llm = MagicMock(spec=LLMClient)
    mock_llm.is_available.return_value = True

    # AI returns a cross-file command injection vulnerability
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Cross-File Command Injection",
                "description": "User input from routes/api.py flows without sanitization into exec_cmd() in helpers/sys_util.py.",
                "cwe_id": "CWE-78",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "start_line": 5,
                "end_line": 6,
                "code_snippet": "exec_cmd(user_command)",
                "recommendation": "Sanitize and validate arguments before passing to subprocess.",
                "is_cross_file": True,
                "related_files": ["helpers/sys_util.py"],
            }
        ]
    }

    resolver = CrossFileContextResolver()
    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm, cross_file_resolver=resolver)

    file_a = SourceFile(
        file_path="app/routes/api.py",
        relative_path="routes/api.py",
        language=Language.PYTHON,
        content="from helpers.sys_util import exec_cmd\ndef handle_req(user_command): exec_cmd(user_command)",
    )
    file_b = SourceFile(
        file_path="app/helpers/sys_util.py",
        relative_path="helpers/sys_util.py",
        language=Language.PYTHON,
        content="import os\ndef exec_cmd(cmd): os.system(cmd)",
    )

    findings = analyzer.analyze_file(
        source_file=file_a,
        all_project_files=[file_a, file_b],
    )

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, AuditFinding)
    assert finding.title == "Cross-File Command Injection"
    assert finding.category == FindingCategory.SECURITY
    assert finding.severity == Severity.CRITICAL
    assert finding.cwe_id == "CWE-78"
    assert finding.metadata.get("cross_file") is True
    assert "helpers/sys_util.py" in finding.metadata.get("related_files")
