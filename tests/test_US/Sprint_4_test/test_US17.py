from pathlib import Path
import pytest

from app.analysis.cross_file import CrossFileContextResolver
from app.core.enums import Confidence, FindingCategory, Language, Severity
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.services.audit_service import AuditService


class InMemoryFileSystem(LocalFileSystem):
    """In-memory file system mock for deterministic multi-file cross-component tests."""

    def __init__(self, virtual_files=None):
        self._files = virtual_files or {}

    def exists(self, path) -> bool:
        norm = Path(path).as_posix()
        return norm in self._files or str(path) in self._files

    def read_text(self, path, encoding='utf-8') -> str:
        norm = Path(path).as_posix()
        if norm in self._files:
            return self._files[norm]
        if str(path) in self._files:
            return self._files[str(path)]
        raise FileNotFoundError(f"File {path} not found in virtual filesystem.")


def test_us17_finding_related_components_defaults_and_add():
    """Verify related_components initialization, addition, and JSON serialization."""
    finding = AuditFinding(
        title="SQL Injection",
        description="Raw SQL query concatenation",
        file_path="app/db/user.py",
        start_line=12,
        end_line=14,
    )
    assert finding.related_components == []

    finding.add_related_component(
        component_name="get_user_by_id",
        component_type="function",
        file_path="app/db/user.py",
        line_number=10,
        relation="enclosing_function",
        metadata={"end_line": 20},
    )

    finding.add_related_component(
        component_name="handle_login",
        component_type="caller",
        file_path="app/api/auth.py",
        line_number=45,
        relation="caller",
    )

    assert len(finding.related_components) == 2
    assert finding.related_components[0]["component_name"] == "get_user_by_id"
    assert finding.related_components[0]["relation"] == "enclosing_function"
    assert finding.related_components[1]["component_name"] == "handle_login"
    assert finding.related_components[1]["relation"] == "caller"

    data = finding.to_dict()
    assert "related_components" in data
    assert len(data["related_components"]) == 2
    assert data["related_components"][0]["component_name"] == "get_user_by_id"


def test_us17_cross_file_resolve_enclosing_function_python_ast():
    """Verify AST resolution accurately detects enclosing function and line boundaries."""
    code = (
        "import os\n"
        "\n"
        "def helper():\n"
        "    return 42\n"
        "\n"
        "def execute_query(user_id):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return query\n"
        "\n"
        "print('done')\n"
    )

    resolver = CrossFileContextResolver()
    comp = resolver.resolve_enclosing_component(code, line_number=7, language=Language.PYTHON)

    assert comp is not None
    assert comp["component_name"] == "execute_query"
    assert comp["component_type"] == "function"
    assert comp["start_line"] == 6
    assert comp["end_line"] == 8


def test_us17_cross_file_resolve_enclosing_class_and_methods():
    """Verify resolution detects class and method components."""
    code = (
        "class SecurityManager:\n"
        "    def __init__(self):\n"
        "        pass\n"
        "\n"
        "    def run_command(self, cmd):\n"
        "        import subprocess\n"
        "        subprocess.run(cmd, shell=True)\n"
    )

    resolver = CrossFileContextResolver()
    # Line 7 is inside run_command
    comp = resolver.resolve_enclosing_component(code, line_number=7, language=Language.PYTHON)

    assert comp is not None
    assert comp["component_name"] == "run_command"
    assert comp["component_type"] == "function"
    assert comp["start_line"] == 5


def test_us17_cross_file_find_callers_across_files():
    """Verify find_callers discovers functions that invoke a target symbol from other files."""
    file_a = SourceFile(
        file_path="src/database.py",
        relative_path="src/database.py",
        content="def execute_raw(sql):\n    pass\n",
        language=Language.PYTHON,
    )
    file_b = SourceFile(
        file_path="src/controllers/auth.py",
        relative_path="src/controllers/auth.py",
        content=(
            "from src.database import execute_raw\n"
            "\n"
            "def login_user(username):\n"
            "    execute_raw(username)\n"
        ),
        language=Language.PYTHON,
    )
    file_c = SourceFile(
        file_path="src/controllers/admin.py",
        relative_path="src/controllers/admin.py",
        content=(
            "import src.database\n"
            "\n"
            "def drop_tables():\n"
            "    src.database.execute_raw('DROP')\n"
        ),
        language=Language.PYTHON,
    )

    fs = InMemoryFileSystem({
        "src/database.py": file_a.content,
        "src/controllers/auth.py": file_b.content,
        "src/controllers/admin.py": file_c.content,
    })

    resolver = CrossFileContextResolver(filesystem=fs)
    callers = resolver.find_callers("execute_raw", "src/database.py", [file_a, file_b, file_c])

    assert len(callers) >= 2
    caller_names = {c["component_name"] for c in callers}
    assert "login_user" in caller_names
    assert "drop_tables" in caller_names
    for c in callers:
        assert c["relation"] == "caller"


def test_us17_cross_file_find_callees_in_snippet():
    """Verify find_callees_in_snippet identifies external component definitions invoked in a code snippet."""
    util_file = SourceFile(
        file_path="src/crypto_utils.py",
        relative_path="src/crypto_utils.py",
        content=(
            "def weak_hash(data):\n"
            "    import hashlib\n"
            "    return hashlib.md5(data.encode()).hexdigest()\n"
        ),
        language=Language.PYTHON,
    )
    service_file = SourceFile(
        file_path="src/auth_service.py",
        relative_path="src/auth_service.py",
        content="pass\n",
        language=Language.PYTHON,
    )

    snippet = "token = weak_hash(user_input)\nprint(token)\n"
    resolver = CrossFileContextResolver()
    callees = resolver.find_callees_in_snippet(snippet, [service_file, util_file], current_file="src/auth_service.py")

    assert len(callees) == 1
    assert callees[0]["component_name"] == "weak_hash"
    assert callees[0]["relation"] == "callee"
    assert callees[0]["file_path"].endswith("src/crypto_utils.py")


def test_us17_link_finding_components_end_to_end():
    """Verify link_finding_components attaches enclosing function, callers, and callees to a finding."""
    db_file = SourceFile(
        file_path="src/db.py",
        relative_path="src/db.py",
        content=(
            "def run_sql(query):\n"
            "    import sqlite3\n"
            "    conn = sqlite3.connect('test.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        ),
        language=Language.PYTHON,
    )
    caller_file = SourceFile(
        file_path="src/routes.py",
        relative_path="src/routes.py",
        content=(
            "from src.db import run_sql\n"
            "\n"
            "def get_profile(name):\n"
            "    return run_sql(name)\n"
        ),
        language=Language.PYTHON,
    )

    fs = InMemoryFileSystem({
        "src/db.py": db_file.content,
        "src/routes.py": caller_file.content,
    })

    resolver = CrossFileContextResolver(filesystem=fs)
    finding = AuditFinding(
        title="SQL Injection",
        description="cursor.execute with untrusted parameter",
        file_path="src/db.py",
        start_line=5,
        end_line=5,
        code_snippet="cursor.execute(query)",
    )

    enriched = resolver.link_finding_components(finding, source_file=db_file, all_project_files=[db_file, caller_file])

    relations = [c["relation"] for c in enriched.related_components]
    names = [c["component_name"] for c in enriched.related_components]

    assert "enclosing_function" in relations
    assert "run_sql" in names
    assert "caller" in relations
    assert "get_profile" in names


def test_us17_audit_service_populates_related_components_in_pipeline():
    """Verify AuditService end-to-end audit enriches findings with related components."""
    file1 = SourceFile(
        file_path="app/vulnerable.py",
        relative_path="app/vulnerable.py",
        content=(
            "import os\n"
            "\n"
            "def dangerous_exec(cmd):\n"
            "    os.system(cmd)\n"
        ),
        language=Language.PYTHON,
    )
    file2 = SourceFile(
        file_path="app/main.py",
        relative_path="app/main.py",
        content=(
            "from app.vulnerable import dangerous_exec\n"
            "\n"
            "def entrypoint():\n"
            "    dangerous_exec('whoami')\n"
        ),
        language=Language.PYTHON,
    )

    fs = InMemoryFileSystem({
        "app/vulnerable.py": file1.content,
        "app/main.py": file2.content,
    })

    class MockScanner:
        def scan_project(self, project):
            return [file1, file2]

    service = AuditService(
        scanner=MockScanner(),
        filesystem=fs,
        cross_file_resolver=CrossFileContextResolver(filesystem=fs),
    )

    project = Project(name="US17Project", root_path=".")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    assert report.total_findings > 0
    # Find the command injection finding in dangerous_exec
    cmd_finding = next((f for f in report.findings if "dangerous_exec" in [c["component_name"] for c in f.related_components]), None)
    assert cmd_finding is not None
    related = cmd_finding.related_components
    assert any(c["relation"] == "enclosing_function" and c["component_name"] == "dangerous_exec" for c in related)
    assert any(c["relation"] == "caller" and c["component_name"] == "entrypoint" for c in related)