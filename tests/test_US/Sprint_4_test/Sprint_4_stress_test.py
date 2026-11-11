from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import random
import pytest

from app.analysis.cross_file import CrossFileContextResolver
from app.core.enums import Confidence, FindingCategory, Language, PatchStatus, Severity
from app.core.models.audit import AuditFinding, AuditReport
from app.core.models.code import SourceFile
from app.core.models.patch import Patch, PatchDiff
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupManager
from app.patches.generator import PatchGenerator
from app.patches.validator import PatchValidator
from app.services.audit_service import AuditService
from app.services.patch_service import PatchService


class VirtualMemoryFileSystem(LocalFileSystem):
    """In-memory filesystem for deterministic stress test isolation."""

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

    def write_text(self, path, data, encoding='utf-8') -> None:
        norm = Path(path).as_posix()
        self._files[norm] = data
        self._files[str(path)] = data


# -----------------------------------------------------------------------------
# Stress Test 1: US 10 Edge Cases & Clamping
# -----------------------------------------------------------------------------
def test_stress_us10_risk_score_clamping_and_extreme_inputs():
    """Verify extreme, negative, oversized, and mixed-case risk score calculations."""
    # Negative override clamped to 0.0
    f_neg = AuditFinding(
        title="Negative Score",
        description="Test",
        severity=Severity.LOW,
        risk_score=-50.0,
    )
    assert f_neg.risk_score == 0.0

    # Oversized override clamped to 10.0
    f_huge = AuditFinding(
        title="Oversized Score",
        description="Test",
        severity=Severity.CRITICAL,
        risk_score=999.99,
    )
    assert f_huge.risk_score == 10.0

    # Dynamic setter clamping
    f_neg.risk_score = 15.0
    assert f_neg.risk_score == 10.0
    f_neg.risk_score = -5.0
    assert f_neg.risk_score == 0.0

    # Mixed-case severity string resolution
    class CustomSeverity:
        def __init__(self, val):
            self.value = val

    f_custom = AuditFinding(
        title="Custom Severity",
        description="Test",
        severity=CustomSeverity("critical"),
        confidence=Confidence.HIGH,
    )
    assert f_custom.risk_score == 10.0


# -----------------------------------------------------------------------------
# Stress Test 2: US 10 Massive Finding Volume (1,000 Findings)
# -----------------------------------------------------------------------------
def test_stress_us10_massive_finding_prioritization_and_filtering():
    """Stress test prioritization and sorting across 1,000 randomized findings."""
    random.seed(42)
    severities = list(Severity)
    confidences = list(Confidence)
    categories = list(FindingCategory)

    findings = []
    for i in range(1000):
        sev = random.choice(severities)
        conf = random.choice(confidences)
        cat = random.choice(categories)
        f = AuditFinding(
            title=f"Stress Finding #{i}",
            description=f"Auto-generated stress test finding index {i}",
            category=cat,
            severity=sev,
            confidence=conf,
            file_path=f"src/module_{i % 50}/file_{i % 10}.py",
            start_line=(i * 3) % 200 + 1,
            end_line=(i * 3) % 200 + 2,
        )
        assert 0.0 <= f.risk_score <= 10.0
        findings.append(f)

    report = AuditReport(
        job_id="stress-job-1000",
        project_id="stress-proj-1000",
        findings=findings,
    )

    prioritized = report.get_prioritized_findings()
    assert len(prioritized) == 1000

    # Ensure strictly descending risk order
    for idx in range(len(prioritized) - 1):
        assert prioritized[idx].risk_score >= prioritized[idx + 1].risk_score

    # Test filtering under heavy load
    critical_only = report.get_prioritized_findings(min_severity=Severity.CRITICAL)
    assert all(f.severity == Severity.CRITICAL for f in critical_only)

    high_risk_only = report.get_prioritized_findings(min_risk_score=7.0)
    assert all(f.risk_score >= 7.0 for f in high_risk_only)

    # Statistical consistency
    assert 0.0 < report.average_risk_score <= 10.0
    assert report.max_risk_score == prioritized[0].risk_score


# -----------------------------------------------------------------------------
# Stress Test 3: US 12 Unicode, Special Characters & JSON Serialization
# -----------------------------------------------------------------------------
def test_stress_us12_evidence_unicode_special_chars_json_roundtrip():
    """Verify evidence handling with emojis, non-ASCII text, quotes, and JSON serialization."""
    evidence_data = {
        "pattern": "SELECT * FROM users WHERE id = '%s'",
        "injected_payload": "1' OR '1'='1'; DROP TABLE users; -- 🚨",
        "developer_comment": "# चेतावनी: यह कोड असुरक्षित है (Warning: insecure code)",
        "nested_trace": {
            "depth": 3,
            "symbols": ["query()", "execute()", "cursor()"],
            "raw_escape": "Newline:\nTab:\tQuote:\"Slash:\\",
        },
    }

    finding = AuditFinding(
        title="SQL Injection 🚨",
        description="Critical SQL injection vulnerability detected",
        file_path="src/api/auth.py",
        evidence=evidence_data,
        risk_explanation="Attackers can bypass authentication and wipe the database.",
        exploit_scenario="Send `' OR 1=1 --` into username parameter.",
    )

    data = finding.to_dict()
    assert data["evidence"]["injected_payload"] == evidence_data["injected_payload"]
    assert data["evidence"]["developer_comment"] == evidence_data["developer_comment"]

    # Verify JSON serialization & deserialization without corruption
    json_str = json.dumps(data)
    loaded = json.loads(json_str)
    assert loaded["evidence"]["nested_trace"]["raw_escape"] == evidence_data["nested_trace"]["raw_escape"]


# -----------------------------------------------------------------------------
# Stress Test 4: US 14 CRLF, Deep Nesting & Indentation Preservation
# -----------------------------------------------------------------------------
def test_stress_us14_remediation_preserves_crlf_and_custom_tab_indentation():
    """Verify remediation preserves CRLF, tab, 2-space, deep 8-level nesting, and blank lines."""
    generator = PatchGenerator()

    # 1. Windows CRLF Preservation
    crlf_code = "def handle():\r\n    os.system(cmd)\r\n    return True\r\n"
    remediated_crlf = generator.apply_inline_remediation(
        original_code=crlf_code,
        start_line=2,
        end_line=2,
        replacement_code="subprocess.run(['safe_cmd'], check=True)",
    )
    assert "\r\n" in remediated_crlf
    assert "\r\n    subprocess.run(['safe_cmd'], check=True)\r\n" in remediated_crlf

    # 2. Tab Indentation Preservation
    tab_code = "def process():\n\t\tos.system(cmd)\n\t\treturn None\n"
    remediated_tab = generator.apply_inline_remediation(
        original_code=tab_code,
        start_line=2,
        end_line=2,
        replacement_code="subprocess.run(['safe_cmd'])",
    )
    assert "\t\tsubprocess.run(['safe_cmd'])" in remediated_tab

    # 3. 2-Space Indentation Preservation
    two_space_code = "def process():\n  os.system(cmd)\n  return None\n"
    remediated_two_space = generator.apply_inline_remediation(
        original_code=two_space_code,
        start_line=2,
        end_line=2,
        replacement_code="subprocess.run(['safe_cmd'])",
    )
    assert "  subprocess.run(['safe_cmd'])" in remediated_two_space

    # 4. Extreme Deep 8-Level Indentation (32 spaces)
    deep_code = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def method(self):\n"
        "            if True:\n"
        "                while True:\n"
        "                    try:\n"
        "                        with open('f') as f:\n"
        "                            for _ in range(1):\n"
        "                                os.system('vulnerable')\n"
    )
    remediated_deep = generator.apply_inline_remediation(
        original_code=deep_code,
        start_line=9,
        end_line=9,
        replacement_code="subprocess.run(['safe'])\nlogger.info('secure')",
    )
    assert "                                subprocess.run(['safe'])" in remediated_deep
    assert "                                logger.info('secure')" in remediated_deep

    # 5. Clean Blank Line Preservation without trailing spaces
    multiline_with_blanks = (
        "# Step 1: validate\n"
        "\n"
        "# Step 2: execute\n"
        "subprocess.run(['safe'])"
    )
    remediated_blanks = generator.apply_inline_remediation(
        original_code="def run():\n    os.system(cmd)\n",
        start_line=2,
        end_line=2,
        replacement_code=multiline_with_blanks,
    )
    lines = remediated_blanks.splitlines()
    assert lines[2] == ""  # Blank line must have NO trailing spaces


# -----------------------------------------------------------------------------
# Stress Test 5: US 14 File Boundary Edge Cases (Line 1, EOF, Expansions)
# -----------------------------------------------------------------------------
def test_stress_us14_remediation_file_boundary_edge_cases():
    """Verify remediation at line 1, end-of-file, and large expansions/contractions."""
    generator = PatchGenerator()

    # Replacement at line 1 (first line of file)
    code_header = "API_KEY = 'hardcoded_secret_12345'\nimport os\n"
    remediated_header = generator.apply_inline_remediation(
        original_code=code_header,
        start_line=1,
        end_line=1,
        replacement_code="import os\nAPI_KEY = os.environ.get('API_KEY')",
    )
    assert remediated_header.startswith("import os\nAPI_KEY = os.environ.get('API_KEY')")

    # Replacement at EOF without trailing newline
    code_eof = "def run():\n    return False"
    remediated_eof = generator.apply_inline_remediation(
        original_code=code_eof,
        start_line=2,
        end_line=2,
        replacement_code="return True",
    )
    assert remediated_eof == "def run():\n    return True"

    # Expanding 1 line into 10 lines
    ten_lines = "\n".join([f"step_{i} = {i}" for i in range(10)])
    remediated_expanded = generator.apply_inline_remediation(
        original_code="def execute():\n    pass\n",
        start_line=2,
        end_line=2,
        replacement_code=ten_lines,
    )
    assert "    step_9 = 9" in remediated_expanded


# -----------------------------------------------------------------------------
# Stress Test 6: US 17 Async Functions, Properties & Closures
# -----------------------------------------------------------------------------
def test_stress_us17_async_decorators_properties_and_closures():
    """Verify cross-file resolution handles async def, properties, and nested closures."""
    advanced_code = (
        "class GatewayService:\n"
        "    @property\n"
        "    def connection_string(self):\n"
        "        return 'db://secret'\n"
        "\n"
        "    @classmethod\n"
        "    async def fetch_async(cls, endpoint):\n"
        "        def inner_retry(att):\n"
        "            import os\n"
        "            os.system(endpoint)\n"
        "        return inner_retry(1)\n"
    )

    resolver = CrossFileContextResolver()

    # Line 4: inside property getter
    prop_comp = resolver.resolve_enclosing_component(advanced_code, line_number=4, language=Language.PYTHON)
    assert prop_comp is not None
    assert prop_comp["component_name"] == "connection_string"

    # Line 10: inside inner_retry closure
    inner_comp = resolver.resolve_enclosing_component(advanced_code, line_number=10, language=Language.PYTHON)
    assert inner_comp is not None
    assert inner_comp["component_name"] == "inner_retry"

    # Line 7: inside fetch_async method definition (Line 11 is return statement of fetch_async)
    async_comp = resolver.resolve_enclosing_component(advanced_code, line_number=7, language=Language.PYTHON)
    assert async_comp is not None
    assert async_comp["component_name"] == "fetch_async"
    assert async_comp["component_type"] in ("async_function", "function")

    ret_comp = resolver.resolve_enclosing_component(advanced_code, line_number=11, language=Language.PYTHON)
    assert ret_comp is not None
    assert ret_comp["component_name"] == "fetch_async"


# -----------------------------------------------------------------------------
# Stress Test 7: US 17 Identical Method Name Disambiguation Across Files
# -----------------------------------------------------------------------------
def test_stress_us17_disambiguate_methods_with_identical_names():
    """Verify multiple files defining identically named methods link accurately."""
    user_repo = SourceFile(
        file_path="repos/user_repo.py",
        relative_path="repos/user_repo.py",
        content="def execute_query(sql):\n    pass\n",
        language=Language.PYTHON,
    )
    order_repo = SourceFile(
        file_path="repos/order_repo.py",
        relative_path="repos/order_repo.py",
        content="def execute_query(sql):\n    pass\n",
        language=Language.PYTHON,
    )
    caller = SourceFile(
        file_path="services/checkout.py",
        relative_path="services/checkout.py",
        content=(
            "import repos.order_repo\n"
            "def checkout():\n"
            "    repos.order_repo.execute_query('SELECT')\n"
        ),
        language=Language.PYTHON,
    )

    fs = VirtualMemoryFileSystem({
        "repos/user_repo.py": user_repo.content,
        "repos/order_repo.py": order_repo.content,
        "services/checkout.py": caller.content,
    })

    resolver = CrossFileContextResolver(filesystem=fs)
    callers = resolver.find_callers("execute_query", "repos/order_repo.py", [user_repo, order_repo, caller])

    assert len(callers) >= 1
    assert any(c["component_name"] == "checkout" for c in callers)


# -----------------------------------------------------------------------------
# Stress Test 8: US 17 Syntax Error Resilience in Repository Source Files
# -----------------------------------------------------------------------------
def test_stress_us17_syntax_error_resilience_in_source_files():
    """Verify resolver does NOT crash when repository contains broken source files."""
    broken_code = "def unclosed_function(x, y:\n  pass"
    valid_code = "def safe_entry():\n    return 42\n"

    broken_file = SourceFile(file_path="broken.py", relative_path="broken.py", content=broken_code, language=Language.PYTHON)
    valid_file = SourceFile(file_path="valid.py", relative_path="valid.py", content=valid_code, language=Language.PYTHON)

    resolver = CrossFileContextResolver()
    # Enclosing component on broken file should fallback cleanly to regex or None, without raising exception
    comp = resolver.resolve_enclosing_component(broken_code, line_number=2, language=Language.PYTHON)
    assert comp is not None or comp is None  # Must not raise

    callers = resolver.find_callers("safe_entry", "valid.py", [broken_file, valid_file])
    assert isinstance(callers, list)


# -----------------------------------------------------------------------------
# Stress Test 9: US 20 Semantic Bytecode Syntax Validation
# -----------------------------------------------------------------------------
def test_stress_us20_semantic_bytecode_syntax_rejection():
    """Verify validator catches semantic syntax errors that grammar parsers alone miss."""
    validator = PatchValidator()

    semantic_errors = [
        ("return outside function", "return 42\n"),
        ("yield outside function", "yield 'item'\n"),
        ("duplicate parameters", "def collide(x, x): pass\n"),
        ("break outside loop", "break\n"),
        ("continue outside loop", "continue\n"),
    ]

    for label, bad_code in semantic_errors:
        is_valid, err = validator.validate_virtual_syntax(bad_code, language=Language.PYTHON)
        assert is_valid is False, f"Failed to reject: {label}"
        assert err is not None


# -----------------------------------------------------------------------------
# Stress Test 10: US 20 Adversarial Corrupted Payloads
# -----------------------------------------------------------------------------
def test_stress_us20_adversarial_malformed_patch_syntax_validation():
    """Stress test pre-application syntax validator with hostile, corrupted payloads."""
    validator = PatchValidator()

    adversarial_payloads = [
        ("unterminated_string.py", "x = 'this string never closes\ndef foo(): pass"),
        ("invalid_dedent.py", "def broken():\n    if True:\n        pass\n      x = 1"),
        ("unmatched_brackets.py", "data = [[1, 2, 3, (4, 5, {6: 7})]]}"),
        ("reserved_keyword_abuse.py", "def class(for, while): return async"),
        ("unicode_homoglyphs.py", "dеf sаfе():\n    pass"),  # Cyrillic 'е' and 'а'
        ("single_giant_line.py", "x = " + " + ".join(str(i) for i in range(1000)) + " + ("),
        ("utf8_bom.py", "\ufeffdef clean_bom():\n    return True\n"),
    ]

    for fname, payload in adversarial_payloads:
        is_valid, err = validator.validate_virtual_syntax(payload, file_path=fname)
        if "utf8_bom" in fname:
            # Valid Python with BOM must pass cleanly
            assert is_valid is True
        else:
            assert is_valid is False, f"Payload {fname} should have failed syntax validation"
            assert err is not None


# -----------------------------------------------------------------------------
# Stress Test 11: US 20 High-Concurrency Race Condition Protection
# -----------------------------------------------------------------------------
def test_stress_us20_multithreaded_concurrent_patch_application(tmp_path: Path):
    """Stress test concurrent patch applications under thread contention."""
    target_file = tmp_path / "shared_service.py"
    base_code = "count = 0\n"
    target_file.write_text(base_code, encoding="utf-8")

    applier = PatchApplier(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))

    def attempt_patch(idx: int):
        candidate_code = f"count = {idx}\n"
        patch = Patch(
            file_path=target_file,
            original_code=base_code,
            modified_code=candidate_code,
            diff=PatchDiff(raw_diff="", additions_count=1, deletions_count=1, hunks=[]),
        )
        try:
            return applier.apply_patch(patch)
        except Exception:
            return False

    # Dispatch 10 concurrent threads attempting to mutate the same file
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(attempt_patch, range(1, 11)))

    assert any(results) is True
    final_content = target_file.read_text(encoding="utf-8")
    assert "count =" in final_content
    is_valid, _ = PatchValidator().validate_virtual_syntax(final_content, file_path=target_file)
    assert is_valid is True


# -----------------------------------------------------------------------------
# Stress Test 12: End-to-End Enterprise Polyglot Audit & Remediation Pipeline
# -----------------------------------------------------------------------------
def test_stress_sprint4_full_polyglot_enterprise_pipeline_stress_test():
    """
    Comprehensive integration test of all Sprint 4 features:
    US 10 (Prioritization), US 12 (Evidence), US 14 (Remediation),
    US 17 (Component Linking), US 20 (Pre-Patch QA Validation).
    """
    python_vuln = (
        "import os\n"
        "\n"
        "def execute_user_command(user_cmd):\n"
        "    os.system(user_cmd)\n"
    )
    python_caller = (
        "from app.server import execute_user_command\n"
        "\n"
        "def handle_request(req):\n"
        "    execute_user_command(req.get('cmd'))\n"
    )

    sf_vuln = SourceFile(
        file_path="app/server.py",
        relative_path="app/server.py",
        content=python_vuln,
        language=Language.PYTHON,
    )
    sf_caller = SourceFile(
        file_path="app/api.py",
        relative_path="app/api.py",
        content=python_caller,
        language=Language.PYTHON,
    )

    fs = VirtualMemoryFileSystem({
        "app/server.py": python_vuln,
        "app/api.py": python_caller,
    })

    class PolyglotScanner:
        def scan_project(self, project):
            return [sf_vuln, sf_caller]

    cross_resolver = CrossFileContextResolver(filesystem=fs)
    service = AuditService(
        scanner=PolyglotScanner(),
        filesystem=fs,
        cross_file_resolver=cross_resolver,
    )

    project = Project(name="PolyglotSprint4Stress", root_path=".")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    assert report.total_findings > 0
    assert report.max_risk_score >= 8.0

    # 1. Verify US 10: Findings sorted by risk_score
    prioritized = report.get_prioritized_findings()
    assert prioritized[0].risk_score == report.max_risk_score

    # 2. Verify US 12: Evidence & Risk Explanations
    top_finding = prioritized[0]
    assert top_finding.evidence is not None
    assert top_finding.risk_explanation is not None
    assert top_finding.exploit_scenario is not None

    # 3. Verify US 14: Remediation Code & Steps
    assert top_finding.remediation_code is not None
    assert len(top_finding.remediation_steps) >= 1

    # 4. Verify US 17: Multi-Component Linking
    assert len(top_finding.related_components) >= 1
    comp_names = [c["component_name"] for c in top_finding.related_components]
    assert "execute_user_command" in comp_names

    # 5. Verify US 20: Generate remediation patch and pre-validate syntax
    generator = PatchGenerator()
    modified_code, diff = generator.generate_remediation(
        original_code=python_vuln,
        finding=top_finding,
    )
    assert diff.additions_count >= 1

    validator = PatchValidator(filesystem=fs)
    is_valid, err = validator.validate_virtual_syntax(modified_code, language=Language.PYTHON)
    assert is_valid is True, f"Generated remediation has invalid syntax: {err}"


# -----------------------------------------------------------------------------
# Stress Test 13: US 20 Polyglot Multi-Language Pre-Patch Validation
# -----------------------------------------------------------------------------
def test_stress_us20_polyglot_multilanguage_syntax_validation():
    """Verify pre-application validator catches syntax errors across C++, Java, JS, and Python."""
    validator = PatchValidator()

    # Broken JavaScript: unclosed function parameter
    bad_js = "const handler = async (req, res => { return res.send(400); };"
    is_valid_js, err_js = validator.validate_virtual_syntax(bad_js, language=Language.JAVASCRIPT)
    assert is_valid_js is False
    assert "Tree-sitter detected syntax errors in Javascript" in err_js

    # Valid JavaScript
    good_js = "const handler = async (req, res) => { return res.send(200); };"
    is_valid_good_js, _ = validator.validate_virtual_syntax(good_js, language=Language.JAVASCRIPT)
    assert is_valid_good_js is True

    # Broken Java: missing closing brace and type violation
    bad_java = "public class SafeAuth { public void login( { int x = 1; } }"
    is_valid_java, err_java = validator.validate_virtual_syntax(bad_java, language=Language.JAVA)
    assert is_valid_java is False
    assert "Tree-sitter detected syntax errors in Java" in err_java

    # Valid Java
    good_java = "public class SafeAuth { public void login() { int x = 1; } }"
    is_valid_good_java, _ = validator.validate_virtual_syntax(good_java, language=Language.JAVA)
    assert is_valid_good_java is True

    # Broken C++: malformed template declaration
    bad_cpp = "template<class T void compute() { return; }"
    is_valid_cpp, err_cpp = validator.validate_virtual_syntax(bad_cpp, language=Language.CPP)
    assert is_valid_cpp is False
    assert "Tree-sitter detected syntax errors in Cpp" in err_cpp

    # Valid C++
    good_cpp = "template<typename T> void compute() { return; }"
    is_valid_good_cpp, _ = validator.validate_virtual_syntax(good_cpp, language=Language.CPP)
    assert is_valid_good_cpp is True


# -----------------------------------------------------------------------------
# Stress Test 14: US 17 Diamond & Multi-Hop Call Graph Resolution
# -----------------------------------------------------------------------------
def test_stress_us17_diamond_and_multihop_call_graph_resolution():
    """Stress test diamond dependency graph linking across 4 interconnected modules."""
    mod_d = SourceFile(
        file_path="src/core_d.py",
        relative_path="src/core_d.py",
        content=(
            "def compute_hash(data):\n"
            "    import hashlib\n"
            "    return hashlib.sha256(data.encode()).hexdigest()\n"
        ),
        language=Language.PYTHON,
    )
    mod_b = SourceFile(
        file_path="src/service_b.py",
        relative_path="src/service_b.py",
        content=(
            "from src.core_d import compute_hash\n"
            "def process_b(payload):\n"
            "    return compute_hash(payload)\n"
        ),
        language=Language.PYTHON,
    )
    mod_c = SourceFile(
        file_path="src/service_c.py",
        relative_path="src/service_c.py",
        content=(
            "import src.core_d\n"
            "def process_c(payload):\n"
            "    return src.core_d.compute_hash(payload)\n"
        ),
        language=Language.PYTHON,
    )
    mod_a = SourceFile(
        file_path="src/service_a.py",
        relative_path="src/service_a.py",
        content=(
            "from src.service_b import process_b\n"
            "from src.service_c import process_c\n"
            "def orchestrate(val):\n"
            "    return process_b(val) + process_c(val)\n"
        ),
        language=Language.PYTHON,
    )

    all_files = [mod_a, mod_b, mod_c, mod_d]
    fs = VirtualMemoryFileSystem({f.file_path: f.content for f in all_files})
    resolver = CrossFileContextResolver(filesystem=fs)

    # Find callers of compute_hash: should find both process_b and process_c
    callers = resolver.find_callers("compute_hash", "src/core_d.py", all_files)
    caller_names = {c["component_name"] for c in callers}
    assert "process_b" in caller_names
    assert "process_c" in caller_names

    # Finding on compute_hash attaches callers cleanly
    finding = AuditFinding(
        title="Weak Hashing",
        description="Verify hash strength",
        file_path="src/core_d.py",
        start_line=3,
        end_line=3,
        code_snippet="return hashlib.sha256(data.encode()).hexdigest()",
    )
    enriched = resolver.link_finding_components(finding, source_file=mod_d, all_project_files=all_files)
    rel_names = {c["component_name"] for c in enriched.related_components}
    assert "compute_hash" in rel_names
    assert "process_b" in rel_names
    assert "process_c" in rel_names


# -----------------------------------------------------------------------------
# Stress Test 15: US 20 Concurrency Chaos Monkey (Simultaneous Apply + Rollback)
# -----------------------------------------------------------------------------
def test_stress_us20_concurrency_chaos_monkey_apply_and_rollback(tmp_path: Path):
    """
    Chaos Monkey stress test: 20 concurrent threads randomly issuing apply_patch and
    rollback_patch under heavy contention. Verifies mutual exclusion and data integrity.
    """
    target = tmp_path / "bank_account.py"
    initial_code = "balance = 1000\n"
    target.write_text(initial_code, encoding="utf-8")

    backup_dir = tmp_path / "chaos_backups"
    service = PatchService(
        backup_manager=BackupManager(backup_dir=backup_dir),
        filesystem=LocalFileSystem(),
    )

    # Pre-generate 5 patches
    patches = []
    for i in range(5):
        p = service.propose_patch(target, f"balance = 1000 + {i * 10}\n")
        patches.append(p)

    def worker_action(thread_id: int):
        target_patch = patches[thread_id % len(patches)]
        action = thread_id % 3
        try:
            if action == 0:
                return service.validate_and_apply(target_patch.patch_id)
            elif action == 1:
                return service.apply_patch(target_patch.patch_id)
            else:
                return service.rollback_patch(target_patch.patch_id)
        except Exception:
            # Expected contention rejections (e.g. stale patch or not applied rollback)
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker_action, range(20)))

    # Disk file must never be corrupt or zero-byte
    final_content = target.read_text(encoding="utf-8")
    assert "balance = 1000" in final_content
    # Syntax check on disk file must pass cleanly
    validator = PatchValidator()
    is_valid, _ = validator.validate_virtual_syntax(final_content, file_path=target)
    assert is_valid is True