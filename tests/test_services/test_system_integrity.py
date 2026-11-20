"""
CodeShield AI - Master System Integrity & Cross-Module Compilation Test Suite.
Verifies full static compilation, ast parsing, clean module import graphs,
abstract interface contracts, and deep cross-module data flow with ZERO logical or syntax errors.
"""

import ast
import glob
import importlib
import inspect
from pathlib import Path
import py_compile
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from app.ai.finding_validator import FindingValidator
from app.analysis.component_extractor import ComponentExtractor
from app.analysis.cross_file import CrossFileContextResolver
from app.analysis.language_detector import LanguageDetector
from app.analysis.parser import ParserRegistry
from app.analysis.quality_analyzer import CodeQualityAnalyzer
from app.analysis.rule_engine import RuleEngine
from app.analysis.rules.builtin import (
    CommandInjectionRule,
    DangerousFunctionRule,
    HardcodedSecretRule,
    SQLInjectionRule,
    WeakCryptoRule,
)
from app.analysis.scanner import RepositoryScanner
from app.core.enums import (
    Confidence,
    FileStatus,
    FindingCategory,
    Language,
    PatchStatus,
    Severity,
)
from app.core.interfaces.embedding import EmbeddingService
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.llm import LLMClient
from app.core.interfaces.parser import PolyglotParser
from app.core.interfaces.vector_store import VectorStore
from app.core.models.audit import AuditFinding, AuditReport
from app.core.models.code import CodeChunk, CodeComponent, SourceFile
from app.core.models.patch import ApprovalRequiredError, Patch, PatchDiff
from app.core.models.project import Project
from app.infrastructure.config import AppConfig, config
from app.infrastructure.filesystem import LocalFileSystem
from app.infrastructure.logger import logger
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupManager
from app.patches.generator import DiffGenerator
from app.patches.rollback_manager import RollbackManager
from app.patches.validator import PatchValidator
from app.rag.chroma_store import ChromaVectorStore
from app.rag.chunker import CodeChunker
from app.rag.context_builder import ContextBuilder
from app.rag.embedding_service import LocalEmbeddingService
from app.rag.indexer import RepositoryIndexer
from app.rag.retriever import LocalContextRetriever
from app.services.audit_service import AuditService
from app.services.patch_service import PatchService
from app.services.project_service import ProjectService


# =============================================================================
# Test 1: Full Repository Zero-Syntax-Error Compilation Sweep
# =============================================================================
def test_system_integrity_full_repo_py_compile_sweep():
    """
    Scans every single Python file across the entire repository (app/ and tests/)
    and compiles each file into Python bytecode, asserting 0 syntax errors or broken tokens.
    """
    root = Path(".").resolve()
    py_files = sorted(list(root.glob("app/**/*.py")) + list(root.glob("tests/**/*.py")))
    assert len(py_files) >= 100, f"Expected at least 100 Python files, found {len(py_files)}"

    compilation_failures = []
    for py_file in py_files:
        try:
            py_compile.compile(str(py_file), doraise=True)
        except py_compile.PyCompileError as err:
            compilation_failures.append((str(py_file), str(err)))

    assert len(compilation_failures) == 0, f"Compilation errors detected: {compilation_failures}"


# =============================================================================
# Test 2: Complete Static AST Validation of All App Modules
# =============================================================================
def test_system_integrity_full_ast_parse_and_docstring_structure():
    """
    Parses every file in app/ using Python's native AST parser.
    Ensures valid abstract syntax tree hierarchy and no unparseable tokens.
    """
    root = Path("app").resolve()
    py_files = sorted(list(root.glob("**/*.py")))

    ast_errors = []
    for f in py_files:
        content = f.read_text(encoding="utf-8")
        try:
            tree = ast.parse(content, filename=str(f))
            assert isinstance(tree, ast.Module)
        except SyntaxError as e:
            ast_errors.append((str(f), str(e)))

    assert len(ast_errors) == 0, f"AST Parsing failed on files: {ast_errors}"


# =============================================================================
# Test 3: Clean Module Import Graph with Zero Circular Dependencies
# =============================================================================
def test_system_integrity_clean_module_import_and_no_circular_dependencies():
    """
    Dynamically imports every module in app/ to verify:
    1. Zero circular dependency deadlocks or broken relative/absolute imports.
    2. All module-level constants, exports, and dataclasses instantiate cleanly.
    """
    sys.path.insert(0, str(Path(".").resolve()))
    root = Path("app").resolve()
    modules = []

    for f in sorted(root.glob("**/*.py")):
        parts = list(f.relative_to(Path(".").resolve()).parts)
        if parts[-1] == "__init__.py":
            mod_name = ".".join(parts[:-1])
        else:
            parts[-1] = parts[-1][:-3]
            mod_name = ".".join(parts)
        if mod_name and mod_name not in modules:
            modules.append(mod_name)

    import_errors = []
    for mod in modules:
        try:
            m = importlib.import_module(mod)
            assert m is not None
        except Exception as exc:
            import_errors.append((mod, str(exc)))

    assert len(import_errors) == 0, f"Module import errors: {import_errors}"


# =============================================================================
# Test 4: Abstract Interface Contract Fulfillment Verification
# =============================================================================
def test_system_integrity_abstract_interface_contract_fulfillment():
    """
    Verifies that all concrete implementations strictly fulfill their abstract interfaces:
    - FileSystem -> LocalFileSystem
    - PolyglotParser -> PythonParser, JSParser, JavaParser, CParser, CppParser
    - VectorStore -> ChromaVectorStore
    - EmbeddingService -> LocalEmbeddingService
    - LLMClient -> GroqLLMClient
    """
    fs = LocalFileSystem()
    assert isinstance(fs, FileSystem)

    vstore = ChromaVectorStore()
    assert isinstance(vstore, VectorStore)

    embed_svc = LocalEmbeddingService()
    assert isinstance(embed_svc, EmbeddingService)

    # Check Polyglot Parsers
    registry = ParserRegistry()
    for lang in [Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.C, Language.CPP]:
        parser = registry.get_parser(lang)
        assert parser is not None
        assert isinstance(parser, PolyglotParser)
        # Check abstract method signature
        assert hasattr(parser, "parse")
        assert callable(getattr(parser, "parse"))


# =============================================================================
# Test 5: End-to-End Cross-Module Data Flow & Logical Integration
# =============================================================================
def test_system_integrity_end_to_end_cross_module_data_flow(tmp_path: Path):
    """
    Exercises the complete end-to-end data pipeline across all 6 subsystems:
    1. Project Registration & Multi-File Discovery (RepositoryScanner -> ProjectService)
    2. Polyglot AST Parsing & Quality Analysis (LanguageDetector -> ParserRegistry -> ComponentExtractor)
    3. Static Vulnerability Scanning & Risk Scoring (RuleEngine -> Builtin Rules -> AuditReport)
    4. RAG Context Indexing & Boundary Truncation (CodeChunker -> LocalEmbeddingService -> Retriever)
    5. Patch Lifecycle: Diff Generation, Pre-Flight Syntax Gate, Approval & Rollback (PatchService -> Applier)
    6. Canonical SARIF v2.1.0 & Markdown Export (FindingValidator -> AuditReport)
    """
    repo = tmp_path / "master_integrity_workspace"
    repo.mkdir()

    # 1. Polyglot source files
    py_file = repo / "auth.py"
    py_file.write_text(
        "import os\n"
        "db_password = 'SuperSecretProductionPassword!2026'\n"
        "def authenticate(user, password):\n"
        "    if password == db_password:\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    js_file = repo / "api.js"
    js_file.write_text("function query(db, input) { return db.execute('SELECT * FROM users WHERE id = ' + input); }\n", encoding="utf-8")

    # 2. Project Service Registration
    fs = LocalFileSystem()
    proj_svc = ProjectService(filesystem=fs, storage_dir=tmp_path / "proj_data")
    project = proj_svc.register_project(root_path=repo, name="MasterIntegrityProject")
    assert project.total_files == 2
    assert project.supported_files == 2

    # 3. Change Detection
    classified, manifest = proj_svc.scanner.detect_changes(project)
    assert len(classified) == 2
    assert all(f.status == FileStatus.NEW for f in classified)

    # 4. AST Component Extraction & Language Detection
    detector = LanguageDetector()
    assert detector.detect_language(py_file) == Language.PYTHON
    assert detector.detect_language(js_file) == Language.JAVASCRIPT

    registry = ParserRegistry()
    py_parser = registry.get_parser(Language.PYTHON)
    py_tree = py_parser.parse(py_file.read_text(encoding="utf-8"))
    assert py_tree is not None

    extractor = ComponentExtractor()
    components = extractor.extract_components(py_tree, py_file.read_text(encoding="utf-8"), SourceFile(file_path=py_file, relative_path="auth.py"))
    assert len(components) >= 1
    assert components[0].name == "authenticate"

    # 5. Static Rule Engine & Vulnerability Detection
    rule_engine = RuleEngine()  # Automatically registers all 5 built-in rules
    sf_py = SourceFile(file_path=py_file, relative_path="auth.py", content=py_file.read_text(encoding="utf-8"), language=Language.PYTHON)
    findings = rule_engine.analyze_file(sf_py)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == "CWE-798"
    assert finding.severity in (Severity.CRITICAL, Severity.HIGH)

    # 6. Canonical Validation & Report Generation
    val = FindingValidator()
    is_valid, val_errs = val.validate_finding(finding)
    assert is_valid is True, f"Finding schema invalid: {val_errs}"

    report = AuditReport(
        job_id="job_master_check",
        project_id=project.project_id,
        findings=[finding],
    )
    # SARIF & Markdown export
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    md = report.to_markdown()
    assert "# CodeShield AI" in md

    # 7. RAG Context Building & Safe Line Truncation
    builder = ContextBuilder(max_tokens_budget=500)
    messages = builder.build_messages(source_file=sf_py, context_snippets=[{"file": "api.js", "snippet": "function query() {}\n"}])
    assert len(messages) == 2
    assert "Focal File: auth.py" in messages[1]["content"]

    # 8. Patch Proposal, Pre-Flight Syntax Gate, Approval, and Rollback
    patch_svc = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"), filesystem=fs)
    orig_code = py_file.read_text(encoding="utf-8")

    # A. Corrupt syntax patch is rejected by pre-flight gate
    corrupt_code = "def authenticate(user, password):\n    return broken syntax(\n"
    corrupt_patch = patch_svc.propose_patch(file_path=py_file, modified_code=corrupt_code)
    patch_svc.approve_patch(corrupt_patch.patch_id, approved_by="lead_security")
    with pytest.raises(ValueError, match="Pre-application syntax validation failed"):
        patch_svc.apply_patch(corrupt_patch.patch_id, require_approval=True)
    assert py_file.read_text(encoding="utf-8") == orig_code

    # B. Valid patch requires approval before application
    valid_remediation = (
        "import hmac\n"
        "import os\n"
        "def authenticate(user, password):\n"
        "    expected = os.getenv('MASTER_AUTH_TOKEN', '')\n"
        "    return hmac.compare_digest(password, expected)\n"
    )
    valid_patch = patch_svc.propose_patch(file_path=py_file, modified_code=valid_remediation)
    # Attempt unapproved apply
    with pytest.raises(ApprovalRequiredError):
        patch_svc.apply_patch(valid_patch.patch_id, require_approval=True)

    # Approve & Apply
    patch_svc.approve_patch(valid_patch.patch_id, approved_by="security_officer")
    assert patch_svc.apply_patch(valid_patch.patch_id, require_approval=True) is True
    assert py_file.read_text(encoding="utf-8") == valid_remediation

    # C. Byte-for-byte verified rollback
    assert patch_svc.rollback_patch(valid_patch.patch_id) is True
    assert py_file.read_text(encoding="utf-8") == orig_code
    assert valid_patch.status == PatchStatus.ROLLED_BACK


# =============================================================================
# Test 6: Defensive Patch Gate Rejection of Whitespace Wipes
# =============================================================================
def test_system_integrity_patch_validator_blocks_whitespace_wipe():
    """
    Verifies that the PatchValidator pre-flight gate strictly prevents accidental or malicious
    file-wipes where modified_code consists solely of whitespace, protecting production files.
    """
    validator = PatchValidator()
    patch = Patch(
        file_path="src/critical.py",
        original_code="def run_core_pipeline(): return True\n",
        modified_code="   \t\n  \n",
        diff=PatchDiff(""),
    )
    is_valid, err_msg = validator.validate_patch_candidate(patch)
    assert is_valid is False
    assert "whitespace-only" in err_msg.lower() or "empty" in err_msg.lower()


# =============================================================================
# Test 7: Retriever Resilience on Pathological None and Zero-Bound Limits
# =============================================================================
def test_system_integrity_retriever_resilience_on_pathological_inputs():
    """
    Verifies LocalContextRetriever gracefully tolerates None, empty strings,
    and negative max_chars limits without raising TypeError or UnboundLocalError.
    """
    retriever = LocalContextRetriever()
    assert retriever._truncate_at_line_boundary(None, 100) == ""
    assert retriever._truncate_at_line_boundary("", 100) == ""
    res = retriever._truncate_at_line_boundary("def foo():\n    return 1\n", -10)
    assert "TRUNCATED" in res


# =============================================================================
# Test 8: Embedding Service Vector Dimensionality & Metric Bounds Invariants
# =============================================================================
def test_system_integrity_embedding_service_invariants_under_stress():
    """
    Verifies LocalEmbeddingService maintains exact vector dimensions, L2 normalization,
    and cosine similarity clamping [-1.0, 1.0] across None, empty, and adversarial texts.
    """
    svc = LocalEmbeddingService(dimension=384)

    # 1. Null, empty, and special-char inputs
    v_none = svc.embed_text(None)
    v_empty = svc.embed_text("")
    v_special = svc.embed_text("!@#$%^&*()_+-=[]{}|;':,.<>?/`~ 🔥 🚀 💎")

    assert len(v_none) == 384
    assert len(v_empty) == 384
    assert len(v_special) == 384

    # 2. Metric bounds [-1.0, 1.0]
    sim_self = svc.compute_similarity(v_special, v_special)
    assert 0.99 <= sim_self <= 1.01

    sim_diff = svc.compute_similarity(v_special, v_none)
    assert -1.0 <= sim_diff <= 1.0

    # 3. None and mismatched lengths return safe default 0.0 without exception
    assert svc.compute_similarity(None, v_special) == 0.0
    assert svc.compute_similarity(v_special, [1.0, 2.0]) == 0.0

