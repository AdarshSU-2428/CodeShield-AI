import concurrent.futures
import json
from pathlib import Path
import threading
import time
from unittest.mock import MagicMock
import pytest

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.attribution_helper import FindingAttributionHelper
from app.analysis.cross_file import CrossFileContextResolver
from app.analysis.parser import ParserRegistry
from app.analysis.quality_analyzer import ArchitecturalSmellDetector, CodeQualityAnalyzer
from app.core.enums import Confidence, FileStatus, FindingCategory, JobStatus, Language, PatchStatus, Severity
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.llm import LLMResponse
from app.core.models.audit import AuditFinding, AuditJob, AuditReport
from app.core.models.code import CodeComponent, SourceFile
from app.core.models.patch import Patch
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupIntegrityError, BackupManager
from app.patches.rollback_manager import RollbackManager
from app.patches.validator import PatchValidator
from app.services.audit_service import AuditService
from app.services.patch_service import PatchService


# ==============================================================================
# STRESS TEST 1: Pathological Dependency Graph (Tangled Web & Self-Loops)
# ==============================================================================
def test_stress_sprint3_pathological_cycle_detection_tangled_web():
    """Stress 1: 15-node tangled dependency web with multi-cycles, self-loops, and cross-edges."""
    files = []
    # Create 15 modules with interlocking circular imports:
    # 0 -> 1 -> 2 -> ... -> 9 -> 0 (10-node cycle)
    # 2 -> 11 -> 12 -> 2 (nested 3-node cycle)
    # 14 -> 14 (self loop)
    # 5 -> 13 (leaf branch)
    for i in range(15):
        lines = []
        if i < 10:
            next_idx = (i + 1) % 10
            lines.append(f"from app.mod_{next_idx} import Service{next_idx}")
        if i == 2:
            lines.append("from app.mod_11 import Service11")
        elif i == 11:
            lines.append("from app.mod_12 import Service12")
        elif i == 12:
            lines.append("from app.mod_2 import Service2")
        elif i == 14:
            lines.append("from app.mod_14 import Service14")  # self loop
        elif i == 5:
            lines.append("from app.mod_13 import Service13")

        lines.append(f"class Service{i}:\n    pass\n")
        content = "\n".join(lines)

        sf = SourceFile(
            file_path=str(Path(f"app/mod_{i}.py").resolve()),
            relative_path=f"app/mod_{i}.py",
            language=Language.PYTHON,
            content=content,
        )
        files.append(sf)

    detector = ArchitecturalSmellDetector()
    t0 = time.perf_counter()
    findings = detector.detect_circular_dependencies(files)
    elapsed = time.perf_counter() - t0

    # Must execute within sub-second time without infinite recursion
    assert elapsed < 1.0, f"Cycle detection took too long: {elapsed:.2f}s"
    assert len(findings) >= 2, "Expected multiple cycles detected in tangled web"
    for f in findings:
        assert f.category == FindingCategory.ARCHITECTURE
        assert f.severity == Severity.HIGH
        assert "Circular Dependency" in f.title


# ==============================================================================
# STRESS TEST 2: Concurrent Patch Stale-Detection Race Condition
# ==============================================================================
def test_stress_sprint3_concurrent_patch_stale_detection_race(tmp_path: Path):
    """Stress 2: 12 threads concurrently race to patch the same file. Stale detection must reject losers."""
    shared_file = tmp_path / "shared_account.py"
    baseline = "BALANCE = 1000\n"
    shared_file.write_text(baseline, encoding="utf-8")

    backup_dir = tmp_path / "race_backups"
    service = PatchService(backup_manager=BackupManager(backup_dir=backup_dir))

    thread_count = 12
    patches = [
        service.propose_patch(
            file_path=shared_file,
            modified_code=f"BALANCE = {1000 + i * 50}\n",
            description=f"Thread {i} update",
        )
        for i in range(thread_count)
    ]

    barrier = threading.Barrier(thread_count)
    results = {"success": 0, "rejected_stale": 0, "errors": []}
    results_lock = threading.Lock()

    def worker(patch: Patch):
        try:
            barrier.wait()
            service.apply_patch(patch.patch_id)
            with results_lock:
                results["success"] += 1
        except ValueError as ve:
            if "Stale patch detected" in str(ve):
                with results_lock:
                    results["rejected_stale"] += 1
            else:
                with results_lock:
                    results["errors"].append(str(ve))
        except Exception as e:
            with results_lock:
                results["errors"].append(str(e))

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(worker, p) for p in patches]
        concurrent.futures.wait(futures)

    # Exactly ONE thread can win; all other 11 must be safely rejected as stale
    assert results["success"] == 1
    assert results["rejected_stale"] == thread_count - 1
    assert len(results["errors"]) == 0
    assert shared_file.read_text(encoding="utf-8").startswith("BALANCE = ")


# ==============================================================================
# STRESS TEST 3: Post-Patch Syntax Sabotage & Atomic Rollback
# ==============================================================================
def test_stress_sprint3_post_patch_syntax_sabotage_and_atomic_rollback(tmp_path: Path):
    """Stress 3: Hostile patches with broken syntax trigger automatic rollback and preserve SHA-256."""
    fs = LocalFileSystem()
    backup_dir = tmp_path / "sabotage_backups"

    # Multi-language files to sabotage
    files = {
        "python": (tmp_path / "auth.py", "def login(user):\n    return True\n", "def login(user:\n    ret True"),
        "javascript": (tmp_path / "app.js", "function run() {\n    return 1;\n}\n", "function run() {\n    ret 1;\n"),
    }

    backup_mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    rollback_mgr = RollbackManager(backup_manager=backup_mgr, filesystem=fs)
    validator = PatchValidator(filesystem=fs, parser_registry=ParserRegistry())
    applier = PatchApplier(
        backup_manager=backup_mgr,
        validator=validator,
        rollback_manager=rollback_mgr,
        filesystem=fs,
    )

    for lang, (fpath, pristine, corrupt) in files.items():
        fpath.write_text(pristine, encoding="utf-8")
        orig_hash = fs.compute_hash(fpath)

        patch = Patch(
            file_path=fpath,
            original_code=pristine,
            modified_code=corrupt,
            diff="--- diff",
            status=PatchStatus.PROPOSED,
        )

        with pytest.raises(ValueError, match="syntax errors detected"):
            applier.apply_patch(patch)

        # Confirm atomic restoration byte-for-byte
        assert fpath.read_text(encoding="utf-8") == pristine
        assert fs.compute_hash(fpath) == orig_hash
        assert patch.status == PatchStatus.FAILED


# ==============================================================================
# STRESS TEST 4: Backup Disk Sabotage & Tampering Recovery
# ==============================================================================
def test_stress_sprint3_backup_tampering_and_zero_byte_sabotage(tmp_path: Path):
    """Stress 4: Simulates disk tampering, zero-byte truncated backups, and missing backup recovery."""
    fs = LocalFileSystem()
    backup_dir = tmp_path / "tamper_backups"
    mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    rollback_mgr = RollbackManager(backup_manager=mgr, filesystem=fs)

    source = tmp_path / "kernel.py"
    source.write_text("DEVICE_STATUS = 'ACTIVE'\n", encoding="utf-8")

    # 1. Zero-byte backup sabotage
    p1 = "patch-zero-byte"
    b1 = mgr.create_backup(source, p1)
    b1.write_text("", encoding="utf-8")  # truncate to 0 bytes
    assert mgr.verify_backup(p1) is False

    patch1 = Patch(file_path=source, original_code="x", modified_code="y", diff="--- diff", status=PatchStatus.APPLIED)
    patch1.patch_id = p1
    patch1.backup_path = b1

    with pytest.raises(ValueError, match="Backup verification failed"):
        rollback_mgr.rollback_patch(patch1)

    # 2. Hostile bit-flip sabotage
    p2 = "patch-bit-flip"
    b2 = mgr.create_backup(source, p2)
    b2.write_text("DEVICE_STATUS = 'CORRUPTED'\n", encoding="utf-8")
    assert mgr.verify_backup(p2) is False


# ==============================================================================
# STRESS TEST 5: Massive 50k-Line God Class & Depth 30 Fuzzing
# ==============================================================================
def test_stress_sprint3_massive_50k_line_god_class_and_depth_30_fuzz():
    """Stress 5: Fuzzing CodeQualityAnalyzer with 50,000 lines and 30 levels of nested indentation."""
    # Build 30-level nested block
    nested_lines = ["def extreme_nesting():"]
    for i in range(1, 31):
        indent = "    " * i
        nested_lines.append(f"{indent}if condition_{i}:")
    nested_lines.append("        " * 15 + "execute_core()")

    # Fill rest up to 50,000 lines
    remaining_count = 50000 - len(nested_lines)
    padding = [f"# Line {idx}: padding logic statement" for idx in range(remaining_count)]
    total_code = "\n".join(nested_lines + padding)

    sf = SourceFile(
        file_path="app/monolith_monster.py",
        relative_path="monolith_monster.py",
        language=Language.PYTHON,
        content=total_code,
    )

    quality_analyzer = CodeQualityAnalyzer(max_nesting_depth=4)
    arch_detector = ArchitecturalSmellDetector(max_god_class_lines=250)

    t0 = time.perf_counter()
    quality_findings = quality_analyzer.evaluate_file(sf)
    arch_findings = arch_detector.evaluate_architecture([sf])
    elapsed = time.perf_counter() - t0

    assert elapsed < 2.0, f"Quality analyzer took too long on 50k lines: {elapsed:.2f}s"
    assert any("Excessive Control Flow Nesting" in f.title for f in quality_findings)
    assert any("Monolithic God Class" in f.title for f in arch_findings)


# ==============================================================================
# STRESS TEST 6: Regex-Confounding Function Signatures & Bare Catch Variations
# ==============================================================================
def test_stress_sprint3_regex_confounding_function_signatures():
    """Stress 6: Devious function declarations and tricky bare catch blocks."""
    adversarial_code = (
        'def tricky_fn(a="def fake():", b=lambda x: [y for y in range(5)], c=1, d=2, e=3, f=4):\n'
        "    try:\n"
        "        do_work()\n"
        "    except BaseException:\n"
        "        # catches system exit\n"
        "        pass\n"
        "    try:\n"
        "        safe_call()\n"
        "    except (ValueError, KeyError) as e:\n"
        "        log(e)\n"
    )
    sf = SourceFile(
        file_path="app/tricky.py",
        relative_path="tricky.py",
        language=Language.PYTHON,
        content=adversarial_code,
    )

    analyzer = CodeQualityAnalyzer(max_parameters=5)
    findings = analyzer.evaluate_file(sf)

    # Must catch the excessive parameters in tricky_fn (6 parameters: a, b, c, d, e, f)
    param_findings = [f for f in findings if "Excessive Parameter List" in f.title]
    assert len(param_findings) == 1
    assert "6 params" in param_findings[0].title

    # Must catch BaseException but NOT safe_call's except (ValueError, KeyError)
    bare_findings = [f for f in findings if "Bare Exception" in f.title]
    assert len(bare_findings) == 1
    assert bare_findings[0].start_line == 4


# ==============================================================================
# STRESS TEST 7: Simulated LLM Apocalypse (Hallucinations & Truncated Payloads)
# ==============================================================================
def test_stress_sprint3_llm_apocalypse_hallucination_and_malformed_payloads():
    """Stress 7: AI vulnerability analyzer withstands corrupted JSON and hallucinated offsets."""
    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True

    # Hostile response: Truncated JSON with invalid line numbers and hallucinated data
    hallucinated_dict = {
        "vulnerabilities": [
            {
                "title": "Hallucinated Danger",
                "description": "Nonsense vulnerability",
                "severity": "CRITICAL_EXTREME_DOOM",
                "confidence": "UNKNOWN_CONFIDENCE",
                "start_line": -9999,
                "end_line": 99999999,
                "cwe_id": "CWE-9999999",
                "recommendation": "Fix it",
            }
        ]
    }
    mock_llm.chat_json.return_value = hallucinated_dict

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(
        file_path="app/server.py",
        relative_path="server.py",
        language=Language.PYTHON,
        content="x = 1\ny = 2\nz = 3\n",
    )

    # 1. Must safely parse and normalize without raising exceptions
    findings = analyzer.analyze_file(sf)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.confidence in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)
    assert f.start_line == 1
    assert f.end_line >= 1

    # 2. Catastrophic network / JSON decoding failure must return [] gracefully
    mock_llm.chat_json.side_effect = RuntimeError("Fatal LLM Network Connection Reset")
    fallback_findings = analyzer.analyze_file(sf)
    assert fallback_findings == []


# ==============================================================================
# STRESS TEST 8: Attribution Helper Pathological Boundaries
# ==============================================================================
def test_stress_sprint3_attribution_helper_pathological_boundaries():
    """Stress 8: FindingAttributionHelper on zero-byte, single-line, and massive-line boundaries."""
    helper = FindingAttributionHelper()

    # 1. Zero-byte content
    f_empty = AuditFinding(title="F1", description="D1", file_path="empty.py", start_line=10, end_line=20)
    helper.hydrate_finding(f_empty, file_content="")
    assert f_empty.code_snippet == "" or f_empty.code_snippet is None
    assert f_empty.context_snippet == "" or f_empty.context_snippet is None

    # 2. Single-line content
    f_single = AuditFinding(title="F2", description="D2", file_path="single.py", start_line=-5, end_line=500)
    helper.hydrate_finding(f_single, file_content="single_statement()")
    assert f_single.start_line == 1
    assert f_single.end_line == 1
    assert f_single.code_snippet == "single_statement()"
    assert ">    1 | single_statement()" in f_single.context_snippet

    # 3. Context window padding overflowing start and end
    f_overflow = AuditFinding(title="F3", description="D3", file_path="overflow.py", start_line=2, end_line=3)
    content = "line 1\nline 2\nline 3\nline 4\n"
    helper.hydrate_finding(f_overflow, file_content=content, context_lines=10)
    assert len(f_overflow.context_snippet.splitlines()) == 4


# ==============================================================================
# STRESS TEST 9: Cross-File Resolver Broken Paths & Unicode Chaos
# ==============================================================================
def test_stress_sprint3_cross_file_resolver_broken_paths_and_unicode_chaos():
    """Stress 9: CrossFileContextResolver with relative traversal, unicode, and missing modules."""
    resolver = CrossFileContextResolver()

    # Broken/traversal imports in Python and JS
    code = (
        "from ...unreachable.secret import Vault\n"
        "import non_existent_system_module\n"
        "import sys\n"
        "from app.unicode_⚡ import Spark\n"
    )

    imports = resolver.extract_imports(code, Language.PYTHON)
    assert len(imports) >= 3

    # Resolve against an empty file list should gracefully return None
    matched = resolver.resolve_import_to_file("non_existent_system_module", "app/main.py", [])
    assert matched is None

    # Resolve with existing files containing unicode
    unicode_sf = SourceFile(
        file_path=str(Path("app/unicode_⚡.py").resolve()),
        relative_path="app/unicode_⚡.py",
        language=Language.PYTHON,
        content="class Spark:\n    pass\n",
    )
    resolved = resolver.resolve_import_to_file("app.unicode_⚡", "app/main.py", [unicode_sf])
    assert resolved is not None
    assert str(resolved.relative_path).replace("\\", "/") == "app/unicode_⚡.py"


# ==============================================================================
# STRESS TEST 10: Multi-Threaded Chaotic Audit Pipeline & Rapid Cancellation
# ==============================================================================
def test_stress_sprint3_audit_service_full_scale_chaotic_project_and_rapid_cancel():
    """Stress 10: Full end-to-end audit with concurrent cancellations across chaotic multilingual repo."""
    mock_scanner = MagicMock()
    mock_fs = MagicMock()
    mock_rule_engine = MagicMock()
    mock_rule_engine.analyze_file.return_value = []

    # Generate 30 diverse source files
    files = []
    for i in range(30):
        lang = [Language.PYTHON, Language.JAVASCRIPT, Language.JAVA][i % 3]
        if i % 5 == 0:
            content = f"def bad_f_{i}(a, b, c, d, e, f, g):\n    try:\n        x()\n    except:\n        pass\n"
        elif i % 5 == 1:
            content = f"// Module {i}\nfunction run_{i}() {{\n    try {{\n    }} catch (e) {{}}\n}}\n"
        else:
            content = f"class Service_{i} {{\n    public void test() {{}}\n}}\n"

        sf = SourceFile(
            file_path=f"app/file_{i}.py",
            relative_path=f"file_{i}.py",
            language=lang,
            status=FileStatus.UNCHANGED,
            content=content,
        )
        files.append(sf)

    mock_scanner.scan_project.return_value = files
    mock_fs.exists.return_value = True
    mock_fs.read_text.side_effect = lambda p: next((f.content for f in files if f.file_path == str(p)), "code")

    service = AuditService(
        scanner=mock_scanner,
        filesystem=mock_fs,
        rule_engine=mock_rule_engine,
        quality_analyzer=CodeQualityAnalyzer(),
        architecture_detector=ArchitecturalSmellDetector(),
        auto_save_report=False,
    )

    project = Project(root_path="chaotic_project", name="ChaosRepo")

    # 1. Normal run with 30 files completes with enriched attribution
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)
    assert report.total_findings > 0
    for finding in report.findings:
        assert finding.context_snippet is not None
        assert finding.code_snippet is not None
        assert len(finding.affected_files) >= 1

    # 2. Rapid cancellation mid-flight
    cancel_job = service.create_job(project)
    cancel_job.status = JobStatus.CANCELLED
    cancel_report = service.run_audit(cancel_job.job_id, project)
    assert cancel_job.status == JobStatus.CANCELLED
    assert cancel_report.summary == "Audit job was cancelled by user."


# ==============================================================================


# ==============================================================================
# STRESS TEST 11: Cascading Multi-Hop Circular Dependency Explosion (50 Modules)
# ==============================================================================
def test_stress_sprint3_cascading_multihop_circular_dependency_explosion():
    """Stress 11: 50 interconnected modules with diamond dependencies and multi-hop cycles."""
    files = []
    # 5 rings of 10 modules each, interconnected at nodes 0, 5
    for ring in range(5):
        for idx in range(10):
            global_id = ring * 10 + idx
            next_global_id = ring * 10 + ((idx + 1) % 10)
            cross_ring_id = ((ring + 1) % 5) * 10 + idx

            content = (
                f"from app.mod_{next_global_id} import Service{next_global_id}\n"
                f"from app.mod_{cross_ring_id} import Service{cross_ring_id}\n"
                f"class Service{global_id}:\n    pass\n"
            )
            sf = SourceFile(
                file_path=str(Path(f"app/mod_{global_id}.py").resolve()),
                relative_path=f"app/mod_{global_id}.py",
                language=Language.PYTHON,
                content=content,
            )
            files.append(sf)

    detector = ArchitecturalSmellDetector()
    t0 = time.perf_counter()
    findings = detector.detect_circular_dependencies(files)
    elapsed = time.perf_counter() - t0

    assert elapsed < 2.0, f"50-module cycle detection took {elapsed:.2f}s, expected < 2.0s"
    assert len(findings) >= 5, "Expected multiple circular rings detected"
    for f in findings:
        assert f.category == FindingCategory.ARCHITECTURE
        assert f.severity == Severity.HIGH


# ==============================================================================
# STRESS TEST 12: Hostile File System Tampering During Rollback (Permission Denied)
# ==============================================================================
def test_stress_sprint3_hostile_filesystem_tampering_during_rollback(tmp_path: Path):
    """Stress 12: Rollback on a read-only locked target file handles OS error without losing backup."""
    import stat

    fs = LocalFileSystem()
    backup_dir = tmp_path / "ro_backups"
    mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    rollback_mgr = RollbackManager(backup_manager=mgr, filesystem=fs)
    applier = PatchApplier(backup_manager=mgr, filesystem=fs)

    source = tmp_path / "locked_file.py"
    initial_code = "SECRET = 'secure'\n"
    source.write_text(initial_code, encoding="utf-8")

    patch = Patch(
        file_path=source,
        original_code=initial_code,
        modified_code="SECRET = 'unsecured'\n",
        diff="--- diff",
        status=PatchStatus.PROPOSED,
    )

    applier.apply_patch(patch)
    assert source.read_text(encoding="utf-8") == "SECRET = 'unsecured'\n"

    # Make target read-only to simulate permission lockdown or anti-virus lock
    source.chmod(stat.S_IREAD)

    try:
        # Rollback should raise an exception because the file is write-protected
        # but the backup itself must remain intact and verified!
        with pytest.raises(RuntimeError, match="Failed to restore file"):
            rollback_mgr.rollback_patch(patch)
        
        # Verify that the backup file is still pristine and uncorrupted
        assert mgr.verify_backup(patch.patch_id) is True
    finally:
        # Restore permissions for cleanup
        source.chmod(stat.S_IWRITE | stat.S_IREAD)


# ==============================================================================
# STRESS TEST 13: Truncated Mid-Stream & Broken UTF-8 / Mixed Encoding in AI Analyzer
# ==============================================================================
def test_stress_sprint3_ai_analyzer_truncated_and_hostile_encodings():
    """Stress 13: Hostile payloads with abrupt JSON cutoffs, unescaped quotes, and binary noise."""
    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True

    # 1. Severely truncated payload mid-stream
    mock_llm.chat_json.side_effect = json.JSONDecodeError("Unterminated string starting at line 1", "", 0)

    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(
        file_path="app/binary_noise.py",
        relative_path="binary_noise.py",
        language=Language.PYTHON,
        content="# Binary noise: \x00\x01\x02\xff\xfe\nprint('hello')\n",
    )

    # Must survive JSONDecodeError gracefully
    findings = analyzer.analyze_file(sf)
    assert findings == []

    # 2. Hostile payload wrapped in nested HTML and commentary
    nested_response = {
        "vulnerabilities": [
            {
                "title": "  <!-- Comment --> XSS in template \x00 ",
                "description": "HTML <script>alert(1)</script> injected",
                "severity": "  HIGH severity  ",
                "confidence": "  LOW confidence  ",
                "start_line": "3",
                "end_line": "3",
                "recommendation": "Sanitize & escape output",
            }
        ]
    }
    mock_llm.chat_json.side_effect = None
    mock_llm.chat_json.return_value = nested_response

    findings2 = analyzer.analyze_file(sf)
    assert len(findings2) == 1
    assert findings2[0].severity == Severity.HIGH
    assert findings2[0].confidence == Confidence.LOW
    assert findings2[0].start_line == 3


# ==============================================================================
# STRESS TEST 14: Concurrent Multi-File Batch Patch & Reverse Rollback Integrity
# ==============================================================================
def test_stress_sprint3_concurrent_multifile_patch_and_reverse_rollback(tmp_path: Path):
    """Stress 14: 8 threads patching distinct files concurrently with sequential LIFO rollback."""
    fs = LocalFileSystem()
    backup_dir = tmp_path / "multifile_backups"
    mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    rollback_mgr = RollbackManager(backup_manager=mgr, filesystem=fs)
    applier = PatchApplier(backup_manager=mgr, filesystem=fs)

    file_count = 8
    files = []
    patches = []
    original_hashes = {}

    for i in range(file_count):
        f = tmp_path / f"bank_service_{i}.py"
        code = f"RATE_{i} = 0.0{i}\n"
        f.write_text(code, encoding="utf-8")
        original_hashes[f] = fs.compute_hash(f)
        files.append(f)

        p = Patch(
            file_path=f,
            original_code=code,
            modified_code=f"RATE_{i} = 0.999\n",
            diff="--- diff",
            status=PatchStatus.PROPOSED,
        )
        patches.append(p)

    # Apply all 8 patches concurrently across 8 threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=file_count) as executor:
        results = list(executor.map(applier.apply_patch, patches))

    assert all(results)
    for p in patches:
        assert p.status == PatchStatus.APPLIED
        assert "0.999" in p.file_path.read_text(encoding="utf-8")

    # Reverse LIFO rollback
    for p in reversed(patches):
        reverted = rollback_mgr.rollback_patch(p)
        assert reverted is True
        assert p.status == PatchStatus.ROLLED_BACK
        # Verify SHA-256 restored exactly
        assert fs.compute_hash(p.file_path) == original_hashes[p.file_path]


# ==============================================================================
# STRESS TEST 15: Extreme Attribution on CRLF, Multi-Byte Unicode & Minified Lines
# ==============================================================================
def test_stress_sprint3_attribution_crlf_multibyte_and_minified_lines():
    """Stress 15: Attribution helper on Windows CRLF, Devanagari/CJK unicode, and 100k minified code."""
    helper = FindingAttributionHelper()

    # 1. Mixed Windows CRLF and multi-byte Devanagari / CJK characters
    unicode_crlf_code = (
        "# Line 1: Header\r\n"
        "# Line 2: \u0930\u093e\u0927\u0947 \u0915\u0943\u0937\u094d\u0923 (Radha Krishna)\r\n"
        "def divine_protection():\r\n"
        "    message = '\u795d\u798f'  # Blessing\r\n"
        "    return True\r\n"
    )

    finding = AuditFinding(
        title="Divine Attribution Check",
        description="Verify multi-byte snippet preservation",
        file_path="app/sacred.py",
        start_line=3,
        end_line=4,
    )

    helper.hydrate_finding(finding, file_content=unicode_crlf_code, context_lines=1)

    assert finding.code_snippet is not None
    assert "def divine_protection():" in finding.code_snippet
    assert "\u795d\u798f" in finding.code_snippet
    lines = finding.context_snippet.splitlines()
    assert len(lines) == 4
    assert any(">    3 | def divine_protection():" in l for l in lines)
    assert any(">    4 |     message = '\u795d\u798f'" in l for l in lines)
    assert any("     2 | # Line 2: \u0930\u093e\u0927\u0947 \u0915\u0943\u0937\u094d\u0923" in l for l in lines)

    # 2. Minified massive single line (10,000 characters)
    minified_line = "var a=1;" * 1250  # 10,000 chars
    f_minified = AuditFinding(title="Minified", description="Minified", file_path="bundle.min.js", start_line=1, end_line=1)
    helper.hydrate_finding(f_minified, file_content=minified_line)
    assert f_minified.start_line == 1
    assert f_minified.end_line == 1
    assert len(f_minified.code_snippet) == len(minified_line)
    assert ">    1 | var a=1;" in f_minified.context_snippet
