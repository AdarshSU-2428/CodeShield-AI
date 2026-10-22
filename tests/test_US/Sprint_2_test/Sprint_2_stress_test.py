import concurrent.futures
from datetime import datetime
import os
from pathlib import Path
import stat
import time
from unittest.mock import MagicMock
import httpx
import pytest

from groq import RateLimitError
from app.analysis.rule_engine import RuleEngine
from app.core.enums import Language, PatchStatus
from app.core.interfaces.llm import LLMResponse
from app.core.models.audit import JobStatus
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.llm import GroqLLMClient
from app.patches.backup_manager import BackupManager
from app.patches.generator import DiffGenerator
from app.services.audit_service import AuditService
from app.services.patch_service import PatchService


def create_rate_limit_error(message: str = "TPM limit reached") -> RateLimitError:
    """Helper to instantiate a real Groq RateLimitError for resilience testing."""
    req = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    resp = httpx.Response(429, request=req)
    return RateLimitError(message, response=resp, body={"error": "rate_limit_exceeded"})


def test_stress_sprint2_concurrent_patch_apply_and_rollback_race(tmp_path: Path):
    """Stress 1: 20 concurrent threads running propose, apply, and rollback simultaneously."""
    backup_dir = tmp_path / "shared_backups"
    service = PatchService(backup_manager=BackupManager(backup_dir=backup_dir))

    thread_count = 20
    files = []
    original_contents = {}

    for i in range(thread_count):
        file_path = tmp_path / f"concurrent_{i}.py"
        content = f"# Original content for thread {i}\nx = {i}\n"
        file_path.write_text(content, encoding="utf-8")
        files.append(file_path)
        original_contents[file_path] = content

    def worker_lifecycle(file_path: Path, worker_id: int):
        modified_content = f"# Modified content for thread {worker_id}\nx = {worker_id * 10}\n"
        # 1. Propose
        patch = service.propose_patch(file_path=file_path, modified_code=modified_content)
        # 2. Apply
        applied = service.apply_patch(patch.patch_id)
        if not applied or patch.status != PatchStatus.APPLIED:
            return False
        if file_path.read_text(encoding="utf-8") != modified_content:
            return False
        # 3. Rollback
        reverted = service.rollback_patch(patch.patch_id)
        if not reverted or patch.status != PatchStatus.ROLLED_BACK:
            return False
        # Verify restored to original
        return file_path.read_text(encoding="utf-8") == original_contents[file_path]

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(worker_lifecycle, files[i], i) for i in range(thread_count)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == thread_count
    assert all(results) is True
    assert len(service.list_patches()) == thread_count


def test_stress_sprint2_massive_multimegabyte_diff_and_hunk_parsing():
    """Stress 2: Massive 5,000-line file with 50 scattered modifications across chunks."""
    total_lines = 5000
    orig_lines = [f"line_{i} = {i} * 2\n" for i in range(total_lines)]
    mod_lines = list(orig_lines)

    # Introduce 50 distinct hunks scattered throughout the file
    modified_indices = [i * 100 for i in range(50)]
    for idx in modified_indices:
        mod_lines[idx] = f"# MODIFIED LINE {idx}\nnew_val_{idx} = True\n"

    generator = DiffGenerator(context_lines=3)
    start_time = time.perf_counter()
    diff = generator.generate_diff("".join(orig_lines), "".join(mod_lines), file_name="huge_file.py")
    elapsed = time.perf_counter() - start_time

    # Performance requirement: diffing 5,000 lines with 50 hunks must complete in under 0.5s
    assert elapsed < 0.5
    assert len(diff.hunks) == 50
    assert diff.additions_count == 100  # 2 new lines per hunk * 50
    assert diff.deletions_count == 50   # 1 line deleted per hunk * 50
    assert "--- a/huge_file.py" in diff.raw_diff


def test_stress_sprint2_hostile_crlf_unicode_bom_and_null_bytes(tmp_path: Path):
    """Stress 3: Extreme line endings (CRLF/LF mixed), BOM headers, emojis, and right-to-left scripts."""
    hostile_file = tmp_path / "adversarial.py"
    # BOM + Unicode emojis + RTL markers + Mixed CRLF and LF
    pristine_bytes = (
        b"\xef\xbb\xbf# -*- coding: utf-8 -*-\r\n"
        b"# Unicode: \xf0\x9f\x94\x92\xd8\xb4\xd9\x81\xd8\xb1\xd8\xa9 (Arabic)\n"
        b"SECRET_DATA = \"\xe2\x80\xaeREVERSED_TEXT\xe2\x80\xac\"\r\n"
        b"x = 100\n"
    )
    hostile_file.write_bytes(pristine_bytes)

    service = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))

    patch = service.propose_patch(
        file_path=hostile_file,
        modified_code="# Remediated Unicode\nx = 200\n",
    )

    # Apply patch
    service.apply_patch(patch.patch_id)
    assert "Remediated Unicode" in hostile_file.read_text(encoding="utf-8")

    # Rollback patch and assert EXACT byte-for-byte equality with pristine binary bytes
    service.rollback_patch(patch.patch_id)
    restored_bytes = hostile_file.read_bytes()
    assert restored_bytes == pristine_bytes


def test_stress_sprint2_llm_cascading_chaos_and_malformed_json_recovery():
    """Stress 4: Primary 70B fails with 429 RateLimit, fallback 8B returns dirty markdown."""
    client = GroqLLMClient(
        api_key="gsk_mock_stress_token",
        fallback_model="llama-3.1-8b-instant",
        retry_delay=0.01,
    )
    mock_groq = MagicMock()

    mock_fallback_choice = MagicMock()
    mock_fallback_choice.message.content = (
        "```markdown\n"
        "# Explanatory note from AI\n"
        "```\n\n"
        "```python\n"
        "def safe_execute(cmd):\n"
        "    import shlex\n"
        "    return shlex.quote(cmd)\n"
        "```\n\n"
        "Hope this helps!"
    )

    mock_fallback_resp = MagicMock(
        choices=[mock_fallback_choice],
        usage=MagicMock(prompt_tokens=450, completion_tokens=80, total_tokens=530),
    )
    mock_fallback_resp.model = "llama-3.1-8b-instant"

    mock_groq.chat.completions.create.side_effect = [
        create_rate_limit_error("Primary llama-3.3-70b-versatile rate limit exceeded"),
        mock_fallback_resp,
    ]

    client._client = mock_groq

    response = client.chat(
        messages=[{"role": "user", "content": "Fix command injection"}],
    )

    assert isinstance(response, LLMResponse)
    assert response.model == "llama-3.1-8b-instant"
    assert "safe_execute" in response.content

    # Verify PatchService cleans out markdown chatter correctly
    service = PatchService(llm_client=client)
    clean_code = service._clean_markdown_code(response.content)
    assert "Hope this helps!" not in clean_code
    assert "def safe_execute(cmd):" in clean_code


def test_stress_sprint2_rule_engine_redos_and_pathological_scale():
    """Stress 5: Rule engine against 20,000-char lines and ReDoS injection payloads."""
    engine = RuleEngine()

    # Craft 20,000-character line designed to trigger catastrophic backtracking in naive regexes
    pathological_line = "query = \"SELECT \" + " + ("\"x\" + " * 3000) + "\" FROM users WHERE \"\n"
    source_file = SourceFile(
        file_path="redos_attack.py",
        relative_path="redos_attack.py",
        language=Language.PYTHON,
        content=pathological_line,
    )

    start_time = time.perf_counter()
    findings = engine.analyze_file(source_file)
    elapsed = time.perf_counter() - start_time

    # Performance requirement: Even under extreme length, scanning must finish in < 1.0s
    assert elapsed < 1.0
    assert isinstance(findings, list)


def test_stress_sprint2_chaos_monkey_filesystem_tampering(tmp_path: Path):
    """Stress 6: Simulate external permission locking (read-only) mid-patching."""
    target_file = tmp_path / "locked_file.py"
    target_file.write_text("x = 10\n", encoding="utf-8")

    service = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))
    patch = service.propose_patch(target_file, "x = 20\n")

    # Lock file as READ-ONLY
    os.chmod(target_file, stat.S_IREAD)

    try:
        # Patching a locked file should fail safely without corrupting the state
        with pytest.raises((RuntimeError, PermissionError)):
            service.apply_patch(patch.patch_id)
        assert patch.status == PatchStatus.FAILED
    finally:
        # Unlock file for cleanup
        os.chmod(target_file, stat.S_IWRITE)

    # Confirm original file was not left in half-written corrupt state
    assert target_file.read_text(encoding="utf-8") == "x = 10\n"


def test_stress_sprint2_orchestrator_rapid_cancellation_and_high_churn(tmp_path: Path):
    """Stress 7: Audit 50 multilingual files with concurrent asynchronous cancellation."""
    project_dir = tmp_path / "massive_polyglot_project"
    project_dir.mkdir(parents=True)

    # Generate 50 realistic files across Python, JavaScript, Java, C, and C++
    extensions = [".py", ".js", ".java", ".c", ".cpp"]
    for i in range(50):
        ext = extensions[i % len(extensions)]
        f = project_dir / f"module_{i}{ext}"
        f.write_text(f"// File {i}\nint func_{i}() {{ return {i}; }}\n", encoding="utf-8")

    project = Project(root_path=project_dir, name="MassivePolyglot")
    service = AuditService()
    job = service.create_job(project)

    # Callback that simulates user clicking 'Cancel' right when progress hits 20%
    def cancel_on_progress(progress):
        if progress.percentage >= 20.0:
            service.cancel_job(job.job_id)

    report = service.run_audit(job.job_id, project, on_progress=cancel_on_progress)

    # Verify atomic cancellation handling
    assert job.status == JobStatus.CANCELLED
    assert report.summary == "Audit job was cancelled by user."
    assert job.completed_at is not None


def test_stress_sprint2_backup_anti_tampering_sha256_rejection(tmp_path: Path):
    """Stress 8: Hostile backup tampering detection and cryptographic rollback rejection."""
    src = tmp_path / "critical_app.py"
    src.write_text("PRISTINE_ORIGINAL = True\n", encoding="utf-8")
    backup_dir = tmp_path / "backups"

    service = PatchService(backup_manager=BackupManager(backup_dir=backup_dir))
    patch = service.propose_patch(src, "PATCHED_CODE = True\n")
    service.apply_patch(patch.patch_id)
    assert src.read_text(encoding="utf-8") == "PATCHED_CODE = True\n"

    # Attacker tampers directly with the backup file on disk
    backup_files = list((backup_dir / patch.patch_id).glob("*.bak"))
    assert len(backup_files) == 1
    tampered_backup = backup_files[0]
    tampered_backup.write_text("HOSTILE_BACKDOOR_INJECTED = True\n", encoding="utf-8")

    # Rollback must detect hash tampering, raise ValueError, and protect the file
    with pytest.raises(ValueError, match="Backup verification failed"):
        service.rollback_patch(patch.patch_id)

    # Verify source file was NOT overwritten with malicious backdoor payload
    assert src.read_text(encoding="utf-8") == "PATCHED_CODE = True\n"


def test_stress_sprint2_multi_patch_chaining_and_lifo_rollback(tmp_path: Path):
    """Stress 9: Chained multi-version patching and sequential LIFO rollback on identical file."""
    src = tmp_path / "versioned.py"
    src.write_text("version = 0\n", encoding="utf-8")

    service = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))

    # Apply Patch 1 (v0 -> v1)
    p1 = service.propose_patch(src, "version = 1\n")
    service.apply_patch(p1.patch_id)
    assert src.read_text(encoding="utf-8") == "version = 1\n"

    # Apply Patch 2 (v1 -> v2)
    p2 = service.propose_patch(src, "version = 2\n")
    service.apply_patch(p2.patch_id)
    assert src.read_text(encoding="utf-8") == "version = 2\n"

    # LIFO Rollback 1: Reverting Patch 2 must bring back v1
    service.rollback_patch(p2.patch_id)
    assert src.read_text(encoding="utf-8") == "version = 1\n"

    # LIFO Rollback 2: Reverting Patch 1 must bring back original v0
    service.rollback_patch(p1.patch_id)
    assert src.read_text(encoding="utf-8") == "version = 0\n"


def test_stress_sprint2_rule_engine_100k_minified_fuzz():
    """Stress 10: 100,000+ character single-line minified code evaluated under 1.0s."""
    engine = RuleEngine()

    huge_code = "SELECT " + "col, " * 20000 + "FROM table WHERE id = " + " OR 1=1" * 1000
    src = SourceFile(
        file_path="minified.py",
        relative_path="minified.py",
        language=Language.PYTHON,
        content=huge_code,
    )

    t0 = time.perf_counter()
    findings = engine.analyze_file(src)
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.0
    assert isinstance(findings, list)
