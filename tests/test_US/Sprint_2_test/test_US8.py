from pathlib import Path
from unittest.mock import MagicMock
import pytest

from app.core.enums import Confidence, FindingCategory, PatchStatus, Severity
from app.core.interfaces.llm import LLMResponse
from app.core.models.audit import AuditFinding
from app.core.models.patch import Patch, PatchDiff
from app.patches.backup_manager import BackupManager
from app.patches.generator import DiffGenerator
from app.services.patch_service import PatchService


def test_us8_diff_generation_and_hunks_review():
    """Verify DiffGenerator produces unified Git diffs with structured hunks for review."""
    original = (
        "def fetch_user(db, user_id):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return db.execute(query)\n"
    )
    remediated = (
        "def fetch_user(db, user_id):\n"
        "    query = 'SELECT * FROM users WHERE id = %s'\n"
        "    return db.execute(query, (user_id,))\n"
    )

    generator = DiffGenerator(context_lines=2)
    diff: PatchDiff = generator.generate_diff(original, remediated, file_name="user_dao.py")

    assert diff.additions_count == 2
    assert diff.deletions_count == 2
    assert "--- a/user_dao.py" in diff.raw_diff
    assert "+++ b/user_dao.py" in diff.raw_diff
    assert len(diff.hunks) >= 1

    hunk = diff.hunks[0]
    assert "old_start" in hunk
    assert "new_start" in hunk

    types = [line["type"] for line in hunk["lines"]]
    assert "deletion" in types
    assert "addition" in types
    assert "context" in types


def test_us8_patch_proposal_preserves_disk_untouched(tmp_path: Path):
    """Verify that proposing a patch generates diff review data without mutating the file on disk."""
    file_path = tmp_path / "app.py"
    original_code = "SECRET_KEY = 'hardcoded_secret_token_123'\n"
    file_path.write_text(original_code, encoding="utf-8")

    service = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))
    remediated_code = "SECRET_KEY = os.getenv('SECRET_KEY')\n"

    patch = service.propose_patch(
        file_path=file_path,
        modified_code=remediated_code,
        description="Extract hardcoded secret to env var",
    )

    assert patch.status == PatchStatus.PROPOSED
    assert patch.diff.additions_count == 1
    assert patch.diff.deletions_count == 1
    assert not patch.is_applied

    # Critical requirement: disk content MUST remain completely untouched before apply
    current_disk_content = file_path.read_text(encoding="utf-8")
    assert current_disk_content == original_code


def test_us8_backup_creation_and_integrity_verification(tmp_path: Path):
    """Verify BackupManager creates a bit-for-bit replica and verifies cryptographic checksums."""
    target_file = tmp_path / "critical.py"
    content = "import os\nprint('Production code')\n"
    target_file.write_text(content, encoding="utf-8")

    backup_dir = tmp_path / "backups"
    manager = BackupManager(backup_dir=backup_dir)

    backup_path = manager.create_backup(target_file, patch_id="PATCH-001")
    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == content
    assert manager.verify_backup("PATCH-001") is True


def test_us8_safe_patch_application_to_disk(tmp_path: Path):
    """Verify patch application mutates target file safely while establishing verified backup."""
    target_file = tmp_path / "service.py"
    original_content = "def calculate():\n    return 41\n"
    target_file.write_text(original_content, encoding="utf-8")

    backup_dir = tmp_path / "backups"
    service = PatchService(backup_manager=BackupManager(backup_dir=backup_dir))

    patch = service.propose_patch(
        file_path=target_file,
        modified_code="def calculate():\n    return 42\n",
    )

    success = service.apply_patch(patch.patch_id)
    assert success is True
    assert patch.status == PatchStatus.APPLIED
    assert patch.is_applied is True
    assert patch.applied_at is not None
    assert patch.backup_path is not None
    assert patch.backup_path.exists()

    # Disk must now reflect the newly applied patch
    assert target_file.read_text(encoding="utf-8") == "def calculate():\n    return 42\n"


def test_us8_byte_for_byte_rollback_restores_original_version(tmp_path: Path):
    """Verify rollback restores the original file byte-for-byte, ensuring no code is lost."""
    target_file = tmp_path / "engine.py"
    pristine_code = (
        "class Engine:\n"
        "    def run(self):\n"
        "        strcpy(dest, src)\n"
    )
    target_file.write_text(pristine_code, encoding="utf-8")

    backup_dir = tmp_path / "backups"
    service = PatchService(backup_manager=BackupManager(backup_dir=backup_dir))

    # 1. Propose & Apply patch
    patch = service.propose_patch(
        file_path=target_file,
        modified_code="class Engine:\n    def run(self):\n        strncpy(dest, src, sizeof(dest))\n",
    )
    service.apply_patch(patch.patch_id)
    assert "strncpy" in target_file.read_text(encoding="utf-8")

    # 2. Revert / Rollback
    rollback_success = service.rollback_patch(patch.patch_id)
    assert rollback_success is True
    assert patch.status == PatchStatus.ROLLED_BACK
    assert patch.is_rolled_back is True

    # 3. Ensure disk file is restored 100% to pristine code
    restored_code = target_file.read_text(encoding="utf-8")
    assert restored_code == pristine_code


def test_us8_ai_remediation_patch_flow_with_mock_llm(tmp_path: Path):
    """Verify full AI patch workflow: finding -> prompt -> remediated code -> diff -> apply."""
    target_file = tmp_path / "db.py"
    vulnerable_code = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
    target_file.write_text(vulnerable_code, encoding="utf-8")

    mock_llm = MagicMock()
    mock_llm.chat.return_value = LLMResponse(
        content="```python\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n```",
        model="llama-3.3-70b-versatile",
    )

    service = PatchService(
        backup_manager=BackupManager(backup_dir=tmp_path / "backups"),
        llm_client=mock_llm,
    )

    finding = AuditFinding(
        title="SQL Injection Detected",
        description="Unparameterized query format",
        category=FindingCategory.SECURITY,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path=str(target_file),
        start_line=1,
        end_line=1,
        cwe_id="CWE-89",
        recommendation="Use parameterized query",
    )

    patch = service.generate_ai_patch(file_path=target_file, finding=finding)

    assert patch.finding_id == finding.finding_id
    assert "SELECT * FROM users WHERE id = %s" in patch.modified_code
    assert patch.diff.additions_count >= 1
    assert patch.diff.deletions_count >= 1

    # Apply the AI-generated remediation
    service.apply_patch(patch.patch_id)
    assert "SELECT * FROM users WHERE id = %s" in target_file.read_text(encoding="utf-8")


def test_us8_safety_error_handling(tmp_path: Path):
    """Verify robust error handling for missing files, invalid patch IDs, and improper rollback states."""
    service = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))

    # 1. Propose on non-existent file
    with pytest.raises(FileNotFoundError):
        service.propose_patch(tmp_path / "ghost.py", "x = 1")

    # 2. Apply non-existent patch ID
    with pytest.raises(ValueError) as exc:
        service.apply_patch("NON-EXISTENT-ID")
    assert "not found" in str(exc.value)

    # 3. Rollback patch that was never applied
    valid_file = tmp_path / "valid.py"
    valid_file.write_text("orig = 1", encoding="utf-8")
    unapplied_patch = service.propose_patch(valid_file, "orig = 2")

    with pytest.raises(ValueError) as exc:
        service.rollback_patch(unapplied_patch.patch_id)
    assert "Only applied patches can be rolled back" in str(exc.value)
