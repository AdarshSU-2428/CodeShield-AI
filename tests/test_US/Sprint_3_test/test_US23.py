from pathlib import Path
import pytest

from app.analysis.parser import ParserRegistry
from app.core.enums import PatchStatus
from app.core.models.patch import Patch
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupIntegrityError, BackupManager
from app.patches.rollback_manager import RollbackManager
from app.patches.validator import PatchValidator


@pytest.fixture
def temp_workspace(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


@pytest.fixture
def backup_dir(tmp_path):
    bdir = tmp_path / "backups"
    bdir.mkdir(parents=True, exist_ok=True)
    return bdir


@pytest.fixture
def fs():
    return LocalFileSystem()


def test_us23_backup_creation_and_cryptographic_verification(temp_workspace, backup_dir, fs):
    """US 23: Verifies byte-for-byte SHA-256 backup creation and persistent manifest generation."""
    source_file = temp_workspace / "service.py"
    original_code = "def calculate_total(a, b):\n    return a + b\n"
    source_file.write_text(original_code, encoding="utf-8")

    mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    patch_id = "patch-us23-001"

    backup_path = mgr.create_backup(source_file, patch_id)

    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == original_code

    # Cryptographic SHA-256 verification
    assert mgr.verify_backup(patch_id) is True

    # Persistent manifest verification
    manifest_file = backup_dir / patch_id / "backup_manifest.json"
    assert manifest_file.exists()
    assert original_code in backup_path.read_text(encoding="utf-8")


def test_us23_backup_tampering_detection(temp_workspace, backup_dir, fs):
    """US 23: Detects corrupted/tampered backup files and rejects verification."""
    source_file = temp_workspace / "data.py"
    source_file.write_text("x = 42\n", encoding="utf-8")

    mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    patch_id = "patch-us23-tamper"

    backup_path = mgr.create_backup(source_file, patch_id)

    # Simulate hostile disk tampering with the backup
    backup_path.write_text("x = 9999 # tampered content\n", encoding="utf-8")

    assert mgr.verify_backup(patch_id) is False


def test_us23_stale_patch_rejection(temp_workspace, backup_dir, fs):
    """US 23: Rejects stale patches if target file was modified externally prior to application."""
    source_file = temp_workspace / "config.py"
    baseline_code = "DEBUG = False\n"
    source_file.write_text(baseline_code, encoding="utf-8")

    patch = Patch(
        file_path=source_file,
        original_code=baseline_code,
        modified_code="DEBUG = True\n",
        diff="--- diff",
        status=PatchStatus.PROPOSED,
    )

    validator = PatchValidator(filesystem=fs)
    assert validator.validate_pre_patch(patch) is True

    # Now simulate an external concurrent edit to the file on disk
    source_file.write_text("DEBUG = 'external_change'\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Stale patch detected"):
        validator.validate_pre_patch(patch)


def test_us23_post_patch_syntax_error_triggers_automatic_rollback(temp_workspace, backup_dir, fs):
    """US 23: Automatically rolls back disk changes if post-patch syntax validation fails."""
    source_file = temp_workspace / "module.py"
    pristine_code = "def valid_func():\n    return 100\n"
    source_file.write_text(pristine_code, encoding="utf-8")
    original_hash = fs.compute_hash(source_file)

    # Patch contains fatal syntax error
    corrupt_code = "def broken_syntax(x:\n    return x *\n"
    patch = Patch(
        file_path=source_file,
        original_code=pristine_code,
        modified_code=corrupt_code,
        diff="--- diff",
        status=PatchStatus.PROPOSED,
    )

    backup_mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    rollback_mgr = RollbackManager(backup_manager=backup_mgr, filesystem=fs)
    validator = PatchValidator(filesystem=fs, parser_registry=ParserRegistry())

    applier = PatchApplier(
        backup_manager=backup_mgr,
        validator=validator,
        rollback_manager=rollback_mgr,
        filesystem=fs,
    )

    with pytest.raises(ValueError, match="syntax errors detected"):
        applier.apply_patch(patch)

    # Verify atomic rollback: disk file was restored to pristine state
    assert source_file.read_text(encoding="utf-8") == pristine_code
    assert fs.compute_hash(source_file) == original_hash
    assert patch.status == PatchStatus.FAILED


def test_us23_backup_manifest_persistence_and_listing(temp_workspace, backup_dir, fs):
    """US 23: Verifies list_backups correctly retrieves all persistent backup manifests."""
    f1 = temp_workspace / "a.py"
    f2 = temp_workspace / "b.py"
    f1.write_text("a = 1\n", encoding="utf-8")
    f2.write_text("b = 2\n", encoding="utf-8")

    mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    mgr.create_backup(f1, "patch-a")
    mgr.create_backup(f2, "patch-b")

    backups = mgr.list_backups()
    assert len(backups) == 2
    patch_ids = {b["patch_id"] for b in backups}
    assert "patch-a" in patch_ids
    assert "patch-b" in patch_ids


def test_us23_successful_safe_patch_lifecycle(temp_workspace, backup_dir, fs):
    """US 23: Complete safe patch application lifecycle with verified backup."""
    source_file = temp_workspace / "payment.py"
    initial_code = "def process():\n    return 'unsecured'\n"
    remediated_code = "def process():\n    return 'secured'\n"
    source_file.write_text(initial_code, encoding="utf-8")

    patch = Patch(
        file_path=source_file,
        original_code=initial_code,
        modified_code=remediated_code,
        diff="--- diff",
        status=PatchStatus.PROPOSED,
    )

    applier = PatchApplier(
        backup_manager=BackupManager(backup_dir=backup_dir, filesystem=fs),
        filesystem=fs,
    )

    success = applier.apply_patch(patch)

    assert success is True
    assert patch.status == PatchStatus.APPLIED
    assert source_file.read_text(encoding="utf-8") == remediated_code
    assert patch.backup_path.exists()
    assert patch.backup_path.read_text(encoding="utf-8") == initial_code


def test_us23_rollback_preserves_byte_for_byte_integrity(temp_workspace, backup_dir, fs):
    """US 23: Explicit rollback restores the original file with identical SHA-256 hash."""
    source_file = temp_workspace / "critical.py"
    clean_code = "SECRET_TOKEN = 'prod_secret'\n"
    source_file.write_text(clean_code, encoding="utf-8")
    clean_hash = fs.compute_hash(source_file)

    patch = Patch(
        file_path=source_file,
        original_code=clean_code,
        modified_code="SECRET_TOKEN = 'replaced'\n",
        diff="--- diff",
        status=PatchStatus.PROPOSED,
    )

    backup_mgr = BackupManager(backup_dir=backup_dir, filesystem=fs)
    rollback_mgr = RollbackManager(backup_manager=backup_mgr, filesystem=fs)
    applier = PatchApplier(backup_manager=backup_mgr, filesystem=fs)

    applier.apply_patch(patch)
    assert source_file.read_text(encoding="utf-8") == "SECRET_TOKEN = 'replaced'\n"

    # Rollback
    reverted = rollback_mgr.rollback_patch(patch)
    assert reverted is True
    assert patch.status == PatchStatus.ROLLED_BACK
    assert source_file.read_text(encoding="utf-8") == clean_code
    assert fs.compute_hash(source_file) == clean_hash
