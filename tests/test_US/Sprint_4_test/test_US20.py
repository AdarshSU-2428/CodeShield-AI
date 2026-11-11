from pathlib import Path
import pytest

from app.core.enums import Language, PatchStatus
from app.core.models.patch import Patch, PatchDiff
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupManager
from app.patches.validator import PatchValidator
from app.services.patch_service import PatchService


def test_us20_validate_virtual_syntax_valid_python():
    """Verify validate_virtual_syntax passes for well-formed Python code."""
    validator = PatchValidator()
    code = (
        "import os\n"
        "\n"
        "def safe_execute(param: str) -> bool:\n"
        "    return bool(param.strip())\n"
    )
    is_valid, err = validator.validate_virtual_syntax(code, language=Language.PYTHON)
    assert is_valid is True
    assert err is None


def test_us20_validate_virtual_syntax_invalid_python_ast():
    """Verify validate_virtual_syntax catches syntax errors with line/column/message details."""
    validator = PatchValidator()
    # Missing closing parenthesis and colon
    bad_code = (
        "def broken_function(x, y\n"
        "    return x + y\n"
    )
    is_valid, err = validator.validate_virtual_syntax(bad_code, language=Language.PYTHON)
    assert is_valid is False
    assert err is not None
    assert "Python SyntaxError" in err
    assert "line" in err.lower()


def test_us20_validate_virtual_syntax_detects_language_from_path():
    """Verify validate_virtual_syntax auto-detects language from file path extension."""
    validator = PatchValidator()
    bad_python = "class UnclosedClass:\n  def foo( self:\n    pass"
    is_valid, err = validator.validate_virtual_syntax(bad_python, file_path="backend/security.py")
    assert is_valid is False
    assert "Python SyntaxError" in err


def test_us20_validate_patch_candidate_dry_run():
    """Verify validate_patch_candidate inspects patch in-memory without disk requirements."""
    validator = PatchValidator()
    patch = Patch(
        file_path="app/auth.py",
        original_code="def login():\n    pass\n",
        modified_code="def login(:\n    pass\n",  # syntax error
        diff=PatchDiff(raw_diff="", additions_count=1, deletions_count=1, hunks=[]),
        status=PatchStatus.PROPOSED,
    )
    is_valid, err = validator.validate_patch_candidate(patch)
    assert is_valid is False
    assert "SyntaxError" in err


def test_us20_pre_application_syntax_check_blocks_corrupt_patch(tmp_path: Path):
    """
    Verify pre-application QA validation rejects corrupt/malformed code BEFORE disk write.
    The original file on disk must remain 100% pristine and no backup should be made.
    """
    target = tmp_path / "vulnerable.py"
    pristine_code = "def query(uid):\n    return f'SELECT {uid}'\n"
    target.write_text(pristine_code, encoding="utf-8")

    backup_dir = tmp_path / "backups"
    applier = PatchApplier(
        backup_manager=BackupManager(backup_dir=backup_dir),
        validator=PatchValidator(),
    )

    bad_patch = Patch(
        file_path=target,
        original_code=pristine_code,
        modified_code="def query(uid:  # BROKEN SYNTAX\n",
        diff=PatchDiff(raw_diff="", additions_count=1, deletions_count=1, hunks=[]),
        status=PatchStatus.PROPOSED,
    )

    with pytest.raises(ValueError) as exc_info:
        applier.apply_patch(bad_patch)

    assert "Pre-application syntax validation failed" in str(exc_info.value)
    assert bad_patch.status == PatchStatus.FAILED

    # Disk file must still be original
    assert target.read_text(encoding="utf-8") == pristine_code

    # No backup should have been created since validation failed before backup step
    assert len(list(backup_dir.glob("*"))) == 0


def test_us20_validate_and_apply_success(tmp_path: Path):
    """Verify validate_and_apply cleanly passes and mutates disk for valid patches."""
    target = tmp_path / "clean.py"
    original_code = "def get_key():\n    return 'insecure'\n"
    target.write_text(original_code, encoding="utf-8")

    good_patch = Patch(
        file_path=target,
        original_code=original_code,
        modified_code="def get_key():\n    import os\n    return os.environ.get('SECRET_KEY')\n",
        diff=PatchDiff(raw_diff="", additions_count=2, deletions_count=1, hunks=[]),
        status=PatchStatus.PROPOSED,
    )

    applier = PatchApplier(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))
    applied = applier.validate_and_apply(good_patch)

    assert applied is True
    assert good_patch.status == PatchStatus.APPLIED
    assert "os.environ.get" in target.read_text(encoding="utf-8")


def test_us20_patch_service_validate_patch_workflow(tmp_path: Path):
    """Verify PatchService.validate_patch and validate_and_apply work seamlessly end-to-end."""
    target = tmp_path / "service_test.py"
    target.write_text("x = 1\n", encoding="utf-8")

    service = PatchService(backup_manager=BackupManager(backup_dir=tmp_path / "backups"))

    # 1. Propose invalid patch
    bad_patch = service.propose_patch(target, "x = (\n")
    is_valid, err = service.validate_patch(bad_patch.patch_id)
    assert is_valid is False
    assert "SyntaxError" in err

    # Ensure validate_and_apply refuses to apply
    with pytest.raises(ValueError):
        service.validate_and_apply(bad_patch.patch_id)

    # 2. Propose valid patch
    good_patch = service.propose_patch(target, "x = 42\n")
    is_valid_good, err_good = service.validate_patch(good_patch.patch_id)
    assert is_valid_good is True
    assert err_good is None

    # Apply valid patch
    success = service.validate_and_apply(good_patch.patch_id)
    assert success is True
    assert target.read_text(encoding="utf-8") == "x = 42\n"