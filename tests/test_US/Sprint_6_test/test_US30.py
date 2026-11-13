from pathlib import Path
import pytest

from app.core.enums import PatchStatus
from app.core.models.patch import ApprovalRequiredError, Patch, PatchDiff
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupManager
from app.patches.rollback_manager import RollbackManager
from app.patches.validator import PatchValidator
from app.services.patch_service import PatchService


class VirtualFS(LocalFileSystem):
    """In-memory filesystem for patch approval and rollback testing."""

    def __init__(self, files=None):
        self._files = files or {}

    def _normalize(self, path) -> str:
        return Path(path).as_posix().lower()

    def exists(self, path) -> bool:
        norm = self._normalize(path)
        return any(norm.endswith(k.lower()) or k.lower().endswith(norm) for k in self._files)

    def is_directory(self, path) -> bool:
        return False

    def read_text(self, path, encoding="utf-8") -> str:
        norm = self._normalize(path)
        for k, v in self._files.items():
            if norm.endswith(k.lower()) or k.lower().endswith(norm):
                return v
        raise FileNotFoundError(str(path))

    def write_text(self, path, content: str, encoding="utf-8") -> None:
        norm = self._normalize(path)
        # Update existing key if matched
        for k in list(self._files.keys()):
            if norm.endswith(k.lower()) or k.lower().endswith(norm):
                self._files[k] = content
                return
        self._files[norm] = content

    def compute_hash(self, path) -> str:
        import hashlib
        content = self.read_text(path)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def copy_file(self, src, dst) -> None:
        content = self.read_text(src)
        self.write_text(dst, content)


def test_us30_patch_starts_in_proposed_state():
    """Verify newly proposed patches default to PROPOSED state without approval metadata."""
    file_path = "src/security.py"
    fs = VirtualFS({file_path: "SECRET = 'raw_key'\n"})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(
        file_path=file_path,
        modified_code="SECRET = os.getenv('SECRET')\n",
        description="Extract hardcoded secret",
    )

    assert patch.status == PatchStatus.PROPOSED
    assert patch.is_approved is False
    assert patch.approved_by is None
    assert patch.approved_at is None
    assert patch.rejection_reason is None


def test_us30_approval_gate_blocks_unapproved_application():
    """Verify that applying an unapproved patch when approval is required raises ApprovalRequiredError."""
    file_path = "src/payment.py"
    orig_code = "def charge(amt): return True\n"
    fs = VirtualFS({file_path: orig_code})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(
        file_path=file_path,
        modified_code="def charge(amt): return validate(amt)\n",
    )

    # Attempting to apply without approval MUST raise ApprovalRequiredError
    with pytest.raises(ApprovalRequiredError, match="without explicit approval"):
        svc.apply_patch(patch.patch_id, require_approval=True)

    # File on disk must remain strictly untouched
    assert fs.read_text(file_path) == orig_code
    assert patch.status == PatchStatus.PROPOSED


def test_us30_approve_patch_workflow():
    """Verify that approve_patch transitions status to APPROVED and populates audit metadata."""
    file_path = "src/auth.py"
    fs = VirtualFS({file_path: "def login(): pass\n"})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(file_path=file_path, modified_code="def login(): return True\n")

    approved_patch = svc.approve_patch(patch.patch_id, approved_by="lead_security_reviewer")

    assert approved_patch.status == PatchStatus.APPROVED
    assert approved_patch.is_approved is True
    assert approved_patch.approved_by == "lead_security_reviewer"
    assert approved_patch.approved_at is not None

    # Now applying with require_approval=True succeeds
    success = svc.apply_patch(patch.patch_id, require_approval=True)
    assert success is True
    assert approved_patch.status == PatchStatus.APPLIED
    assert fs.read_text(file_path) == "def login(): return True\n"


def test_us30_reject_patch_workflow():
    """Verify that reject_patch transitions status to REJECTED and records rejection reason."""
    file_path = "src/db.py"
    fs = VirtualFS({file_path: "def query(): pass\n"})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(file_path=file_path, modified_code="def query(): execute()\n")

    rejected_patch = svc.reject_patch(patch.patch_id, reason="Introduces breaking API signature")

    assert rejected_patch.status == PatchStatus.REJECTED
    assert rejected_patch.rejection_reason == "Introduces breaking API signature"

    # Cannot apply a rejected patch
    with pytest.raises(ApprovalRequiredError):
        svc.apply_patch(patch.patch_id, require_approval=True)


def test_us30_cannot_approve_or_reject_applied_patch():
    """Verify that applied or rolled back patches cannot be re-approved or rejected."""
    file_path = "src/api.py"
    fs = VirtualFS({file_path: "x = 1\n"})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(file_path=file_path, modified_code="x = 2\n")
    svc.approve_patch(patch.patch_id)
    svc.apply_patch(patch.patch_id)

    with pytest.raises(ValueError, match="Cannot approve patch in state applied"):
        patch.approve()

    with pytest.raises(ValueError, match="Cannot reject patch in state applied"):
        patch.reject()


def test_us30_safe_rollback_restores_byte_for_byte_fidelity(tmp_path: Path):
    """
    US 30: Verify rollback_patch reverts applied patch using SHA-256 backup,
    restoring the exact pre-patch disk content byte-for-byte.
    """
    target_file = tmp_path / "critical_system.py"
    original_bytes = "def calculate_risk(portfolio):\n    return sum(portfolio) * 0.05\n"
    target_file.write_text(original_bytes, encoding="utf-8")

    backup_dir = tmp_path / "backups"
    svc = PatchService(
        backup_manager=BackupManager(backup_dir=backup_dir),
    )

    patch = svc.propose_patch(
        file_path=target_file,
        modified_code="def calculate_risk(portfolio):\n    return sum(portfolio) * 0.10\n",
    )
    svc.approve_patch(patch.patch_id, approved_by="admin")

    # 1. Apply patch
    applied = svc.apply_patch(patch.patch_id, require_approval=True)
    assert applied is True
    assert target_file.read_text(encoding="utf-8") != original_bytes

    # 2. Rollback patch
    rolled_back = svc.rollback_patch(patch.patch_id)
    assert rolled_back is True
    assert patch.status == PatchStatus.ROLLED_BACK
    assert patch.is_rolled_back is True

    # 3. File content must match pre-patch baseline byte-for-byte!
    restored_bytes = target_file.read_text(encoding="utf-8")
    assert restored_bytes == original_bytes


def test_us30_rollback_unapplied_patch_raises_error():
    """Verify attempting to rollback an unapplied patch raises an informative ValueError."""
    file_path = "src/handler.py"
    fs = VirtualFS({file_path: "code = True\n"})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(file_path=file_path, modified_code="code = False\n")

    with pytest.raises(ValueError, match="Only applied patches can be rolled back"):
        svc.rollback_patch(patch.patch_id)
