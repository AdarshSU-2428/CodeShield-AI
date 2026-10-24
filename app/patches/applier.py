from datetime import datetime, timezone
from pathlib import Path
import threading
from typing import Optional

from app.core.enums import PatchStatus
from app.core.interfaces.filesystem import FileSystem
from app.core.models.patch import Patch
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.backup_manager import BackupManager
from app.patches.rollback_manager import RollbackManager
from app.patches.validator import PatchValidator


class PatchApplier:
    """Safely applies proposed code patches to target files after creating verified backups."""

    def __init__(
        self,
        backup_manager: Optional[BackupManager] = None,
        validator: Optional[PatchValidator] = None,
        rollback_manager: Optional[RollbackManager] = None,
        filesystem: Optional[FileSystem] = None,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.backup_manager: BackupManager = (
            backup_manager if backup_manager is not None else BackupManager(filesystem=self.filesystem)
        )
        self.validator: PatchValidator = (
            validator if validator is not None else PatchValidator(filesystem=self.filesystem)
        )
        self.rollback_manager: RollbackManager = (
            rollback_manager if rollback_manager is not None else RollbackManager(
                backup_manager=self.backup_manager, filesystem=self.filesystem
            )
        )
        self._lock = threading.Lock()

    def apply_patch(self, patch: Patch) -> bool:
        """Apply patch to target file with mandatory pre-application backup and post-patch validation."""
        with self._lock:
            target_path = Path(patch.file_path).resolve()

            if not self.filesystem.exists(target_path):
                patch.status = PatchStatus.FAILED
                raise FileNotFoundError(f"Target file for patch application does not exist: {target_path}")

            try:
                # 1. Pre-patch validation (detect stale patches or empty files)
                self.validator.validate_pre_patch(patch)

                # 2. Mandatory cryptographic backup before disk mutation
                backup_file = self.backup_manager.create_backup(target_path, patch.patch_id)
                patch.backup_path = backup_file

                # 3. Write new modified content to disk
                self.filesystem.write_text(target_path, patch.modified_code)

                # 4. Post-patch validation (syntax & integrity check)
                if not self.validator.validate_post_patch(patch):
                    # Automatic rollback on post-patch validation failure
                    patch.status = PatchStatus.APPLIED
                    self.rollback_manager.rollback_patch(patch)
                    patch.status = PatchStatus.FAILED
                    raise ValueError("Post-patch validation failed: syntax errors detected. Automatically rolled back.")

                # 5. Transition status to APPLIED
                patch.status = PatchStatus.APPLIED
                patch.applied_at = datetime.now(timezone.utc)
                return True

            except Exception as exc:
                patch.status = PatchStatus.FAILED
                raise exc
