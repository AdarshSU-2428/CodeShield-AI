from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.core.enums import PatchStatus
from app.core.interfaces.filesystem import FileSystem
from app.core.models.patch import Patch
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.backup_manager import BackupManager


class PatchApplier:
    """Safely applies proposed code patches to target files after creating verified backups."""

    def __init__(
        self,
        backup_manager: Optional[BackupManager] = None,
        filesystem: Optional[FileSystem] = None,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.backup_manager: BackupManager = (
            backup_manager if backup_manager is not None else BackupManager(filesystem=self.filesystem)
        )

    def apply_patch(self, patch: Patch) -> bool:
        """Apply patch to target file with mandatory pre-application backup."""
        target_path = patch.file_path

        if not self.filesystem.exists(target_path):
            patch.status = PatchStatus.FAILED
            raise FileNotFoundError(f"Target file for patch application does not exist: {target_path}")

        try:
            # 1. Mandatory backup before disk mutation
            backup_file = self.backup_manager.create_backup(target_path, patch.patch_id)
            patch.backup_path = backup_file

            # 2. Write new modified content safely
            self.filesystem.write_text(target_path, patch.modified_code)

            # 3. Transition status
            patch.status = PatchStatus.APPLIED
            patch.applied_at = datetime.now(timezone.utc)
            return True

        except Exception as exc:
            patch.status = PatchStatus.FAILED
            raise RuntimeError(f"Failed to apply patch '{patch.patch_id}': {exc}") from exc
