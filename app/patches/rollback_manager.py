from pathlib import Path
from typing import Optional

from app.core.enums import PatchStatus
from app.core.interfaces.filesystem import FileSystem
from app.core.models.patch import Patch
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.backup_manager import BackupManager


class RollbackManager:
    """Restores original files byte-for-byte from verified backups when reverting patches."""

    def __init__(
        self,
        backup_manager: Optional[BackupManager] = None,
        filesystem: Optional[FileSystem] = None,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.backup_manager: BackupManager = (
            backup_manager if backup_manager is not None else BackupManager(filesystem=self.filesystem)
        )

    def rollback_patch(self, patch: Patch) -> bool:
        """Restore target file from its pre-patch backup."""
        if patch.status != PatchStatus.APPLIED:
            raise ValueError(
                f"Cannot rollback patch '{patch.patch_id}' with status '{patch.status.value}'. "
                "Only applied patches can be rolled back."
            )

        backup_path = patch.backup_path or self.backup_manager.get_backup_path(patch.patch_id)
        
        if not backup_path or not self.filesystem.exists(backup_path):
            raise FileNotFoundError(
                f"Backup file for patch '{patch.patch_id}' not found. Cannot rollback safely."
            )

        # Verify integrity before restoring
        if not self.backup_manager.verify_backup(patch.patch_id):
            raise ValueError(f"Backup verification failed for patch '{patch.patch_id}'.")

        try:
            # Overwrite current file with verified original backup
            self.filesystem.copy_file(backup_path, patch.file_path)
            patch.status = PatchStatus.ROLLED_BACK
            return True
        
        except Exception as exc:
            raise RuntimeError(f"Failed to restore file during rollback: {exc}") from exc
