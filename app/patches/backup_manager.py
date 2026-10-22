from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Any, Dict, Optional, Union

from app.core.interfaces.filesystem import FileSystem
from app.infrastructure.config import config
from app.infrastructure.filesystem import LocalFileSystem


class BackupManager:
    """Manages secure, timestamped backups of source files prior to patch application."""

    def __init__(
        self,
        backup_dir: Optional[Union[str, Path]] = None,
        filesystem: Optional[FileSystem] = None,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()

        if backup_dir is not None:
            self._backup_dir = Path(backup_dir).resolve()
        else:
            raw_dir = config._raw_config.get("patch", {}).get("backup_dir", "data/backups")
            self._backup_dir = Path(raw_dir).resolve()

        self._backup_dir.mkdir(parents=True, exist_ok=True)
        # In-memory registry mapping patch_id -> metadata
        self._registry: Dict[str, Dict[str, Any]] = {}

    @property
    def backup_dir(self) -> Path:
        return self._backup_dir

    def create_backup(self, file_path: Union[str, Path], patch_id: str) -> Path:
        """Create an exact backup of target file before patching."""
        target = Path(file_path).resolve()
        
        if not self.filesystem.exists(target):
            raise FileNotFoundError(f"Cannot backup non-existent file: {target}")

        patch_folder = self._backup_dir / patch_id
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_file = patch_folder / f"{target.name}_{timestamp}.bak"

        # Delegate copy and hash computation to our existing FileSystem adapter
        self.filesystem.copy_file(target, backup_file)
        file_hash = self.filesystem.compute_hash(target)

        self._registry[patch_id] = {
            "target_path": target,
            "backup_path": backup_file,
            "sha256": file_hash,
            "created_at": datetime.now(timezone.utc),
        }

        return backup_file

    def get_backup_path(self, patch_id: str) -> Optional[Path]:
        """Retrieve the backup path associated with a patch."""
        entry = self._registry.get(patch_id)
        if entry:
            return entry["backup_path"]

        patch_folder = self._backup_dir / patch_id
        if self.filesystem.exists(patch_folder):
            backups = list(patch_folder.glob("*.bak"))
            if backups:
                return backups[-1]
        return None

    def verify_backup(self, patch_id: str) -> bool:
        """Verify that the backup exists, is non-empty, and matches original hash."""
        backup_path = self.get_backup_path(patch_id)
        if not backup_path or not self.filesystem.exists(backup_path):
            return False

        if backup_path.stat().st_size == 0:
            return False

        entry = self._registry.get(patch_id)
        if entry and "sha256" in entry:
            current_hash = self.filesystem.compute_hash(backup_path)
            return current_hash == entry["sha256"]

        return True

    def delete_backup(self, patch_id: str) -> bool:
        """Clean up backup folder after a patch is permanently accepted."""
        patch_folder = self._backup_dir / patch_id
        if self.filesystem.exists(patch_folder):
            shutil.rmtree(patch_folder, ignore_errors=True)
            self._registry.pop(patch_id, None)
            return True
        return False
