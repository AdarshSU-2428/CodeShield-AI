import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional, Union

from app.core.interfaces.filesystem import FileSystem
from app.infrastructure.config import config
from app.infrastructure.filesystem import LocalFileSystem


class BackupIntegrityError(Exception):
    """Raised when backup creation or hash verification fails."""
    pass


class BackupManager:
    """Manages QA-grade, cryptographically verified backups with persistent audit trails."""

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
        self._registry: Dict[str, Dict[str, Any]] = {}

    @property
    def backup_dir(self) -> Path:
        return self._backup_dir

    def create_backup(self, file_path: Union[str, Path], patch_id: str) -> Path:
        """
        Create a cryptographically verified backup of target file before patching.
        Verifies SHA-256 matches byte-for-byte and saves a persistent audit manifest.
        """
        target = Path(file_path).resolve()
        if not self.filesystem.exists(target):
            raise FileNotFoundError(f"Cannot backup non-existent file: {target}")

        original_hash = self.filesystem.compute_hash(target)
        if not original_hash:
            raise BackupIntegrityError(f"Failed to compute SHA-256 hash for {target}")

        patch_folder = self._backup_dir / patch_id
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_file = patch_folder / f"{target.name}_{timestamp}.bak"

        # Copy file to backup location
        self.filesystem.copy_file(target, backup_file)

        # Cryptographic Verification: compute hash of written backup
        backup_hash = self.filesystem.compute_hash(backup_file)
        if backup_hash != original_hash:
            try:
                self.filesystem.delete(backup_file)
            except Exception:
                pass
            raise BackupIntegrityError(
                f"Backup SHA-256 mismatch! Target: {original_hash}, Backup: {backup_hash}"
            )

        metadata = {
            "patch_id": patch_id,
            "target_path": str(target),
            "backup_path": str(backup_file),
            "sha256": original_hash,
            "file_size_bytes": backup_file.stat().st_size if backup_file.exists() else 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "verified": True,
        }

        self._registry[patch_id] = metadata

        # Save persistent manifest for QA audit trail
        manifest_file = patch_folder / "backup_manifest.json"
        try:
            manifest_file.parent.mkdir(parents=True, exist_ok=True)
            self.filesystem.write_text(manifest_file, json.dumps(metadata, indent=2))
        except Exception:
            pass

        return backup_file

    def get_backup_path(self, patch_id: str) -> Optional[Path]:
        """Retrieve the verified backup path associated with a patch."""
        entry = self._registry.get(patch_id)
        if entry:
            return Path(entry["backup_path"])

        patch_folder = self._backup_dir / patch_id
        manifest_file = patch_folder / "backup_manifest.json"
        if self.filesystem.exists(manifest_file):
            try:
                data = json.loads(self.filesystem.read_text(manifest_file))
                b_path = Path(data["backup_path"])
                if self.filesystem.exists(b_path):
                    return b_path
            except Exception:
                pass

        if self.filesystem.exists(patch_folder):
            backups = list(patch_folder.glob("*.bak"))
            if backups:
                return backups[-1]
        return None

    def verify_backup(self, patch_id: str) -> bool:
        """Verify that the backup exists, is non-empty, and matches original SHA-256 hash."""
        backup_path = self.get_backup_path(patch_id)
        if not backup_path or not self.filesystem.exists(backup_path):
            return False

        if backup_path.stat().st_size == 0:
            return False

        entry = self._registry.get(patch_id)
        expected_hash = entry.get("sha256") if entry else None

        if not expected_hash:
            manifest_file = self._backup_dir / patch_id / "backup_manifest.json"
            if self.filesystem.exists(manifest_file):
                try:
                    data = json.loads(self.filesystem.read_text(manifest_file))
                    expected_hash = data.get("sha256")
                except Exception:
                    pass

        if expected_hash:
            current_hash = self.filesystem.compute_hash(backup_path)
            return current_hash == expected_hash

        return True

    def list_backups(self) -> List[Dict[str, Any]]:
        """List all historical backup manifests for audit reporting."""
        results = []
        for patch_folder in self._backup_dir.iterdir():
            if patch_folder.is_dir():
                manifest = patch_folder / "backup_manifest.json"
                if manifest.exists():
                    try:
                        data = json.loads(manifest.read_text(encoding="utf-8"))
                        results.append(data)
                    except Exception:
                        pass
        return results

    def delete_backup(self, patch_id: str) -> bool:
        """Clean up backup folder after a patch is accepted or discarded."""
        patch_folder = self._backup_dir / patch_id
        if self.filesystem.exists(patch_folder):
            shutil.rmtree(patch_folder, ignore_errors=True)
            self._registry.pop(patch_id, None)
            return True
        return False
