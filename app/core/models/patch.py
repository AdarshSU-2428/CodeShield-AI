from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.core.enums import PatchStatus


class PatchDiff:
    """Encapsulates unified diff representation and line-by-line breakdown for UI rendering."""

    def __init__(
        self,
        raw_diff: str,
        additions_count: int = 0,
        deletions_count: int = 0,
        hunks: Optional[List[Dict[str, Any]]] = None,
    ):
        self.raw_diff: str = raw_diff
        self.additions_count: int = additions_count
        self.deletions_count: int = deletions_count
        self.hunks: List[Dict[str, Any]] = hunks if hunks is not None else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_diff": self.raw_diff,
            "additions_count": self.additions_count,
            "deletions_count": self.deletions_count,
            "hunks": self.hunks,
        }


class Patch:
    """Represents a code modification patch proposed to fix an identified finding."""

    def __init__(
        self,
        file_path: Union[str, Path],
        original_code: str,
        modified_code: str,
        diff: PatchDiff,
        finding_id: Optional[str] = None,
        patch_id: Optional[str] = None,
        status: PatchStatus = PatchStatus.PENDING,
        created_at: Optional[datetime] = None,
        backup_path: Optional[Union[str, Path]] = None,
        applied_at: Optional[datetime] = None,
        description: Optional[str] = None,
    ):
        self.patch_id: str = patch_id if patch_id else f"PATCH-{uuid.uuid4().hex[:8].upper()}"
        self.file_path: Path = Path(file_path).resolve() if isinstance(file_path, str) else file_path.resolve()
        self.original_code: str = original_code
        self.modified_code: str = modified_code
        self.diff: PatchDiff = diff
        self.finding_id: Optional[str] = finding_id
        self.status: PatchStatus = status
        self.created_at: datetime = created_at if created_at else datetime.now(timezone.utc)
        self.backup_path: Optional[Path] = (
            Path(backup_path).resolve() if backup_path is not None else None
        )
        self.applied_at: Optional[datetime] = applied_at
        self.description: str = description if description else "AI-generated security/quality remediation patch"

    @property
    def is_applied(self) -> bool:
        return self.status == PatchStatus.APPLIED

    @property
    def is_rolled_back(self) -> bool:
        return self.status == PatchStatus.ROLLED_BACK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "file_path": self.file_path.as_posix(),
            "finding_id": self.finding_id,
            "status": self.status.value,
            "description": self.description,
            "diff": self.diff.to_dict(),
            "created_at": self.created_at.isoformat(),
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "backup_path": self.backup_path.as_posix() if self.backup_path else None,
        }

    def __repr__(self) -> str:
        return f"<Patch id='{self.patch_id}' file='{self.file_path.name}' status='{self.status.value}'>"
