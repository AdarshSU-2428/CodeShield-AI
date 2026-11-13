from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from app.core.enums import PatchStatus


class ApprovalRequiredError(ValueError):
    """Raised when an attempt is made to apply an unapproved patch."""
    pass


class PatchDiff:
    """
    US 18: Encapsulates standard Git diff representations, change statistics,
    and structured line-by-line breakdowns for code reviewers.
    """

    def __init__(
        self,
        raw_diff: str,
        additions_count: int = 0,
        deletions_count: int = 0,
        hunks: Optional[List[Dict[str, Any]]] = None,
        diff_stat: Optional[str] = None,
        file_stat: Optional[str] = None,
    ):
        self.raw_diff: str = raw_diff
        self.additions_count: int = additions_count
        self.deletions_count: int = deletions_count
        self.hunks: List[Dict[str, Any]] = hunks if hunks is not None else []
        self.diff_stat: Optional[str] = diff_stat
        self.file_stat: Optional[str] = file_stat

    @property
    def git_diff(self) -> str:
        """Alias returning standard Git unified diff string."""
        return self.raw_diff

    @property
    def total_changes(self) -> int:
        """Total modified line count (additions + deletions)."""
        return self.additions_count + self.deletions_count

    def to_dict(self) -> Dict[str, Any]:
        """Serialize diff representation for API and UI rendering."""
        return {
            "raw_diff": self.raw_diff,
            "git_diff": self.git_diff,
            "additions_count": self.additions_count,
            "deletions_count": self.deletions_count,
            "total_changes": self.total_changes,
            "diff_stat": self.diff_stat,
            "file_stat": self.file_stat,
            "hunks_count": len(self.hunks),
            "hunks": self.hunks,
        }


class Patch:
    """
    US 18 & US 30: Represents an AI-generated code modification proposal
    with Git-style diff review, approval gates, and rollback support.
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        original_code: str,
        modified_code: str,
        diff: PatchDiff,
        finding_id: Optional[str] = None,
        patch_id: Optional[str] = None,
        status: PatchStatus = PatchStatus.PROPOSED,
        created_at: Optional[datetime] = None,
        backup_path: Optional[Union[str, Path]] = None,
        applied_at: Optional[datetime] = None,
        description: Optional[str] = None,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime] = None,
        rejection_reason: Optional[str] = None,
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
        
        # User Story 30: Approval Metadata
        self.approved_by: Optional[str] = approved_by
        self.approved_at: Optional[datetime] = approved_at
        self.rejection_reason: Optional[str] = rejection_reason

    @property
    def git_diff(self) -> str:
        """Return the standard Git-style diff for reviewer inspection."""
        return self.diff.raw_diff if self.diff else ""

    @property
    def diff_stat(self) -> str:
        """Return short diffstat summary (e.g., '1 file changed, 2 insertions(+), 1 deletion(-)')."""
        return self.diff.diff_stat if self.diff and self.diff.diff_stat else ""

    @property
    def is_approved(self) -> bool:
        return self.status == PatchStatus.APPROVED

    @property
    def is_applied(self) -> bool:
        return self.status == PatchStatus.APPLIED

    @property
    def is_rolled_back(self) -> bool:
        return self.status == PatchStatus.ROLLED_BACK

    def approve(self, approved_by: Optional[str] = "user") -> None:
        """Explicitly approve this patch for disk application."""
        if self.status in (PatchStatus.APPLIED, PatchStatus.ROLLED_BACK):
            raise ValueError(f"Cannot approve patch in state {self.status.value}")
        self.status = PatchStatus.APPROVED
        self.approved_by = approved_by or "user"
        self.approved_at = datetime.now(timezone.utc)

    def reject(self, reason: Optional[str] = None) -> None:
        """Reject this patch."""
        if self.status in (PatchStatus.APPLIED, PatchStatus.ROLLED_BACK):
            raise ValueError(f"Cannot reject patch in state {self.status.value}")
        self.status = PatchStatus.REJECTED
        self.rejection_reason = reason or "Rejected by reviewer"

    def to_git_diff(self) -> str:
        """Format complete Git-style patch string ready for code review."""
        return self.git_diff

    def to_dict(self) -> Dict[str, Any]:
        """Serialize patch object for REST endpoints and UI."""
        return {
            "patch_id": self.patch_id,
            "file_path": self.file_path.as_posix(),
            "finding_id": self.finding_id,
            "status": self.status.value,
            "description": self.description,
            "git_diff": self.git_diff,
            "diff_stat": self.diff_stat,
            "diff": self.diff.to_dict() if self.diff else None,
            "created_at": self.created_at.isoformat(),
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "backup_path": self.backup_path.as_posix() if self.backup_path else None,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "rejection_reason": self.rejection_reason,
        }

    def __repr__(self) -> str:
        return f"<Patch id='{self.patch_id}' file='{self.file_path.name}' status='{self.status.value}'>"