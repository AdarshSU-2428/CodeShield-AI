from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from app.core.enums import PatchStatus
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.llm import LLMClient
from app.core.models.audit import AuditFinding
from app.core.models.patch import ApprovalRequiredError, Patch
from app.infrastructure.filesystem import LocalFileSystem
from app.infrastructure.llm import GroqLLMClient
from app.patches import (
    BackupManager,
    DiffGenerator,
    PatchApplier,
    RollbackManager,
)


class PatchService:
    """
    Coordinates code patch proposal, Git-style diff review,
    polyglot syntax diagnostics, AI remediation, safe disk application, approval gates, and rollback.
    """

    def __init__(
        self,
        diff_generator: Optional[DiffGenerator] = None,
        backup_manager: Optional[BackupManager] = None,
        applier: Optional[PatchApplier] = None,
        rollback_manager: Optional[RollbackManager] = None,
        llm_client: Optional[LLMClient] = None,
        filesystem: Optional[FileSystem] = None,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.diff_generator: DiffGenerator = (
            diff_generator if diff_generator is not None else DiffGenerator()
        )
        self.backup_manager: BackupManager = (
            backup_manager if backup_manager is not None else BackupManager(filesystem=self.filesystem)
        )
        self.applier: PatchApplier = (
            applier if applier is not None else PatchApplier(
                backup_manager=self.backup_manager, filesystem=self.filesystem
            )
        )
        self.rollback_manager: RollbackManager = (
            rollback_manager if rollback_manager is not None else RollbackManager(
                backup_manager=self.backup_manager, filesystem=self.filesystem
            )
        )
        self.llm_client: LLMClient = (
            llm_client if llm_client is not None else GroqLLMClient()
        )

        # In-memory patch storage: patch_id -> Patch
        self._patches: Dict[str, Patch] = {}

    def propose_patch(
        self,
        file_path: Union[str, Path],
        modified_code: str,
        finding_id: Optional[str] = None,
        description: str = "",
    ) -> Patch:
        """Create a patch proposal without modifying the underlying disk file."""
        target_path = Path(file_path).resolve()

        if not self.filesystem.exists(target_path):
            raise FileNotFoundError(f"Target file does not exist: {target_path}")

        original_code = self.filesystem.read_text(target_path)
        diff = self.diff_generator.generate_diff(
            original_code=original_code,
            modified_code=modified_code,
            file_name=target_path.name,
            include_git_header=True,
        )

        patch = Patch(
            file_path=target_path,
            original_code=original_code,
            modified_code=modified_code,
            diff=diff,
            finding_id=finding_id,
            status=PatchStatus.PROPOSED,
            description=description,
        )

        self._patches[patch.patch_id] = patch
        
        return patch

    def _clean_markdown_code(self, raw_code: str) -> str:
        """Extract clean source code from AI response if wrapped in markdown code fences."""
        text = raw_code.strip()
        blocks = re.findall(r"```(\w*)\s*([\s\S]*?)```", text)
        if blocks:
            code_blocks = [
                content.strip()
                for lang, content in blocks
                if lang.lower() not in {"markdown", "md", "txt", "text"} and content.strip()
            ]
            if code_blocks:
                return max(code_blocks, key=len)
            return max((content.strip() for _, content in blocks), key=len)

        return text

    def generate_ai_patch(
        self,
        file_path: Union[str, Path],
        finding: AuditFinding,
    ) -> Patch:
        """Generate a remediation patch using the AI auditor for a specific security finding."""
        target_path = Path(file_path).resolve()
        
        if not self.filesystem.exists(target_path):
            raise FileNotFoundError(f"Source file not found: {target_path}")

        original_code = self.filesystem.read_text(target_path)

        prompt = (
            f"You are an expert security engineer. Fix the following vulnerability in the provided code.\n\n"
            f"Vulnerability Title: {finding.title}\n"
            f"CWE ID: {finding.cwe_id}\n"
            f"Line Number: {finding.line_number}\n"
            f"Recommendation: {finding.recommendation}\n\n"
            f"Original Source Code:\n{original_code}\n\n"
            f"Output ONLY the complete, remediated source code. Do NOT add conversational text or markdown explanation."
        )

        messages = [
            {"role": "system", "content": "You output only clean, valid, drop-in replacement source code."},
            {"role": "user", "content": prompt},
        ]

        response = self.llm_client.chat(messages=messages, temperature=0.0)
        remediated_code = self._clean_markdown_code(response.content)

        return self.propose_patch(
            file_path=target_path,
            modified_code=remediated_code,
            finding_id=finding.finding_id,
            description=f"AI Remediation for {finding.title} ({finding.cwe_id or 'Quality Issue'})",
        )

    def get_patch(self, patch_id: str) -> Optional[Patch]:
        """Retrieve a patch by its unique ID."""
        return self._patches.get(patch_id)

    def list_patches(
        self,
        file_path: Optional[Union[str, Path]] = None,
        status: Optional[PatchStatus] = None,
    ) -> List[Patch]:
        """List patches with optional file_path and status filtering."""
        patches = list(self._patches.values())
        
        if file_path:
            target = Path(file_path).resolve()
            patches = [p for p in patches if p.file_path == target]
        
        if status:
            patches = [p for p in patches if p.status == status]
        
        return patches

    def get_git_diff(self, patch_id: str) -> str:
        """
        Retrieve the standard Git-style diff representation for a proposed patch
        to allow code reviewers to inspect line additions, deletions, and context.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        return patch.git_diff

    def get_diff_stats(self, patch_id: str) -> Dict[str, Any]:
        """
        Retrieve diff statistics for code review (additions, deletions, total, diff_stat).
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        return {
            "patch_id": patch.patch_id,
            "file_path": patch.file_path.as_posix(),
            "additions_count": patch.diff.additions_count if patch.diff else 0,
            "deletions_count": patch.diff.deletions_count if patch.diff else 0,
            "total_changes": patch.diff.total_changes if patch.diff else 0,
            "diff_stat": patch.diff_stat,
            "file_stat": patch.diff.file_stat if patch.diff else None,
        }

    def get_patch_hunks(self, patch_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve structured hunks with line-by-line coordinate mapping for review.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        return patch.diff.hunks if patch.diff else []

    def validate_patch_syntax(self, patch_id: str) -> Dict[str, Any]:
        """
        Retrieve detailed polyglot syntax diagnostics (line, column, token, valid)
        for a patch proposal before applying it to disk.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        return self.applier.validator.get_syntax_diagnostics(
            content=patch.modified_code,
            file_path=patch.file_path,
        )

    def validate_patch(self, patch_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validate candidate patch syntax in-memory without mutating disk.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        return self.applier.validator.validate_patch_candidate(patch)

    def approve_patch(
        self,
        patch_id: str,
        approved_by: Optional[str] = "reviewer",
    ) -> Patch:
        """
        Explicitly approve a proposed patch, unblocking it for disk application.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")

        patch.approve(approved_by=approved_by)
        return patch

    def reject_patch(
        self,
        patch_id: str,
        reason: Optional[str] = None,
    ) -> Patch:
        """
        US 30: Explicitly reject a proposed patch.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")

        patch.reject(reason=reason)
        return patch

    def validate_and_apply(
        self,
        patch_id: str,
        require_approval: bool = False,
    ) -> bool:
        """
        Explicitly validate candidate patch syntax and apply atomically to disk.
        """
        patch = self.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        return self.applier.apply_patch(
            patch,
            validate_pre_syntax=True,
            require_approval=require_approval,
        )

    def apply_patch(
        self,
        patch_id: str,
        require_approval: bool = False,
    ) -> bool:
        """Safely apply a proposed patch to disk with verified backup."""
        patch = self.get_patch(patch_id)
        
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        
        return self.applier.apply_patch(
            patch,
            validate_pre_syntax=True,
            require_approval=require_approval,
        )

    def rollback_patch(self, patch_id: str) -> bool:
        """Restore target file from backup, reverting applied patch."""
        patch = self.get_patch(patch_id)
        
        if not patch:
            raise ValueError(f"Patch with ID '{patch_id}' not found.")
        
        return self.rollback_manager.rollback_patch(patch)