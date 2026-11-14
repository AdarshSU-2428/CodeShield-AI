from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.api.routes.audit import audit_service
from app.api.routes.project import project_service
from app.api.schemas import (
    BatchApplyRequest,
    BatchApplyResponse,
    BatchProposeProjectRequest,
    BatchProposeResponse,
    BatchRollbackRequest,
    BatchRollbackResponse,
    PatchApplyResponse,
    PatchApprovalRequest,
    PatchProposeRequest,
    PatchRejectionRequest,
    PatchResponse,
    PatchRollbackResponse,
)
from app.core.models.patch import ApprovalRequiredError, Patch
from app.infrastructure.filesystem import LocalFileSystem
from app.infrastructure.llm import GroqLLMClient
from app.patches.backup_manager import BackupManager
from app.patches.generator import DiffGenerator
from app.patches.rollback_manager import RollbackManager
from app.services.patch_service import PatchService

router = APIRouter(prefix="/api/patches", tags=["Patches"])

# Singleton PatchService instance for API runtime
_fs = LocalFileSystem()
_backup_mgr = BackupManager(filesystem=_fs)
_diff_gen = DiffGenerator(context_lines=3)
_rollback_mgr = RollbackManager(backup_manager=_backup_mgr, filesystem=_fs)
_llm = GroqLLMClient()

patch_service = PatchService(
    diff_generator=_diff_gen,
    backup_manager=_backup_mgr,
    rollback_manager=_rollback_mgr,
    llm_client=_llm,
    filesystem=_fs,
)


def _serialize_patch(patch: Patch) -> PatchResponse:
    """Serialize a domain Patch model to Pydantic PatchResponse."""
    d = patch.to_dict()
    diff_obj = patch.diff
    return PatchResponse(
        patch_id=patch.patch_id,
        file_path=str(patch.file_path),
        finding_id=patch.finding_id,
        status=patch.status.value,
        description=patch.description,
        git_diff=patch.git_diff,
        diff_stat=patch.diff_stat,
        additions_count=diff_obj.additions_count if diff_obj else 0,
        deletions_count=diff_obj.deletions_count if diff_obj else 0,
        total_changes=diff_obj.total_changes if diff_obj else 0,
        hunks=diff_obj.hunks if diff_obj else [],
        created_at=patch.created_at.isoformat(),
        applied_at=patch.applied_at.isoformat() if patch.applied_at else None,
        approved_by=patch.approved_by,
        approved_at=patch.approved_at.isoformat() if patch.approved_at else None,
        rejection_reason=patch.rejection_reason,
    )



# FILE-BY-FILE PATCH ENDPOINTS
@router.post("/propose", response_model=PatchResponse, status_code=status.HTTP_201_CREATED)
def propose_patch(req: PatchProposeRequest):
    """
    Propose an individual code patch for a file.
    Generates Git-style unified diff with additions/deletions statistics and structured hunks.
    File remains strictly untouched on disk.
    """
    try:
        patch = patch_service.propose_patch(
            file_path=req.file_path,
            modified_code=req.modified_code,
            finding_id=req.finding_id,
            description=req.description or "User or AI suggested code remediation",
        )
        return _serialize_patch(patch)
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to propose patch: {exc}")


@router.get("", response_model=List[PatchResponse])
def list_patches(
    file_path: Optional[str] = Query(None, description="Optional filter by target file path"),
    status_filter: Optional[str] = Query(None, alias="status", description="Optional filter by status"),
):
    """List all proposed, approved, or applied patches with optional filters."""
    patches = patch_service.list_patches()
    if file_path:
        norm = Path(file_path).as_posix().lower()
        patches = [p for p in patches if Path(p.file_path).as_posix().lower() == norm]
    if status_filter:
        patches = [p for p in patches if p.status.value.lower() == status_filter.lower()]
    return [_serialize_patch(p) for p in patches]


# BULK PROJECT BATCH REMEDIATION ENDPOINTS
@router.post("/batch/propose-project", response_model=BatchProposeResponse)
def batch_propose_project(req: BatchProposeProjectRequest):
    """
    Generate candidate remediation patches for all actionable findings in a project.
    Can be used by the '⚡ Patch Entire Project' button to prepare bulk patches for review.
    """
    project = project_service.get_project(req.project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{req.project_id}' not found.")

    # Find latest completed audit report for this project
    # Collect all findings across completed reports
    actionable_findings = []
    for job_id, report in audit_service._reports.items():
        if report.project_id == req.project_id:
            for f in report.findings:
                if f.remediation_code:
                    if req.finding_ids is None or f.finding_id in req.finding_ids:
                        actionable_findings.append(f)

    generated_patches: List[Patch] = []
    for finding in actionable_findings:
        try:
            target_file = Path(finding.file_path)
            if not target_file.is_absolute():
                target_file = (project.root_path / target_file).resolve()

            if not _fs.exists(target_file):
                continue

            orig_code = _fs.read_text(target_file)
            mod_code = finding.remediation_code

            # If remediation code is a small snippet, don't wipe whole file
            # If full code replacement or structured replacement:
            p = patch_service.propose_patch(
                file_path=target_file,
                modified_code=mod_code,
                finding_id=finding.finding_id,
                description=f"Automated remediation for {finding.title}",
            )
            generated_patches.append(p)
        except Exception:
            continue

    return BatchProposeResponse(
        project_id=req.project_id,
        total_patches_generated=len(generated_patches),
        patches=[_serialize_patch(p) for p in generated_patches],
    )


@router.post("/batch/apply", response_model=BatchApplyResponse)
def batch_apply_patches(req: BatchApplyRequest):
    """
    Bulk apply multiple patches with approval and pre-flight validation.
    Applies each valid patch, establishes backups, and logs any failures without halting.
    """
    applied = []
    failed = []

    for patch_id in req.patch_ids:
        patch = patch_service.get_patch(patch_id)
        if not patch:
            failed.append({"patch_id": patch_id, "error": "Patch not found"})
            continue

        try:
            # 1. Approve
            patch_service.approve_patch(patch_id, approved_by=req.approved_by)
            # 2. Apply with pre-flight check and backup
            patch_service.apply_patch(patch_id, require_approval=True)
            applied.append(patch_id)
        except Exception as exc:
            failed.append({"patch_id": patch_id, "error": str(exc)})

    return BatchApplyResponse(
        success_count=len(applied),
        failed_count=len(failed),
        applied_patches=applied,
        failed_patches=failed,
        message=f"Applied {len(applied)} patches, {len(failed)} failed.",
    )


@router.post("/batch/rollback", response_model=BatchRollbackResponse)
def batch_rollback_patches(req: BatchRollbackRequest):
    """
    Roll back an entire batch of applied patches back to their original baseline state.
    """
    rolled_back = []
    failed = []

    for patch_id in req.patch_ids:
        patch = patch_service.get_patch(patch_id)
        if not patch:
            failed.append({"patch_id": patch_id, "error": "Patch not found"})
            continue

        try:
            patch_service.rollback_patch(patch_id)
            rolled_back.append(patch_id)
        except Exception as exc:
            failed.append({"patch_id": patch_id, "error": str(exc)})

    return BatchRollbackResponse(
        success_count=len(rolled_back),
        failed_count=len(failed),
        rolled_back_patches=rolled_back,
        failed_patches=failed,
        message=f"Rolled back {len(rolled_back)} patches, {len(failed)} failed.",
    )



# PARAMETERIZED PATCH ID ENDPOINTS
@router.get("/{patch_id}", response_model=PatchResponse)
def get_patch(patch_id: str):
    """Retrieve full details of a specific patch proposal including Git unified diff."""
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")
    return _serialize_patch(patch)


@router.get("/{patch_id}/validate")
def validate_patch_syntax(patch_id: str):
    """
    US 21: Pre-patch in-memory syntax inspection across Python, JS, Java, C, and C++.
    Returns precise 1-indexed error line, column, and diagnostic description.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    diagnostics = patch_service.validate_patch_syntax(patch_id)
    return {
        "patch_id": patch_id,
        "is_valid": diagnostics.get("is_valid", False),
        "error_message": diagnostics.get("error_message"),
        "line": diagnostics.get("line"),
        "column": diagnostics.get("column"),
        "token": diagnostics.get("token"),
        "language": diagnostics.get("language"),
    }


@router.post("/{patch_id}/approve", response_model=PatchResponse)
def approve_patch(patch_id: str, req: PatchApprovalRequest):
    """
    US 30: Explicitly approve a proposed patch, unblocking it for disk application.
    Records approver ID and timestamp.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    try:
        updated = patch_service.approve_patch(patch_id=patch_id, approved_by=req.approved_by)
        return _serialize_patch(updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post("/{patch_id}/reject", response_model=PatchResponse)
def reject_patch(patch_id: str, req: PatchRejectionRequest):
    """
    US 30: Explicitly reject a proposed patch with a recorded rationale.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    try:
        rejected = patch_service.reject_patch(patch_id=patch_id, reason=req.reason)
        return _serialize_patch(rejected)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post("/{patch_id}/apply", response_model=PatchApplyResponse)
def apply_patch(
    patch_id: str,
    require_approval: bool = Query(True, description="Enforce approval gate before application"),
):
    """
    US 21 & US 30: Safely apply a proposed patch to disk:
    1. Enforces approval gate (raises 403 if unapproved).
    2. Runs pre-flight virtual syntax validation.
    3. Establishes cryptographic SHA-256 backup.
    4. Writes modified code to disk.
    5. Verifies post-patch disk integrity.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    try:
        success = patch_service.apply_patch(patch_id=patch_id, require_approval=require_approval)
        backup_str = str(patch.backup_path) if patch.backup_path else None
        return PatchApplyResponse(
            patch_id=patch_id,
            success=success,
            status=patch.status.value,
            message=f"Patch applied successfully to '{patch.file_path.name}'.",
            backup_path=backup_str,
        )
    except ApprovalRequiredError as app_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(app_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Patch application failed: {exc}")


@router.post("/{patch_id}/rollback", response_model=PatchRollbackResponse)
def rollback_patch(patch_id: str):
    """
    US 30: Revert an applied patch, restoring the original file byte-for-byte from verified backup.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    try:
        success = patch_service.rollback_patch(patch_id=patch_id)
        return PatchRollbackResponse(
            patch_id=patch_id,
            success=success,
            status=patch.status.value,
            message=f"File '{patch.file_path.name}' restored byte-for-byte to pre-patch state.",
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Rollback failed: {exc}")
