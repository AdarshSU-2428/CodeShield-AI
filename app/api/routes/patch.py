import io
from pathlib import Path
from typing import Any, Dict, List, Optional
import zipfile
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import Response

from app.api.routes.audit import audit_service
from app.api.routes.project import project_service
from app.api.schemas import (
    BatchApplyRequest,
    BatchApplyResponse,
    BatchProposeProjectRequest,
    BatchProposeResponse,
    BatchRollbackRequest,
    BatchRollbackResponse,
    GenerateAIPatchRequest,
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


@router.post("/generate-ai", response_model=PatchResponse, status_code=status.HTTP_201_CREATED)
def generate_ai_remediation_patch(req: GenerateAIPatchRequest):
    """
    US 14: Dynamic AI Remediation Patch Generation using Groq LLM.
    Synthesizes drop-in polyglot replacement code for specific security findings.
    """
    from app.core.models.audit import AuditFinding

    # 1. Guard against single-file auto-patching of broad architectural smells
    cat = (req.category or "").lower()
    if cat in ("architecture", "architectural"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Architectural smells (High-Coupling Hubs, Monolithic Modules) involve cross-file structural "
                "redesign and cannot be patched via single-line automated code replacement. "
                "Please follow the architectural remediation steps provided in the Threat Intelligence Inspector."
            ),
        )

    # 2. Retrieve finding from stored reports if finding_id is provided
    target_finding = None
    if req.finding_id:
        for r in audit_service._reports.values():
            for f in r.findings:
                if f.finding_id == req.finding_id:
                    target_finding = f
                    break
            if target_finding:
                break

    if not target_finding:
        target_finding = AuditFinding(
            title=req.title or "Security Vulnerability",
            description=req.recommendation or "AI Remediated Finding",
            cwe_id=req.cwe_id,
            file_path=req.file_path,
            line_number=req.line_number or 1,
            recommendation=req.recommendation or "Fix vulnerability securely.",
        )

    try:
        patch = patch_service.generate_ai_patch(
            file_path=req.file_path,
            finding=target_finding,
        )
        return _serialize_patch(patch)
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"AI patch generation failed: {exc}")



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
@router.post("/batch/propose", response_model=BatchProposeResponse)
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
@router.post("/{patch_id}/validate")
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
def approve_patch(patch_id: str, req: Optional[PatchApprovalRequest] = None):
    """
    US 30: Explicitly approve a proposed patch, unblocking it for disk application.
    Records approver ID and timestamp.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    approver = req.approved_by if (req and req.approved_by) else "reviewer"
    try:
        updated = patch_service.approve_patch(patch_id=patch_id, approved_by=approver)
        return _serialize_patch(updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post("/{patch_id}/reject", response_model=PatchResponse)
def reject_patch(patch_id: str, req: Optional[PatchRejectionRequest] = None):
    """
    US 30: Explicitly reject a proposed patch with a recorded rationale.
    """
    patch = patch_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch '{patch_id}' not found.")

    reason = req.reason if (req and req.reason) else "Rejected by user"
    try:
        rejected = patch_service.reject_patch(patch_id=patch_id, reason=reason)
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


@router.get("/export-zip/{project_id}")
@router.get("/export-project-zip/{project_id}")
def export_patched_project_zip(project_id: str):
    """
    Non-destructive sandbox export: bundles the entire project into a ZIP file.
    Files with active proposed or applied patches have their patched contents included.
    All other files retain their original contents.
    The user's local disk repository remains 100% untouched.
    """
    project = project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found.")

    root_path = Path(project.root_path).resolve()
    if not root_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project root path does not exist on disk: {root_path}")

    # Map target normalized file paths to their latest patched code
    patched_code_by_path = {}
    for patch in patch_service._patches.values():
        if patch.modified_code:
            norm = Path(patch.file_path).resolve().as_posix()
            patched_code_by_path[norm] = patch.modified_code

    # Build in-memory zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in root_path.rglob("*"):
            if not p.is_file():
                continue
            # Skip ignored directories and files
            if project_service.scanner.should_ignore_file(p.name):
                continue
            rel_parts = p.relative_to(root_path).parts
            if any(project_service.scanner.should_ignore_dir(part) for part in rel_parts[:-1]):
                continue

            rel_path_str = p.relative_to(root_path).as_posix()
            norm = p.resolve().as_posix()

            if norm in patched_code_by_path:
                content = patched_code_by_path[norm].encode("utf-8")
            else:
                try:
                    content = p.read_bytes()
                except Exception:
                    continue

            zf.writestr(rel_path_str, content)

    zip_buffer.seek(0)
    safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project.name).strip("_")
    filename = f"{safe_name}_patched.zip"

    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

