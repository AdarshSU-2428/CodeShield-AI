from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# System & Engine Health Schemas
class SystemHealthResponse(BaseModel):
    status: str = Field("ok", description="Overall system health status")
    app_name: str = Field("CodeShield AI", description="Application name")
    version: str = Field("0.1.0", description="Application version")
    tree_sitter_available: bool = Field(True, description="Polyglot AST parsers availability")
    chromadb_available: bool = Field(True, description="Local on-device ChromaDB vector store availability")
    llm_available: bool = Field(False, description="Cloud Groq LLM assistance availability")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# Project & Sidebar File Tree Schemas
class ProjectRegisterRequest(BaseModel):
    root_path: str = Field(..., description="Absolute path to project directory on developer's machine")
    name: Optional[str] = Field(None, description="Optional custom project display name")
    project_id: Optional[str] = Field(None, description="Optional explicit project UUID")

    model_config = {
        "json_schema_extra": {
            "example": {
                "root_path": "C:/Users/ADARSH S SAHOO/Desktop/Engineering folder/3rd year/College Projects/CodeShield AI",
                "name": "CodeShield AI",
            }
        }
    }


class ProjectResponse(BaseModel):
    project_id: str
    name: str
    root_path: str
    total_files: int
    supported_files: int
    is_indexed: bool
    created_at: str
    last_indexed_at: Optional[str] = None


class FileTreeNode(BaseModel):
    """
    Hierarchical recursive node for rendering the interactive sidebar file tree in the UI.
    Supports directory folding, file selection, and rolled-up finding badges.
    """
    name: str = Field(..., description="File or directory name")
    path: str = Field(..., description="Normalized relative path from project root")
    type: str = Field(..., description="'file' or 'directory'")
    language: Optional[str] = Field(None, description="Detected programming language")
    size_bytes: int = Field(0, description="File size in bytes")
    status: str = Field("unchanged", description="File status: 'new', 'modified', 'unchanged', 'deleted'")
    findings_count: int = Field(0, description="Total security/quality findings in this file or subtree")
    highest_severity: Optional[str] = Field(None, description="Highest severity: critical, high, medium, low, info")
    children: Optional[List["FileTreeNode"]] = Field(None, description="Child nodes for directories")


FileTreeNode.model_rebuild()


class ProjectTreeResponse(BaseModel):
    project_id: str
    root_path: str
    tree: FileTreeNode


class FileContentResponse(BaseModel):
    file_path: str
    relative_path: str
    language: str
    content: str
    size_bytes: int



# Audit & Finding Schemas
class AuditStartRequest(BaseModel):
    project_id: str = Field(..., description="Project ID to audit")
    enable_ai: bool = Field(False, description="Enable Groq cloud semantic analysis")
    enable_smells: bool = Field(True, description="Detect architectural smells and cyclic dependencies")
    incremental: bool = Field(False, description="Only scan modified/new files (incremental)")
    include_tests: bool = Field(False, description="Include test suites and fixtures in audit (default False for production scans)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "project_id": "paste-project-id-here",
                "enable_ai": False,
                "enable_smells": True,
                "incremental": False,
                "include_tests": False,
            }
        }
    }


class AuditJobResponse(BaseModel):
    job_id: str
    project_id: str
    status: str = Field(..., description="'pending', 'in_progress', 'completed', 'failed', 'cancelled'")
    progress_percentage: float = Field(0.0, description="Progress from 0.0 to 100.0")
    current_stage: str = Field("", description="Current execution stage description")
    files_scanned: int = 0
    total_files: int = 0
    findings_count: int = 0
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)


class AuditFindingResponse(BaseModel):
    finding_id: str
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    file_path: str
    relative_file_path: Optional[str] = None
    start_line: int
    end_line: int
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    risk_score: float = 0.0
    recommendation: Optional[str] = None
    remediation_code: Optional[str] = None
    remediation_steps: List[str] = Field(default_factory=list)
    risk_explanation: Optional[str] = None
    exploit_scenario: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    source: str = "static_sast"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuditResultsResponse(BaseModel):
    job_id: str
    project_id: str
    health_score: float = Field(..., description="Project health score out of 100.0")
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    findings: List[AuditFindingResponse]
    summary_markdown: Optional[str] = None


# Patch & Diff Schemas (Individual & Batch Remediation)
class PatchProposeRequest(BaseModel):
    file_path: str = Field(..., description="Target file path to patch")
    modified_code: str = Field(..., description="Proposed replacement code content")
    finding_id: Optional[str] = Field(None, description="Optional finding ID being remediated")
    description: Optional[str] = Field(None, description="Patch description")

    model_config = {
        "json_schema_extra": {
            "example": {
                "file_path": "src/app.py",
                "modified_code": "# Remediated secure code\nprint('Safe execution')\n",
                "description": "Fix security vulnerability",
            }
        }
    }


class PatchHunkResponse(BaseModel):
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    header: str
    lines: List[Dict[str, Any]]


class PatchResponse(BaseModel):
    patch_id: str
    file_path: str
    finding_id: Optional[str] = None
    status: str = Field(..., description="'proposed', 'approved', 'rejected', 'applied', 'rolled_back'")
    description: str
    git_diff: str
    diff_stat: str
    additions_count: int
    deletions_count: int
    total_changes: int
    hunks: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    applied_at: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejection_reason: Optional[str] = None


class PatchApprovalRequest(BaseModel):
    approved_by: Optional[str] = Field("reviewer", description="Name/ID of the approver")

    model_config = {
        "json_schema_extra": {
            "example": {
                "approved_by": "SecurityLead"
            }
        }
    }


class PatchRejectionRequest(BaseModel):
    reason: Optional[str] = Field("Rejected by reviewer", description="Reason for rejecting the patch")

    model_config = {
        "json_schema_extra": {
            "example": {
                "reason": "Does not conform to coding guidelines or syntax checks failed."
            }
        }
    }


class PatchApplyResponse(BaseModel):
    patch_id: str
    success: bool
    status: str
    message: str
    backup_path: Optional[str] = None


class PatchRollbackResponse(BaseModel):
    patch_id: str
    success: bool
    status: str
    message: str


# Bulk Project Batch Remediation Schemas
class BatchProposeProjectRequest(BaseModel):
    project_id: str = Field(..., description="Project ID to generate patches for all actionable findings")
    finding_ids: Optional[List[str]] = Field(None, description="Optional subset of finding IDs to remediate")

    model_config = {
        "json_schema_extra": {
            "example": {
                "project_id": "paste-project-id-here",
                "finding_ids": None,
            }
        }
    }


class BatchProposeResponse(BaseModel):
    project_id: str
    total_patches_generated: int
    patches: List[PatchResponse]


class BatchApplyRequest(BaseModel):
    patch_ids: List[str] = Field(..., description="List of patch IDs to approve and apply in bulk")
    approved_by: Optional[str] = Field("bulk_admin", description="Name/ID of the approver")

    model_config = {
        "json_schema_extra": {
            "example": {
                "patch_ids": ["patch-id-1", "patch-id-2"],
                "approved_by": "BatchSecurityAdmin",
            }
        }
    }


class BatchApplyResponse(BaseModel):
    success_count: int
    failed_count: int
    applied_patches: List[str]
    failed_patches: List[Dict[str, str]]
    message: str


class BatchRollbackRequest(BaseModel):
    patch_ids: List[str] = Field(..., description="List of patch IDs to roll back in bulk")

    model_config = {
        "json_schema_extra": {
            "example": {
                "patch_ids": ["patch-id-1", "patch-id-2"],
            }
        }
    }


class BatchRollbackResponse(BaseModel):
    success_count: int
    failed_count: int
    rolled_back_patches: List[str]
    failed_patches: List[Dict[str, str]]
    message: str
