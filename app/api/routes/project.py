from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.analysis.language_detector import default_language_detector
from app.analysis.scanner import RepositoryScanner
from app.api.schemas import (
    FileContentResponse,
    FileTreeNode,
    ProjectRegisterRequest,
    ProjectResponse,
    ProjectTreeResponse,
)
from app.core.enums import Language
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.services.project_service import ProjectService

router = APIRouter(prefix="/api/projects", tags=["Projects"])

# Singleton ProjectService instance for stateful API runtime
_fs = LocalFileSystem()
_scanner = RepositoryScanner(filesystem=_fs)
project_service = ProjectService(filesystem=_fs, scanner=_scanner)


def _serialize_project(project: Project) -> ProjectResponse:
    """Helper to convert Project domain model into Pydantic ProjectResponse."""
    return ProjectResponse(
        project_id=project.project_id,
        name=project.name,
        root_path=str(project.root_path),
        total_files=project.total_files,
        supported_files=project.supported_files,
        is_indexed=project.is_indexed,
        created_at=project.created_at.isoformat(),
        last_indexed_at=project.last_indexed_at.isoformat() if project.last_indexed_at else None,
    )


def _build_tree_recursive(
    current_path: Path,
    root_path: Path,
    scanner: RepositoryScanner,
    manifest: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[FileTreeNode]:
    """
    Recursively build the hierarchical FileTreeNode structure for the sidebar tree view.
    Filters out ignored directories (.git, node_modules, venv, etc.) and tags languages and statuses.
    """
    rel_path_str = current_path.relative_to(root_path).as_posix() if current_path != root_path else ""

    if current_path.is_dir():
        dir_name = current_path.name
        if current_path != root_path and scanner.should_ignore_dir(dir_name):
            return None

        children_nodes: List[FileTreeNode] = []
        try:
            entries = sorted(list(current_path.iterdir()), key=lambda e: (not e.is_dir(), e.name.lower()))
        except (PermissionError, OSError):
            entries = []

        total_findings = 0
        for entry in entries:
            child_node = _build_tree_recursive(entry, root_path, scanner, manifest)
            if child_node is not None:
                children_nodes.append(child_node)
                total_findings += child_node.findings_count

        return FileTreeNode(
            name=current_path.name if current_path != root_path else root_path.name,
            path=rel_path_str,
            type="directory",
            children=children_nodes,
            findings_count=total_findings,
        )

    else:
        # File node
        file_name = current_path.name
        if scanner.should_ignore_file(file_name):
            return None

        lang = default_language_detector.detect_language(file_path=current_path)
        lang_str = lang.value if lang != Language.UNKNOWN else None

        try:
            size_bytes = current_path.stat().st_size
        except (OSError, FileNotFoundError):
            size_bytes = 0

        # Look up incremental status from manifest if available
        status_val = "unchanged"
        if manifest and rel_path_str in manifest:
            status_val = manifest[rel_path_str].get("status", "unchanged")

        return FileTreeNode(
            name=file_name,
            path=rel_path_str,
            type="file",
            language=lang_str,
            size_bytes=size_bytes,
            status=status_val,
            findings_count=0,
            children=None,
        )


@router.post("/register", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def register_project(req: ProjectRegisterRequest):
    """
    Register a new project directory workspace.
    Validates folder existence, executes initial discovery scan, and returns project metadata.
    """
    try:
        project = project_service.register_project(
            root_path=req.root_path,
            name=req.name,
            project_id=req.project_id,
        )
        return _serialize_project(project)
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to register project: {exc}")


@router.get("", response_model=List[ProjectResponse])
def list_projects():
    """List all registered project workspaces."""
    return [_serialize_project(p) for p in project_service.list_projects()]


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str):
    """Retrieve details for a specific registered project."""
    project = project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found.")
    return _serialize_project(project)


@router.get("/{project_id}/tree", response_model=ProjectTreeResponse)
def get_project_tree(project_id: str):
    """
    Generate the hierarchical recursive file tree for the interactive UI sidebar explorer.
    Includes language tagging, file sizes, and directory collapse structures.
    """
    project = project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found.")

    manifest = project_service.get_manifest(project_id)
    tree_node = _build_tree_recursive(
        current_path=project.root_path,
        root_path=project.root_path,
        scanner=project_service.scanner,
        manifest=manifest,
    )

    if tree_node is None:
        tree_node = FileTreeNode(
            name=project.name,
            path="",
            type="directory",
            children=[],
        )

    return ProjectTreeResponse(
        project_id=project.project_id,
        root_path=str(project.root_path),
        tree=tree_node,
    )


@router.get("/{project_id}/file-content", response_model=FileContentResponse)
def get_file_content(
    project_id: str,
    path: str = Query(..., description="Relative or absolute path of file to view"),
):
    """
    Read and return safe text content of a project file for the UI code viewer.
    Prevents path traversal outside of the registered project workspace.
    """
    project = project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found.")

    target_path = Path(path)
    if not target_path.is_absolute():
        resolved_path = (project.root_path / target_path).resolve()
    else:
        resolved_path = target_path.resolve()

    # Path traversal protection
    try:
        resolved_path.relative_to(project.root_path.resolve())
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: path is outside project workspace.")

    if not _fs.exists(resolved_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File not found: '{path}'")

    if _fs.is_directory(resolved_path):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Path is a directory, not a file: '{path}'")

    try:
        content = _fs.read_text(resolved_path)
        lang = default_language_detector.detect_language(file_path=resolved_path)
        rel_str = resolved_path.relative_to(project.root_path).as_posix()

        return FileContentResponse(
            file_path=str(resolved_path),
            relative_path=rel_str,
            language=lang.value,
            content=content,
            size_bytes=len(content.encode("utf-8")),
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error reading file: {exc}")


@router.get("/{project_id}/changes")
def get_project_changes(project_id: str):
    """
    US 28: Inspect incremental file modifications against stored baseline snapshot manifest.
    Returns categorized NEW, MODIFIED, UNCHANGED, and DELETED files.
    """
    try:
        result = project_service.detect_project_changes(project_id)
        classified = result.get("classified_files", [])
        return {
            "project_id": project_id,
            "total_files": len(classified),
            "files": [
                {
                    "file_path": str(sf.file_path),
                    "relative_path": str(sf.relative_path or Path(sf.file_path).name).replace("\\", "/"),
                    "status": sf.status.value,
                    "language": sf.language.value,
                    "size_bytes": sf.size_bytes,
                }
                for sf in classified
            ],
        }
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error detecting changes: {exc}")
