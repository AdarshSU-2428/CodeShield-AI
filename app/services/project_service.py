import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.analysis.scanner import RepositoryScanner
from app.core.interfaces.filesystem import FileSystem
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.indexer import RepositoryIndexer


class ProjectService:
    """
    Manages project workspaces, project registration, directory validation,
    and snapshot manifest persistence for incremental change tracking.
    """

    def __init__(
        self,
        filesystem: Optional[FileSystem] = None,
        scanner: Optional[RepositoryScanner] = None,
        indexer: Optional[RepositoryIndexer] = None,
        storage_dir: Optional[Union[str, Path]] = None,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.scanner: RepositoryScanner = (
            scanner if scanner is not None else RepositoryScanner(filesystem=self.filesystem)
        )
        self.indexer: Optional[RepositoryIndexer] = indexer
        self.storage_dir: Path = (
            Path(storage_dir).resolve() if storage_dir else Path("data/projects").resolve()
        )
        self._projects: Dict[str, Project] = {}
        self._manifests: Dict[str, Dict[str, Any]] = {}

    def register_project(
        self,
        root_path: Union[str, Path],
        name: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Project:
        """Register a new project directory workspace."""
        path_obj = Path(root_path)
        if not self.filesystem.exists(path_obj) and not self.filesystem.exists(path_obj.resolve()):
            raise FileNotFoundError(f"Project directory does not exist: {path_obj}")

        if not self.filesystem.is_directory(path_obj) and not self.filesystem.is_directory(path_obj.resolve()):
            raise ValueError(f"Project path is not a directory: {path_obj}")

        proj = Project(
            root_path=path_obj,
            name=name or path_obj.name,
            project_id=project_id,
        )

        # Initial scan to populate file metrics
        self.scanner.scan_project(proj)
        self._projects[proj.project_id] = proj
        return proj

    def get_project(self, project_id: str) -> Optional[Project]:
        """Retrieve a registered project by its ID."""
        return self._projects.get(project_id)

    def list_projects(self) -> List[Project]:
        """List all active registered projects."""
        return list(self._projects.values())

    def get_manifest(self, project_id: str) -> Dict[str, Any]:
        """Retrieve the latest snapshot manifest for a project."""
        if project_id in self._manifests:
            return self._manifests[project_id]

        # Try loading from disk storage
        manifest_path = self.storage_dir / f"{project_id}_manifest.json"
        if self.filesystem.exists(manifest_path):
            try:
                raw_json = self.filesystem.read_text(manifest_path)
                data = json.loads(raw_json)
                self._manifests[project_id] = data
                return data
            except Exception:
                return {}

        return {}

    def save_manifest(self, project_id: str, manifest: Dict[str, Any]) -> None:
        """Persist snapshot manifest in memory and to disk."""
        self._manifests[project_id] = manifest
        manifest_path = self.storage_dir / f"{project_id}_manifest.json"
        try:
            self.filesystem.write_text(manifest_path, json.dumps(manifest, indent=2))
        except Exception:
            pass

    def detect_project_changes(
        self,
        project_id: str,
    ) -> Dict[str, Any]:
        """
        Detect file changes in a project against its stored baseline snapshot manifest.
        Returns categorized files and updated manifest.
        """
        project = self.get_project(project_id)
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        baseline = self.get_manifest(project_id)
        classified_files, new_manifest = self.scanner.detect_changes(
            project=project,
            baseline_manifest=baseline,
        )

        return {
            "project_id": project_id,
            "classified_files": classified_files,
            "manifest": new_manifest,
        }

    def run_incremental_index(
        self,
        project_id: str,
    ) -> Dict[str, Any]:
        """
        Execute incremental indexing on the project, saving the resulting snapshot manifest.
        """
        project = self.get_project(project_id)
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        if self.indexer is None:
            self.indexer = RepositoryIndexer(
                filesystem=self.filesystem,
                scanner=self.scanner,
            )

        baseline = self.get_manifest(project_id)
        result = self.indexer.index_incremental(
            project=project,
            baseline_manifest=baseline,
        )

        # Update and save latest snapshot manifest
        updated_manifest = result.get("manifest", {})
        self.save_manifest(project_id, updated_manifest)

        project.is_indexed = True
        project.last_indexed_at = datetime.now(timezone.utc)

        return result