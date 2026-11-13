from pathlib import Path
from unittest.mock import MagicMock
import pytest

from app.analysis.scanner import RepositoryScanner
from app.core.enums import FileStatus, Language
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.indexer import RepositoryIndexer
from app.services.project_service import ProjectService


class VirtualFS(LocalFileSystem):
    """In-memory filesystem for incremental change detection testing."""

    def __init__(self, files=None):
        self._files = files or {}

    def _normalize(self, path) -> str:
        return Path(path).as_posix().lower()

    def exists(self, path) -> bool:
        norm = self._normalize(path)
        for k in self._files:
            k_norm = self._normalize(k)
            if norm == k_norm or norm.endswith(k_norm) or k_norm.endswith(norm):
                return True
            # Check directory prefix
            if k_norm.startswith(norm.rstrip("/") + "/"):
                return True
        return False

    def is_directory(self, path) -> bool:
        norm = self._normalize(path)
        for k in self._files:
            k_norm = self._normalize(k)
            if k_norm.startswith(norm.rstrip("/") + "/"):
                return True
        return True

    def read_text(self, path, encoding="utf-8") -> str:
        norm = self._normalize(path)
        for k, v in self._files.items():
            if norm.endswith(k.lower()) or k.lower().endswith(norm):
                return v
        raise FileNotFoundError(str(path))

    def write_text(self, path, content: str, encoding="utf-8") -> None:
        norm = self._normalize(path)
        self._files[norm] = content

    def compute_hash(self, path) -> str:
        import hashlib
        content = self.read_text(path)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_us28_detect_changes_initial_scan_classifies_all_as_new():
    """Verify that scanning without a baseline snapshot categorizes all supported files as NEW."""
    files = {
        "repo/app.py": "import os\nprint('hello')\n",
        "repo/utils.js": "function helper() { return 42; }\n",
    }
    fs = VirtualFS(files)
    scanner = RepositoryScanner(filesystem=fs)
    project = Project(root_path="repo", project_id="proj_init")

    # Mock _walk to yield the virtual files
    scanner._walk = lambda root: [
        (Path("repo"), [], ["app.py", "utils.js"]),
    ]

    classified, manifest = scanner.detect_changes(project=project, baseline_manifest=None)

    assert len(classified) == 2
    assert all(f.status == FileStatus.NEW for f in classified)
    assert "app.py" in manifest
    assert "utils.js" in manifest
    assert manifest["app.py"]["status"] == "new"
    assert manifest["app.py"]["content_hash"] is not None


def test_us28_detect_changes_unchanged_files_skipped():
    """Verify that files with identical hashes are classified as UNCHANGED."""
    code_app = "def main(): return 1\n"
    code_util = "def util(): return 2\n"

    import hashlib
    hash_app = hashlib.sha256(code_app.encode("utf-8")).hexdigest()
    hash_util = hashlib.sha256(code_util.encode("utf-8")).hexdigest()

    baseline = {
        "app.py": {"relative_path": "app.py", "content_hash": hash_app, "size_bytes": len(code_app)},
        "util.py": {"relative_path": "util.py", "content_hash": hash_util, "size_bytes": len(code_util)},
    }

    files = {"repo/app.py": code_app, "repo/util.py": code_util}
    fs = VirtualFS(files)
    scanner = RepositoryScanner(filesystem=fs)
    project = Project(root_path="repo", project_id="proj_unchanged")

    scanner._walk = lambda root: [
        (Path("repo"), [], ["app.py", "util.py"]),
    ]

    classified, manifest = scanner.detect_changes(project=project, baseline_manifest=baseline)

    assert len(classified) == 2
    for f in classified:
        assert f.status == FileStatus.UNCHANGED
        rel_str = str(f.relative_path or Path(f.file_path).name).replace("\\", "/")
        assert manifest[rel_str]["status"] == "unchanged"


def test_us28_detect_changes_modified_files_detected():
    """Verify that modified files with changed content hashes are classified as MODIFIED."""
    old_code = "def authenticate(): return False\n"
    new_code = "def authenticate(): return True\n"

    import hashlib
    old_hash = hashlib.sha256(old_code.encode("utf-8")).hexdigest()

    baseline = {
        "auth.py": {"relative_path": "auth.py", "content_hash": old_hash, "size_bytes": len(old_code)},
    }

    files = {"repo/auth.py": new_code}
    fs = VirtualFS(files)
    scanner = RepositoryScanner(filesystem=fs)
    project = Project(root_path="repo", project_id="proj_modified")

    scanner._walk = lambda root: [
        (Path("repo"), [], ["auth.py"]),
    ]

    classified, manifest = scanner.detect_changes(project=project, baseline_manifest=baseline)

    assert len(classified) == 1
    assert classified[0].status == FileStatus.MODIFIED
    assert manifest["auth.py"]["status"] == "modified"
    assert manifest["auth.py"]["content_hash"] != old_hash


def test_us28_detect_changes_deleted_files_detected():
    """Verify that files existing in baseline manifest but missing from disk are marked as DELETED."""
    baseline = {
        "legacy.py": {"relative_path": "legacy.py", "content_hash": "deadbeef123", "size_bytes": 100, "language": "python"},
        "active.py": {"relative_path": "active.py", "content_hash": "aabbcc456", "size_bytes": 50, "language": "python"},
    }

    import hashlib
    active_code = "print('active')\n"
    active_hash = hashlib.sha256(active_code.encode("utf-8")).hexdigest()
    baseline["active.py"]["content_hash"] = active_hash

    # legacy.py is NOT present in filesystem
    files = {"repo/active.py": active_code}
    fs = VirtualFS(files)
    scanner = RepositoryScanner(filesystem=fs)
    project = Project(root_path="repo", project_id="proj_deleted")

    scanner._walk = lambda root: [
        (Path("repo"), [], ["active.py"]),
    ]

    classified, manifest = scanner.detect_changes(project=project, baseline_manifest=baseline)

    del_files = [f for f in classified if f.status == FileStatus.DELETED]
    assert len(del_files) == 1
    assert str(del_files[0].relative_path or Path(del_files[0].file_path).name).replace("\\", "/") == "legacy.py"


def test_us28_repository_indexer_incremental_skips_unchanged_and_purges_deleted():
    """
    Verify RepositoryIndexer.index_incremental() skips UNCHANGED files and
    purges vector chunks for DELETED files.
    """
    mock_vector_store = MagicMock()
    mock_scanner = MagicMock()

    sf_unchanged = SourceFile(file_path="repo/stay.py", relative_path="stay.py", status=FileStatus.UNCHANGED, language=Language.PYTHON)
    sf_new = SourceFile(file_path="repo/new.py", relative_path="new.py", status=FileStatus.NEW, language=Language.PYTHON, content="x=1")
    sf_deleted = SourceFile(file_path="repo/gone.py", relative_path="gone.py", status=FileStatus.DELETED, language=Language.PYTHON)

    mock_scanner.detect_changes.return_value = (
        [sf_unchanged, sf_new, sf_deleted],
        {"stay.py": {}, "new.py": {}},
    )

    indexer = RepositoryIndexer(
        vector_store=mock_vector_store,
        scanner=mock_scanner,
    )
    indexer.index_file = MagicMock(return_value=[MagicMock()])  # 1 chunk for new file

    project = Project(root_path="repo", project_id="proj_inc_1")
    summary = indexer.index_incremental(project=project, baseline_manifest={})

    assert summary["unchanged_files"] == 1
    assert summary["new_files"] == 1
    assert summary["deleted_files"] == 1
    assert summary["chunks_indexed"] == 1

    # Verified index_file was called ONLY for the new file, not the unchanged file!
    indexer.index_file.assert_called_once_with(source_file=sf_new, project_id="proj_inc_1")
    # Verified vector store removed chunks for deleted file
    mock_vector_store.delete_file_chunks.assert_called_once_with(file_path=str(sf_deleted.file_path), project_id="proj_inc_1")


def test_us28_project_service_registers_and_tracks_project_lifecycle():
    """Verify ProjectService validates directories and registers projects."""
    fs = VirtualFS({"workspace/src/app.py": "x = 10\n"})
    svc = ProjectService(filesystem=fs)

    proj = svc.register_project(root_path="workspace", name="MyWorkspace", project_id="proj_ws_1")
    assert proj.name == "MyWorkspace"
    assert proj.project_id == "proj_ws_1"
    assert svc.get_project("proj_ws_1") is proj

    # Non-existent path raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        svc.register_project(root_path="does_not_exist")


def test_us28_project_service_incremental_indexing_workflow_persists_manifest():
    """Verify ProjectService coordinates incremental indexing and saves snapshot manifest."""
    fs = VirtualFS({"repo/main.py": "def main(): pass\n"})
    mock_indexer = MagicMock()
    mock_indexer.index_incremental.return_value = {
        "project_id": "test_ws",
        "unchanged_files": 0,
        "new_files": 1,
        "modified_files": 0,
        "deleted_files": 0,
        "chunks_indexed": 2,
        "manifest": {"main.py": {"content_hash": "abc12345", "status": "new"}},
        "errors": [],
    }

    svc = ProjectService(filesystem=fs, indexer=mock_indexer)
    proj = svc.register_project(root_path="repo", project_id="test_ws")

    res = svc.run_incremental_index(project_id="test_ws")

    assert res["new_files"] == 1
    assert res["chunks_indexed"] == 2
    assert proj.is_indexed is True
    assert proj.last_indexed_at is not None

    # Check manifest retrieval
    saved_manifest = svc.get_manifest("test_ws")
    assert "main.py" in saved_manifest
    assert saved_manifest["main.py"]["content_hash"] == "abc12345"
