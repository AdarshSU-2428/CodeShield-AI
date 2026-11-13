import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from app.analysis.language_detector import LanguageDetector, default_language_detector
from app.core.enums import FileStatus, Language
from app.core.interfaces.filesystem import FileSystem
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.config import AppConfig, config as default_config
from app.infrastructure.filesystem import LocalFileSystem


class RepositoryScanner:
    """Discovers, filters, and classifies source files within a project directory."""

    def __init__(
        self,
        filesystem: Optional[FileSystem] = None,
        config: Optional[AppConfig] = None,
        language_detector: Optional[LanguageDetector] = None,
    ):
        self.fs = filesystem if filesystem else LocalFileSystem()
        self.config = config if config else default_config
        self.language_detector = language_detector if language_detector else default_language_detector

    def should_ignore_dir(self, dir_name: str) -> bool:
        """Check if a directory name is in the ignore list."""
        return dir_name in self.config.ignore_directories or dir_name.startswith(".")
    
    def should_ignore_file(self, file_name: str) -> bool:
        """Check if a file matches any ignore glob patterns (e.g., *.min.js)."""
        for pattern in self.config.ignore_patterns:
            if fnmatch.fnmatch(file_name, pattern):
                return True
        return False
    
    def scan_project(self, project: Project) -> List[SourceFile]:
        """
        Scan a project's root directory and return all discovered SourceFile models.
        Also updates project.total_files and project.supported_files summary counts.
        """
        root_path = project.root_path
        if not self.fs.is_directory(root_path):
            return []

        discovered_files: List[SourceFile] = []
        total_count = 0
        supported_count = 0
        max_size = self.config.max_file_size_bytes
        
        # Traverse directory recursively using os.walk semantics with pathlib
        for current_dir, dirs, files in self._walk(root_path):
            # Prune ignored directories in-place so walk does not descend into them
            dirs[:] = [d for d in dirs if not self.should_ignore_dir(d)]
            for file_name in files:
                total_count += 1
                if self.should_ignore_file(file_name):
                    continue

                abs_path = current_dir / file_name
                try:
                    rel_path = abs_path.relative_to(root_path)
                except ValueError:
                    rel_path = Path(file_name)

                ext = abs_path.suffix.lower()
                language = self.language_detector.detect_language(file_path=abs_path)

                # Disambiguate .h or extensionless files using content inspection
                if language in (Language.UNKNOWN, Language.C) and (not ext or ext == ".h"):
                    try:
                        snippet = self.fs.read_text(abs_path)[:1024]
                        language = self.language_detector.detect_language(file_path=abs_path, content=snippet)
                    except Exception:
                        pass

                # Check file size
                try:
                    size_bytes = abs_path.stat().st_size
                except (OSError, FileNotFoundError):
                    size_bytes = 0

                # Determine file status & support
                if language == Language.UNKNOWN or size_bytes > max_size:
                    status = FileStatus.UNSUPPORTED
                else:
                    status = FileStatus.NEW
                    supported_count += 1

                # Compute content hash for supported files
                content_hash = None
                if status != FileStatus.UNSUPPORTED:
                    try:
                        content_hash = self.fs.compute_hash(abs_path)
                    except Exception:
                        status = FileStatus.ERROR
                
                source_file = SourceFile(
                    file_path=abs_path,
                    relative_path=rel_path,
                    language=language,
                    status=status,
                    size_bytes=size_bytes,
                    content_hash=content_hash,
                )
                discovered_files.append(source_file)

        # Update project summary metrics
        project.total_files = total_count
        project.supported_files = supported_count
        return discovered_files

    def detect_changes(
        self,
        project: Project,
        baseline_manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Tuple[List[SourceFile], Dict[str, Dict[str, Any]]]:
        """
        Incremental change detection against a baseline snapshot manifest.
        Compares content hashes, file sizes, and paths to categorize files into:
        - NEW: Discovered file not present in baseline manifest.
        - MODIFIED: Existing file whose content hash or size has changed.
        - UNCHANGED: Existing file whose content hash exactly matches baseline.
        - DELETED: File present in baseline manifest but missing from current filesystem.

        Returns:
            Tuple[List[SourceFile], Dict[str, Dict[str, Any]]]:
                (classified_files_list, updated_snapshot_manifest)
        """
        discovered = self.scan_project(project)
        baseline = baseline_manifest or {}

        # Normalize baseline keys to forward-slash relative paths
        norm_baseline: Dict[str, Dict[str, Any]] = {}
        for raw_k, v in baseline.items():
            norm_k = Path(raw_k).as_posix().lower()
            norm_baseline[norm_k] = v

        current_relative_keys: Set[str] = set()
        updated_manifest: Dict[str, Dict[str, Any]] = {}
        classified_files: List[SourceFile] = []

        for sf in discovered:
            rel_str = str(sf.relative_path or Path(sf.file_path).name).replace("\\", "/")
            rel_key = rel_str.lower()
            current_relative_keys.add(rel_key)

            if sf.status == FileStatus.UNSUPPORTED:
                classified_files.append(sf)
                continue

            current_hash = sf.content_hash
            base_entry = norm_baseline.get(rel_key)

            if base_entry is None:
                sf.status = FileStatus.NEW
            else:
                base_hash = base_entry.get("content_hash") or base_entry.get("hash")
                if current_hash and base_hash and current_hash == base_hash:
                    sf.status = FileStatus.UNCHANGED
                else:
                    sf.status = FileStatus.MODIFIED

            # Populate snapshot manifest
            updated_manifest[rel_str] = {
                "file_path": str(sf.file_path),
                "relative_path": rel_str,
                "content_hash": current_hash,
                "size_bytes": sf.size_bytes,
                "language": sf.language.value if hasattr(sf.language, "value") else str(sf.language),
                "status": sf.status.value,
            }
            classified_files.append(sf)

        # Detect DELETED files from baseline that no longer exist on disk
        for base_key, base_entry in norm_baseline.items():
            if base_key not in current_relative_keys:
                del_rel = base_entry.get("relative_path") or base_key
                del_path = base_entry.get("file_path") or (project.root_path / del_rel)
                raw_lang = base_entry.get("language", "unknown")
                lang = Language.UNKNOWN
                for l in Language:
                    if l.value == raw_lang:
                        lang = l
                        break

                deleted_sf = SourceFile(
                    file_path=Path(del_path),
                    relative_path=Path(del_rel),
                    language=lang,
                    status=FileStatus.DELETED,
                    size_bytes=0,
                    content_hash=base_entry.get("content_hash"),
                )
                classified_files.append(deleted_sf)

        return classified_files, updated_manifest
        
    def _walk(self, root: Path):
        """Helper to walk directory tree yielding (Path, List[str], List[str])."""
        import os
        for dirpath, dirnames, filenames in os.walk(root):
            yield Path(dirpath), dirnames, filenames