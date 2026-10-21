import fnmatch
from pathlib import Path
from typing import List, Optional, Set
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
    ):
        self.fs = filesystem if filesystem else LocalFileSystem()
        self.config = config if config else default_config

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
        ext_map = self.config.extension_to_language
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
                language = ext_map.get(ext, Language.UNKNOWN)
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
        
    def _walk(self, root: Path):
        """Helper to walk directory tree yielding (Path, List[str], List[str])."""
        import os
        for dirpath, dirnames, filenames in os.walk(root):
            yield Path(dirpath), dirnames, filenames