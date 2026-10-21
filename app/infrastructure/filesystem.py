import hashlib
import os
from pathlib import Path
import shutil
from typing import List
from app.core.interfaces.filesystem import FileSystem

class LocalFileSystem(FileSystem):
    """Concrete filesystem adapter for local disk operations."""

    def is_directory(self, path: Path) -> bool:
        """Check if path exists and is a valid directory."""
        return path.exists() and path.is_dir()

    def exists(self, path: Path) -> bool:
        """Check if path exists."""
        return path.exists()
    
    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """
        Read and return content of a text file safely.
        Falls back to latin-1 if utf-8 fails to prevent crashing on legacy files.
        """
        try:
            return path.read_text(encoding=encoding, errors="replace")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1", errors="replace")
    
    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write content to file, creating parent directories if they don't exist."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding, newline="")
    
    def compute_hash(self, path: Path) -> str:
        """
        Compute SHA-256 hash of a file by streaming 64KB blocks.
        Memory efficient for files of any size.
        """
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def copy_file(self, source: Path, destination: Path) -> None:
        """Copy a file from source to destination, creating parent dirs if needed."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    
    def delete_file(self, path: Path) -> bool:
        """Delete a file if it exists."""
        if path.exists() and path.is_file():
            path.unlink()
            return True
        return False
    
    def list_dir(self, directory: Path) -> List[Path]:
        """List all entries in a directory."""
        if not self.is_directory(directory):
            return []
        return list(directory.iterdir())
