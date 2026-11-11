import hashlib
import os
from pathlib import Path
import shutil
from typing import List, Union
from app.core.interfaces.filesystem import FileSystem

class LocalFileSystem(FileSystem):
    """Concrete filesystem adapter for local disk operations."""

    def is_directory(self, path: Union[str, Path]) -> bool:
        """Check if path exists and is a valid directory."""
        p = Path(path)
        return p.exists() and p.is_dir()

    def exists(self, path: Union[str, Path]) -> bool:
        """Check if path exists."""
        return Path(path).exists()
    
    def read_text(self, path: Union[str, Path], encoding: str = "utf-8") -> str:
        """
        Read and return content of a text file safely.
        Falls back to latin-1 if utf-8 fails to prevent crashing on legacy files.
        """
        p = Path(path)
        try:
            return p.read_text(encoding=encoding, errors="replace")
        except UnicodeDecodeError:
            return p.read_text(encoding="latin-1", errors="replace")
    
    def write_text(self, path: Union[str, Path], content: str, encoding: str = "utf-8") -> None:
        """Write content to file, creating parent directories if they don't exist."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding=encoding, newline="")
    
    def compute_hash(self, path: Union[str, Path]) -> str:
        """
        Compute SHA-256 hash of a file by streaming 64KB blocks.
        Memory efficient for files of any size.
        """
        hasher = hashlib.sha256()
        with open(Path(path), "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def copy_file(self, source: Union[str, Path], destination: Union[str, Path]) -> None:
        """Copy a file from source to destination, creating parent dirs if needed."""
        dst = Path(destination)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(source), dst)
    
    def delete_file(self, path: Union[str, Path]) -> bool:
        """Delete a file if it exists."""
        p = Path(path)
        if p.exists() and p.is_file():
            p.unlink()
            return True
        return False
    
    def list_dir(self, directory: Union[str, Path]) -> List[Path]:
        """List all entries in a directory."""
        p = Path(directory)
        if not self.is_directory(p):
            return []
        return list(directory.iterdir())
