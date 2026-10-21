from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

class FileSystem(ABC):
    """Abstract contract for filesystem operations across the application."""

    @abstractmethod
    def is_directory(self, path: Path) -> bool:
        """Check if the given path exists and is a valid directory."""
        pass

    @abstractmethod
    def exists(self, path: Path) -> bool:
        """Check if a file or directory exists."""
        pass

    @abstractmethod
    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """Read and return content of a text file safely."""
        pass

    @abstractmethod
    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write text content to a file, creating parent directories if needed."""
        pass

    @abstractmethod
    def compute_hash(self, path: Path) -> str:
        """Compute and return the SHA-256 hash of a file's content."""
        pass

    @abstractmethod
    def copy_file(self, source: Path, destination: Path) -> None:
        """Copy a file from source to destination, creating parent dirs if needed."""
        pass

    @abstractmethod
    def delete_file(self, path: Path) -> bool:
        """Delete a file if it exists. Returns True if deleted, False otherwise."""
        pass

    @abstractmethod
    def list_dir(self, directory: Path) -> List[Path]:
        """List all entries in a directory."""
        pass
