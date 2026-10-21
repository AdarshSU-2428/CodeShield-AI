from abc import ABC, abstractmethod
from typing import Any, Dict, List

from app.core.models.code import CodeChunk


class VectorStore(ABC):
    """Abstract contract for local vector database operations."""

    @abstractmethod
    def add_chunks(self, chunks: List[CodeChunk], project_id: str) -> int:
        """
        Store a batch of CodeChunks with embeddings and metadata.
        Returns the number of chunks successfully stored.
        """
        pass

    @abstractmethod
    def query_similar(
        self,
        query_text: str,
        project_id: str,
        top_k: int = 5,
        filters: Dict[str, Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Perform vector similarity search for a query string within a project.
        Returns list of matching records with content, metadata, and distance.
        """
        pass

    @abstractmethod
    def delete_file_chunks(self, file_path: str, project_id: str) -> int:
        """
        Remove all chunks associated with a specific file path from the vector store.
        Used for incremental updates when a file is modified or deleted.
        """
        pass

    @abstractmethod
    def reset_project_index(self, project_id: str) -> None:
        """Purge and reset the vector index for a specific project."""
        pass

    @abstractmethod
    def count(self, project_id: str) -> int:
        """Return total number of vectors stored for a project."""
        pass
