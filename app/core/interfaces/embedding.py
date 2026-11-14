from abc import ABC, abstractmethod
from typing import List


class EmbeddingService(ABC):
    """
    Abstract contract for computing dense vector embeddings and similarity scores
    entirely locally without network transmission.
    """

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generate a dense floating-point vector embedding for the input text."""
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate dense vector embeddings for a batch of input texts."""
        pass

    @abstractmethod
    def compute_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Calculate cosine similarity score between two vector representations."""
        pass
