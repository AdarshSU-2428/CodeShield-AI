import hashlib
import re
from typing import Any, Dict, List, Optional, Union

from sklearn.metrics.pairwise import cosine_similarity

from app.core.interfaces.embedding import EmbeddingService


class LocalEmbeddingService(EmbeddingService):
    """
    Generates text and code embeddings completely locally on the developer's machine.
    Zero external network transmission; supports local Chroma embedding functions and deterministic hashing fallbacks.
    """

    def __init__(
        self,
        embedding_function: Optional[Any] = None,
        dimension: int = 384,
    ):
        self.dimension: int = dimension
        self._embedding_fn = embedding_function
        self._cache: Dict[str, List[float]] = {}

    def _hash_fallback_vector(self, text: str) -> List[float]:
        """
        Deterministic, normalized on-device vector representation for fallback or offline test environments.
        Computes stable pseudo-random floats based on cryptographic SHA-256 tokens.
        """
        words = re.findall(r"[a-zA-Z0-9_]+", text.lower())
        vec = [0.0] * self.dimension

        if not words:
            return vec

        for word in words:
            digest = hashlib.sha256(word.encode("utf-8")).hexdigest()
            idx = int(digest[:8], 16) % self.dimension
            val = (int(digest[8:16], 16) / 0xFFFFFFFF) * 2.0 - 1.0
            vec[idx] += val

        # L2 normalization to unit circle
        magnitude = sum(x * x for x in vec) ** 0.5
        if magnitude > 1e-9:
            vec = [round(x / magnitude, 6) for x in vec]

        return vec

    def embed_text(self, text: str) -> List[float]:
        """Generate embedding vector for a single string locally."""
        if not text or not text.strip():
            return [0.0] * self.dimension

        cache_key = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self._embedding_fn is not None:
            try:
                res = self._embedding_fn([text])
                if res and isinstance(res, list) and len(res) > 0:
                    vec = [float(x) for x in res[0]]
                    self._cache[cache_key] = vec
                    return vec
            except Exception:
                pass

        vec = self._hash_fallback_vector(text)
        self._cache[cache_key] = vec
        return vec

    def embed_documents(self, documents: List[str]) -> List[List[float]]:
        """Batch embed multiple code snippets or documents locally."""
        if not documents:
            return []
        return [self.embed_text(doc) for doc in documents]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Alias conforming to EmbeddingService interface for batch embeddings."""
        return self.embed_documents(texts)

    def compute_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Compute cosine similarity between two local vectors using sklearn."""
        if not vec_a or not vec_b or len(vec_a) != len(vec_b):
            return 0.0
        # If either vector is all zeros, similarity is zero
        if all(x == 0.0 for x in vec_a) or all(x == 0.0 for x in vec_b):
            return 0.0

        sim_matrix = cosine_similarity([vec_a], [vec_b])
        val = float(sim_matrix[0][0])
        return round(0.0 if (val != val) else max(-1.0, min(1.0, val)), 4)