from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from app.core.interfaces.vector_store import VectorStore
from app.core.models.code import CodeChunk
from app.infrastructure.config import AppConfig, config as default_config

class ChromaVectorStore(VectorStore):
    """Local, embedded vector database adapter using ChromaDB."""
    def __init__(
        self,
        persist_directory: Optional[Path] = None,
        config: Optional[AppConfig] = None,
    ):
        self.config = config if config else default_config
        
        # Determine local persistence folder
        if persist_directory:
            self.persist_dir = Path(persist_directory).resolve()
            
        else:
            rag_cfg = getattr(self.config, "_raw_config", {}).get("rag", {})
            rel_path = rag_cfg.get("vector_store_path", "data/vector_store")
            self.persist_dir = Path(rel_path).resolve()
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        # Initialize local persistent client (no server needed)
        self._client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(anonymized_telemetry=False),
        )
        # Local default embedding function (lightweight ONNX model)
        self._embedding_fn = embedding_functions.DefaultEmbeddingFunction()

    def _get_collection_name(self, project_id: str) -> str:
        """
        Normalize project_id into a valid Chroma collection name
        (must be 3-63 chars, alphanumeric, start/end with alphanumeric).
        """
        clean = re.sub(r"[^a-zA-Z0-9_-]", "_", str(project_id))
        name = f"proj_{clean}".strip("._-")

        if len(name) < 3:
            name = "proj_default"

        if len(name) > 60:
            name = name[:60].rstrip("._-")
        
        return name

    def _get_or_create_collection(self, project_id: str):
        """Retrieve or create Chroma collection for a given project."""
        col_name = self._get_collection_name(project_id)

        return self._client.get_or_create_collection(
            name=col_name,
            embedding_function=self._embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )

    def add_chunks(self, chunks: List[CodeChunk], project_id: str) -> int:
        """Add or update CodeChunks in the project's Chroma collection."""
        if not chunks:
            return 0
        
        collection = self._get_or_create_collection(project_id)
        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        
        for idx, chunk in enumerate(chunks):
            # Create a deterministic chunk ID
            chunk_id = (
                f"{chunk.file_path}_{chunk.component_name}_{chunk.start_line}_{chunk.end_line}_{idx}"
            )
            
            clean_id = re.sub(r"[^a-zA-Z0-9._-]", "_", chunk_id)
            ids.append(clean_id)
            documents.append(chunk.content)
            
            # Metadata must contain only primitive types for Chroma
            resolved_file_path = str(Path(chunk.file_path).resolve()) if chunk.file_path else ""
            meta = {
                "file_path": resolved_file_path,
                "component_name": chunk.component_name or "unknown",
                "start_line": int(chunk.start_line),
                "end_line": int(chunk.end_line),
            }
            
            if chunk.metadata:
                for k, v in chunk.metadata.items():
                    if isinstance(v, (str, int, float, bool)):
                        meta[k] = v
            metadatas.append(meta)
        
        # Upsert into Chroma (adds new, updates existing)
        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )
        
        return len(ids)

    def query_similar(
        self,
        query_text: str,
        project_id: str,
        top_k: int = 5,
        filters: Dict[str, Any] = None,
    ) -> List[Dict[str, Any]]:
        """Query Chroma collection for semantically similar chunks."""
        if top_k <= 0 or not query_text or not query_text.strip():
            return []

        collection = self._get_or_create_collection(project_id)
        count = collection.count()

        if count == 0:
            return []
            
        effective_top_k = min(top_k, count)
        
        results = collection.query(
            query_texts=[query_text],
            n_results=effective_top_k,
            where=filters if filters else None,
        )
        
        formatted_results: List[Dict[str, Any]] = []
        
        if results and "documents" in results and results["documents"]:
            docs = results["documents"][0]
            metas = results["metadatas"][0] if "metadatas" in results else [{}] * len(docs)
            distances = results["distances"][0] if "distances" in results else [0.0] * len(docs)
            ids = results["ids"][0] if "ids" in results else [""] * len(docs)
            
            for doc, meta, dist, cid in zip(docs, metas, distances, ids):
                formatted_results.append({
                    "id": cid,
                    "content": doc,
                    "metadata": meta,
                    "distance": dist,
                    "similarity": round(1.0 - dist, 4) if dist is not None else 1.0,
                })
        
        return formatted_results

    def delete_file_chunks(self, file_path: str, project_id: str) -> int:
        """Delete all chunks belonging to a file from the project collection."""
        collection = self._get_or_create_collection(project_id)
        resolved_file_path = str(Path(file_path).resolve())
        try:
            collection.delete(where={"file_path": resolved_file_path})
            return 1

        except Exception:
            return 0

    def reset_project_index(self, project_id: str) -> None:
        """Delete the entire Chroma collection for a project."""
        col_name = self._get_collection_name(project_id)
        try:
            self._client.delete_collection(name=col_name)
        
        except Exception:
            pass

    def count(self, project_id: str) -> int:
        """Return vector count in the project's collection."""
        collection = self._get_or_create_collection(project_id)
        
        return collection.count()
