from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from app.analysis.cross_file import CrossFileContextResolver
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.vector_store import VectorStore
from app.core.models.code import SourceFile
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.chroma_store import ChromaVectorStore


class LocalContextRetriever:
    """
    Retrieves local repository context without transmitting the entire codebase.
    Combines AST-driven cross-file import resolution with on-device ChromaDB vector similarity search.
    Guarantees that retrieved code preserves complete line and block boundaries without mid-statement truncation.
    """

    def __init__(
        self,
        vector_store: Optional[VectorStore] = None,
        cross_file_resolver: Optional[CrossFileContextResolver] = None,
        filesystem: Optional[FileSystem] = None,
        max_context_snippets: int = 5,
        max_chars_per_snippet: int = 10000,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.vector_store: VectorStore = (
            vector_store if vector_store is not None else ChromaVectorStore()
        )
        self.cross_file_resolver: CrossFileContextResolver = (
            cross_file_resolver if cross_file_resolver is not None
            else CrossFileContextResolver(filesystem=self.filesystem, vector_store=self.vector_store)
        )
        self.max_context_snippets: int = max(1, max_context_snippets)
        self.max_chars_per_snippet: int = max(1000, max_chars_per_snippet)

    def _truncate_at_line_boundary(self, content: Optional[str], max_chars: int) -> str:
        """
        Truncate large files strictly at complete line boundaries, ensuring functions
        and expressions are never cut in the middle of a line or token.
        Gracefully handles None, empty strings, and zero/negative character budgets.
        """
        if content is None or not content:
            return ""

        effective_limit = max(0, max_chars)
        if len(content) <= effective_limit:
            return content

        lines = content.splitlines(keepends=True)
        accumulated: List[str] = []
        current_len = 0

        for line in lines:
            if current_len + len(line) > effective_limit:
                break
            accumulated.append(line)
            current_len += len(line)

        if not accumulated:
            first_line = lines[0].rstrip() if lines else ""
            return first_line + "\n# [TRUNCATED REMAINING LINES CLEANLY]"

        return "".join(accumulated).rstrip() + "\n\n# [TRUNCATED REMAINING LINES CLEANLY]"

    def retrieve_structural_context(
        self,
        source_file: SourceFile,
        all_project_files: List[SourceFile],
    ) -> List[Dict[str, Any]]:
        """
        Extract direct dependency context from imported project files and component definitions.
        """
        if not source_file or not all_project_files:
            return []

        try:
            return self.cross_file_resolver.get_imported_context(
                source_file=source_file,
                all_project_files=all_project_files,
            )
        except Exception:
            return []

    def retrieve_semantic_context(
        self,
        query: str,
        project_id: str,
        exclude_file_path: Optional[Union[str, Path]] = None,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Perform local ChromaDB semantic vector retrieval based on focal code keywords or finding details.
        """
        if not query or not query.strip() or not project_id:
            return []

        try:
            raw_hits = self.vector_store.query_similar(
                query_text=query,
                project_id=project_id,
                top_k=max(1, top_k),
            )
        except Exception:
            return []

        exclude_str = (
            Path(exclude_file_path).as_posix().lower()
            if exclude_file_path else None
        )

        semantic_snippets: List[Dict[str, Any]] = []
        for hit in raw_hits:
            fpath = str(hit.get("file_path") or "").replace("\\", "/")
            if exclude_str and (exclude_str == fpath.lower() or exclude_str.endswith(fpath.lower()) or fpath.lower().endswith(exclude_str)):
                continue

            raw_content = str(hit.get("content") or "").strip()
            if not raw_content:
                continue

            # Clean truncation at full line boundary
            clean_content = self._truncate_at_line_boundary(raw_content, self.max_chars_per_snippet)

            semantic_snippets.append({
                "file": fpath,
                "file_path": fpath,
                "snippet": clean_content,
                "type": "semantic_vector_similarity",
                "component_name": hit.get("component_name"),
                "component_type": hit.get("component_type"),
                "start_line": hit.get("start_line", 1),
                "end_line": hit.get("end_line", 1),
                "distance": hit.get("distance", 0.0),
            })

        return semantic_snippets

    def retrieve_hybrid_context(
        self,
        source_file: SourceFile,
        all_project_files: List[SourceFile],
        project_id: Optional[str] = None,
        query: Optional[str] = None,
        top_k: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        US 27: Multi-strategy local retrieval:
        1. Retrieves exact structural dependencies from AST import resolution.
        2. Fills remaining slots using local vector similarity search.
        3. Deduplicates and ensures the focal file is never duplicated in context.
        """
        limit = top_k if top_k is not None else self.max_context_snippets
        results: List[Dict[str, Any]] = []
        seen_files: Set[str] = set()

        focal_norm = Path(source_file.file_path).as_posix().lower()
        seen_files.add(focal_norm)
        if source_file.relative_path:
            seen_files.add(str(source_file.relative_path).replace("\\", "/").lower())

        # 1. Structural ground-truth imports
        structural_items = self.retrieve_structural_context(source_file, all_project_files)
        for item in structural_items:
            f_key = str(item.get("file") or item.get("file_path") or "").replace("\\", "/").lower()
            if f_key not in seen_files:
                seen_files.add(f_key)
                # Clean snippet boundaries
                if item.get("snippet"):
                    item["snippet"] = self._truncate_at_line_boundary(item["snippet"], self.max_chars_per_snippet)
                results.append(item)
                if len(results) >= limit:
                    return results

        # 2. Semantic vector retrieval for remaining capacity
        remaining = limit - len(results)
        effective_query = query
        if not effective_query and source_file.content:
            # Extract meaningful symbols from first 20 lines of focal file
            lines = [l.strip() for l in source_file.content.splitlines()[:20] if l.strip()]
            effective_query = " ".join(lines[:5]) if lines else Path(source_file.file_path).stem

        if remaining > 0 and project_id and effective_query:
            semantic_items = self.retrieve_semantic_context(
                query=effective_query,
                project_id=project_id,
                exclude_file_path=source_file.file_path,
                top_k=remaining * 2,
            )
            for item in semantic_items:
                f_key = str(item.get("file") or item.get("file_path") or "").replace("\\", "/").lower()
                if f_key not in seen_files:
                    seen_files.add(f_key)
                    results.append(item)
                    if len(results) >= limit:
                        break

        return results[:limit]