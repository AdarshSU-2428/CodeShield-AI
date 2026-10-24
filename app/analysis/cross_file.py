import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Union

from app.core.enums import Language
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.vector_store import VectorStore
from app.core.models.code import SourceFile
from app.infrastructure.filesystem import LocalFileSystem


class CrossFileContextResolver:
    """Resolves cross-file dependencies, imports, and semantic context for multi-file security audits."""

    def __init__(
        self,
        filesystem: Optional[FileSystem] = None,
        vector_store: Optional[VectorStore] = None,
        max_context_chars_per_file: int = 2500,
        max_related_files: int = 4,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.vector_store: Optional[VectorStore] = vector_store
        self.max_context_chars_per_file: int = max_context_chars_per_file
        self.max_related_files: int = max_related_files

    def extract_imports(self, source_code: str, language: Language) -> List[str]:
        """Extract imported module names and file references across languages."""
        if not source_code or not source_code.strip():
            return []

        imports: Set[str] = set()

        if language == Language.PYTHON:
            # e.g., import auth, from services.db import execute_query
            for match in re.finditer(r"(?:from\s+([a-zA-Z0-9_\.]+)\s+import|import\s+([a-zA-Z0-9_\.]+))", source_code):
                mod = match.group(1) or match.group(2)
                if mod:
                    imports.add(mod.split(".")[0])
                    imports.add(mod.replace(".", "/"))

        elif language == Language.JAVASCRIPT:
            # e.g., import foo from './foo', const db = require('../db')
            for match in re.finditer(r"""(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))""", source_code):
                mod = match.group(1) or match.group(2)
                if mod:
                    imports.add(Path(mod).name)
                    imports.add(mod.lstrip("./").lstrip("../"))

        elif language in (Language.C, Language.CPP):
            # e.g., #include "auth_helper.h"
            for match in re.finditer(r'#include\s*["<]([^">]+)[">]', source_code):
                header = match.group(1)
                imports.add(Path(header).stem)
                imports.add(Path(header).name)

        elif language == Language.JAVA:
            # e.g., import com.app.services.DatabaseService;
            for match in re.finditer(r"import\s+(?:static\s+)?([a-zA-Z0-9_\.]+);", source_code):
                mod = match.group(1)
                parts = mod.split(".")
                if parts:
                    imports.add(parts[-1])  # Class name or static method
                    if len(parts) >= 2:
                        imports.add(parts[-2])  # Enclosing class

        return sorted(list(imports))

    def resolve_import_to_file(
        self,
        import_name: str,
        current_file: Union[str, Path],
        available_files: List[SourceFile],
    ) -> Optional[SourceFile]:
        """Find matching SourceFile in the project for a given imported identifier."""
        norm_import = import_name.replace(".", "/").replace("\\", "/").strip().lower()
        parts = [p for p in norm_import.split("/") if p]
        leaf_name = parts[-1] if parts else norm_import
        clean_stem = Path(norm_import).stem.lower()

        current_path_str = Path(current_file).as_posix().lower()

        for candidate in available_files:
            cand_path_str = Path(candidate.file_path).as_posix().lower()
            if cand_path_str == current_path_str:
                continue

            cand_stem = Path(candidate.file_path).stem.lower()
            cand_rel = str(candidate.relative_path or "").replace("\\", "/").lower()

            if (
                leaf_name == cand_stem
                or clean_stem == cand_stem
                or norm_import in cand_rel
                or cand_rel.endswith(f"/{leaf_name}.py")
                or cand_rel.endswith(f"/{norm_import}.py")
            ):
                return candidate

        return None

    def get_imported_context(
        self,
        source_file: SourceFile,
        all_project_files: List[SourceFile],
    ) -> List[Dict[str, Any]]:
        """Identify imported project files and extract their code context."""
        extracted_imports = self.extract_imports(source_file.content, source_file.language)
        context_items: List[Dict[str, Any]] = []
        seen_paths: Set[str] = set()

        for imp in extracted_imports:
            if len(context_items) >= self.max_related_files:
                break

            matched_file = self.resolve_import_to_file(imp, source_file.file_path, all_project_files)
            if matched_file and matched_file.file_path not in seen_paths:
                seen_paths.add(matched_file.file_path)
                
                content = matched_file.content
                if len(content) > self.max_context_chars_per_file:
                    content = content[: self.max_context_chars_per_file] + "\n# [TRUNCATED CONTEXT]"

                rel_str = str(matched_file.relative_path or Path(matched_file.file_path).name).replace("\\", "/")
                context_items.append({
                    "file": rel_str,
                    "file_path": str(matched_file.file_path),
                    "snippet": content,
                    "type": "import_dependency",
                })

        return context_items

    def get_semantic_context(
        self,
        query: str,
        project_id: str,
        exclude_file_path: Optional[str] = None,
        top_k: int = 2,
    ) -> List[Dict[str, Any]]:
        """Query ChromaDB vector store for semantically related code across other files."""
        if not self.vector_store or not query or not query.strip():
            return []

        try:
            matches = self.vector_store.query_similar(
                query_text=query,
                project_id=project_id,
                top_k=top_k + 2,
            )
        except Exception:
            return []

        results: List[Dict[str, Any]] = []
        norm_exclude = Path(exclude_file_path).as_posix() if exclude_file_path else None

        for match in matches:
            metadata = match.get("metadata", {})
            file_path = metadata.get("file_path", "")
            
            if norm_exclude and Path(file_path).as_posix() == norm_exclude:
                continue

            content = match.get("content", "")
            if not content:
                continue

            if len(content) > self.max_context_chars_per_file:
                content = content[: self.max_context_chars_per_file] + "\n# [TRUNCATED CONTEXT]"

            rel_sem = str(metadata.get("relative_path") or Path(file_path).name).replace("\\", "/")
            results.append({
                "file": rel_sem,
                "file_path": str(file_path),
                "snippet": content,
                "type": "semantic_similarity",
            })

            if len(results) >= top_k:
                break

        return results

    def bundle_cross_file_context(
        self,
        source_file: SourceFile,
        all_project_files: List[SourceFile],
        project_id: Optional[str] = None,
        semantic_query: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Assemble a unified cross-file context bundle combining import graph and vector search."""
        bundled_context: List[Dict[str, Any]] = []
        seen_files: Set[str] = set()

        # 1. Structural import-driven context
        import_context = self.get_imported_context(source_file, all_project_files)
        for item in import_context:
            seen_files.add(item["file"])
            bundled_context.append(item)

        # 2. Semantic vector-driven context
        remaining_slots = self.max_related_files - len(bundled_context)
        if remaining_slots > 0 and self.vector_store and project_id and semantic_query:
            semantic_items = self.get_semantic_context(
                query=semantic_query,
                project_id=project_id,
                exclude_file_path=str(source_file.file_path),
                top_k=remaining_slots,
            )
            for item in semantic_items:
                if item["file"] not in seen_files:
                    seen_files.add(item["file"])
                    bundled_context.append(item)

        return bundled_context[: self.max_related_files]
