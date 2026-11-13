from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.analysis.component_extractor import ComponentExtractor
from app.analysis.parser import ParserRegistry
from app.analysis.scanner import RepositoryScanner
from app.core.enums import FileStatus
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.vector_store import VectorStore
from app.core.models.code import CodeChunk, CodeComponent, SourceFile
from app.core.models.project import Project
from app.infrastructure.config import AppConfig, config as default_config
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.chroma_store import ChromaVectorStore
from app.rag.chunker import CodeChunker


class RepositoryIndexer:
    """
    End-to-end repository indexing pipeline.
    Orchestrates scanning, AST parsing, component extraction,
    hierarchical chunking, and vector database ingestion.
    """

    def __init__(
        self,
        vector_store: Optional[VectorStore] = None,
        scanner: Optional[RepositoryScanner] = None,
        filesystem: Optional[FileSystem] = None,
        chunker: Optional[CodeChunker] = None,
        extractor: Optional[ComponentExtractor] = None,
        parser_registry: Optional[ParserRegistry] = None,
        config: Optional[AppConfig] = None,
    ):
        self.config = config if config else default_config
        self.filesystem = filesystem if filesystem else LocalFileSystem()
        self.vector_store = vector_store if vector_store else ChromaVectorStore(config=self.config)
        self.scanner = scanner if scanner else RepositoryScanner(filesystem=self.filesystem, config=self.config)
        self.chunker = chunker if chunker else CodeChunker(config=self.config)
        self.extractor = extractor if extractor else ComponentExtractor()
        self.parser_registry = parser_registry if parser_registry else ParserRegistry()

    def index_project(self, project: Project) -> Dict[str, Any]:
        """
        Scan and index all eligible source files in a project.
        Returns a summary report of indexed files and chunks.
        """
        project_id = getattr(project, "project_id", getattr(project, "id", str(project.root_path)))
        scanned_files = self.scanner.scan_project(project)
        
        total_chunks = 0
        indexed_files = 0
        errors: List[str] = []

        for source_file in scanned_files:
            try:
                chunks = self.index_file(source_file, project_id=project_id)
                if chunks:
                    total_chunks += len(chunks)
                    indexed_files += 1

            except Exception as e:
                errors.append(f"Failed to index {source_file.file_path}: {str(e)}")

        return {
            "project_id": project_id,
            "files_scanned": len(scanned_files),
            "files_indexed": indexed_files,
            "chunks_indexed": total_chunks,
            "errors": errors,
        }

    def index_incremental(
        self,
        project: Project,
        baseline_manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        US 28: Incremental repository indexing.
        Skips UNCHANGED files entirely to save compute and embedding generation.
        Indexes NEW files and re-indexes MODIFIED files (purging stale chunks).
        Deletes vector chunks for DELETED files.
        Returns detailed delta metrics and the updated snapshot manifest.
        """
        project_id = getattr(project, "project_id", getattr(project, "id", str(project.root_path)))
        classified_files, updated_manifest = self.scanner.detect_changes(
            project=project,
            baseline_manifest=baseline_manifest,
        )

        unchanged_count = 0
        new_count = 0
        modified_count = 0
        deleted_count = 0
        total_chunks_indexed = 0
        errors: List[str] = []

        for sf in classified_files:
            try:
                if sf.status == FileStatus.UNCHANGED:
                    unchanged_count += 1
                    continue

                elif sf.status == FileStatus.DELETED:
                    # Purge chunks from vector store using relative or string file path
                    del_path_str = str(sf.file_path)
                    self.remove_file(file_path=del_path_str, project_id=project_id)
                    deleted_count += 1

                elif sf.status in (FileStatus.NEW, FileStatus.MODIFIED):
                    chunks = self.index_file(source_file=sf, project_id=project_id)
                    total_chunks_indexed += len(chunks)
                    if sf.status == FileStatus.NEW:
                        new_count += 1
                    else:
                        modified_count += 1

            except Exception as exc:
                errors.append(f"Error incrementally indexing {sf.file_path}: {exc}")

        return {
            "project_id": project_id,
            "unchanged_files": unchanged_count,
            "new_files": new_count,
            "modified_files": modified_count,
            "deleted_files": deleted_count,
            "chunks_indexed": total_chunks_indexed,
            "manifest": updated_manifest,
            "errors": errors,
        }

    def index_file(self, source_file: SourceFile, project_id: str) -> List[CodeChunk]:
        """
        Parse, extract, chunk, and index an individual source file.
        Removes any previously stored chunks for this file to prevent duplicates.
        """
        # Skip unsupported or non-code binary files
        if getattr(source_file, "status", None) and source_file.status.value == "unsupported":
            return []
        
        if getattr(source_file, "language", None) and source_file.language.value == "unknown":
            return []

        file_path_str = str(source_file.file_path)
        
        # 1. Invalidate stale chunks for this file
        self.vector_store.delete_file_chunks(file_path=file_path_str, project_id=project_id)

        # 2. Read source code
        if not self.filesystem.exists(source_file.file_path):
            return []

        source_code = self.filesystem.read_text(source_file.file_path)
        if not source_code.strip():
            return []

        # 3. Retrieve parser for this language
        parser = self.parser_registry.get_parser(source_file.language)
        components: List[CodeComponent] = []

        if parser:
            try:
                tree = parser.parse(source_code)
                components = self.extractor.extract_components(
                    tree=tree,
                    source_code=source_code,
                    source_file=source_file,
                )
            except Exception:
                components = []

        # 4. Fallback: If no components were detected (e.g. scripts or non-AST files), chunk whole file
        if not components:
            line_count = len(source_code.splitlines())
            fallback_component = CodeComponent(
                name=Path(source_file.file_path).stem,
                component_type="file",
                start_line=1,
                end_line=max(1, line_count),
                source_content=source_code,
                file_path=source_file.file_path,
                language=source_file.language,
            )
            chunks = self.chunker.chunk_component(fallback_component)
            
        else:
            chunks = self.chunker.chunk_components(components)

        # 5. Ingest chunks into VectorStore
        if chunks:
            self.vector_store.add_chunks(chunks=chunks, project_id=project_id)

        return chunks

    def remove_file(self, file_path: str, project_id: str) -> int:
        """Remove file chunks from the vector store upon file deletion."""
        return self.vector_store.delete_file_chunks(file_path=file_path, project_id=project_id)

    def search_project(
        self,
        query: str,
        project_id: str,
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Perform semantic code search across the indexed project."""
        return self.vector_store.query_similar(
            query_text=query,
            project_id=project_id,
            top_k=top_k,
            filters=filters,
        )

    def reset_project(self, project_id: str) -> None:
        """Purge all indexed vectors for the given project."""
        self.vector_store.reset_project_index(project_id=project_id)
