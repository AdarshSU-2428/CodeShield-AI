from pathlib import Path
from typing import List, Optional
from app.core.models.code import CodeChunk, CodeComponent
from app.infrastructure.config import AppConfig, config as default_config

class CodeChunker:
    """Slices code components into retrieval-sized chunks with rich contextual headers."""
    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config if config else default_config
        # Read from config with sensible defaults
        rag_cfg = getattr(self.config, "_raw_config", {}).get("rag", {})
        self.max_chunk_lines = rag_cfg.get("chunk_size_lines", 50)
        self.overlap_lines = rag_cfg.get("chunk_overlap_lines", 10)
    
    def chunk_component(self, component: CodeComponent) -> List[CodeChunk]:
        """
        Convert a single CodeComponent into one or more CodeChunks.
        Small components become 1 chunk; large components are sliced with overlap.
        """
        lines = component.source_content.splitlines(keepends=True)
        total_lines = len(lines)
        # Build contextual header for embedding clarity
        header = self._build_header(component)
        # Case 1: Small component fits in a single chunk
        if total_lines <= self.max_chunk_lines:
            content = header + component.source_content
            chunk = CodeChunk(
                content=content,
                file_path=component.file_path,
                start_line=component.start_line,
                end_line=component.end_line,
                component_name=component.name,
                metadata={
                    "component_type": component.component_type,
                    "parent_name": component.parent_name or "",
                    "language": component.language.value,
                    "line_count": total_lines,
                },
            )
            return [chunk]

        # Case 2: Large component sliced into overlapping windows
        chunks: List[CodeChunk] = []
        step = max(1, self.max_chunk_lines - self.overlap_lines)
        start_idx = 0
        
        while start_idx < total_lines:
            end_idx = min(start_idx + self.max_chunk_lines, total_lines)
            chunk_slice = "".join(lines[start_idx:end_idx])
            # Calculate 1-indexed line numbers relative to the original file
            chunk_start_line = component.start_line + start_idx
            chunk_end_line = component.start_line + end_idx - 1
            chunk_content = header + f"// [Lines {chunk_start_line}-{chunk_end_line}]\n" + chunk_slice
            
            chunk = CodeChunk(
                content=chunk_content,
                file_path=component.file_path,
                start_line=chunk_start_line,
                end_line=chunk_end_line,
                component_name=component.name,
                metadata={
                    "component_type": component.component_type,
                    "parent_name": component.parent_name or "",
                    "language": component.language.value,
                    "line_count": end_idx - start_idx,
                    "is_sub_chunk": True,
                },
            )

            chunks.append(chunk)
            if end_idx == total_lines:
                break
            start_idx += step

        return chunks
    
    def chunk_components(self, components: List[CodeComponent]) -> List[CodeChunk]:
        """Batch process a list of CodeComponents into a flat list of CodeChunks."""
        all_chunks: List[CodeChunk] = []
        for comp in components:
            all_chunks.extend(self.chunk_component(comp))

        return all_chunks
    
    def _build_header(self, component: CodeComponent) -> str:
        """Create a contextual metadata header prepended to the code chunk."""
        file_name = Path(component.file_path).name if component.file_path else "unknown"
        parts = [f"File: {file_name}"]

        if component.parent_name:
            parts.append(f"Parent: {component.parent_name}")
        
        parts.append(f"{component.component_type.capitalize()}: {component.name}")
        parts.append(f"Lang: {component.language.value}")

        return f"// [{ ' | '.join(parts) }]\n"