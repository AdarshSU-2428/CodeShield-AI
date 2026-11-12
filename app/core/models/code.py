from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid
from app.core.enums import FileStatus, Language


class SourceFile:
    """Represents a discovered source file inside a project workspace."""

    def __init__(
        self,
        file_path: Union[str, Path],
        relative_path: Union[str, Path],
        language: Language = Language.UNKNOWN,
        status: FileStatus = FileStatus.NEW,
        size_bytes: int = 0,
        content_hash: Optional[str] = None,
        file_id: Optional[str] = None,
        content: Optional[str] = None,
    ):
        self.file_path = Path(file_path).resolve() if isinstance(file_path, str) else file_path.resolve()
        self.relative_path = Path(relative_path) if isinstance(relative_path, str) else relative_path
        self.language = language
        self.status = status
        self.size_bytes = size_bytes
        self.content_hash = content_hash
        self.file_id = file_id if file_id else str(uuid.uuid4())
        self.content = content or ""
        
    @property
    def extension(self) -> str:
        """Return the lowercase file extension including the dot (e.g., '.py')."""
        return self.file_path.suffix.lower()

    @property
    def is_supported(self) -> bool:
        """Check if the file is in a supported programming language."""
        return self.language != Language.UNKNOWN and self.status != FileStatus.UNSUPPORTED
    
    def __repr__(self) -> str:
        return f"<SourceFile path='{self.relative_path}' lang={self.language.value} status={self.status.value}>"


class CodeComponent:
    """
    Represents a structural code component extracted from an AST
    (e.g., class, function, method) with standardized cross-language metadata.
    """

    def __init__(
        self,
        name: str,
        component_type: str,
        start_line: int,
        end_line: int,
        source_content: str,
        file_path: Union[str, Path],
        parent_name: Optional[str] = None,
        language: Language = Language.UNKNOWN,
        component_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.component_type = component_type  
        self.start_line = start_line
        self.end_line = end_line
        self.source_content = source_content
        self.file_path = Path(file_path) if isinstance(file_path, str) else file_path
        self.parent_name = parent_name
        self.language = language
        self.component_id = component_id if component_id else str(uuid.uuid4())

        # User Story 26: Common normalized metadata schema across all languages
        base_meta: Dict[str, Any] = {
            "language": language.value if hasattr(language, "value") else str(language),
            "component_type": component_type,
            "line_count": max(1, end_line - start_line + 1),
            "signature": "",
            "parameters": [],
            "parameter_count": 0,
            "visibility": "public",
            "is_async": False,
            "docstring": None,
            "decorators": [],
        }
        if metadata:
            base_meta.update(metadata)
            if "parameters" in base_meta and "parameter_count" not in metadata:
                base_meta["parameter_count"] = len(base_meta["parameters"])
        self.metadata: Dict[str, Any] = base_meta

    @property
    def line_count(self) -> int:
        """Return total number of lines spanned by this component."""
        return max(1, self.end_line - self.start_line + 1)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize CodeComponent and its normalized metadata to a dictionary."""
        return {
            "component_id": self.component_id,
            "name": self.name,
            "component_type": self.component_type,
            "file_path": Path(self.file_path).as_posix() if self.file_path else "",
            "parent_name": self.parent_name,
            "language": self.language.value if hasattr(self.language, "value") else str(self.language),
            "start_line": self.start_line,
            "end_line": self.end_line,
            "line_count": self.line_count,
            "source_content": self.source_content,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"<CodeComponent {self.component_type} '{self.name}' lines={self.start_line}-{self.end_line}>"


class CodeChunk:
    """
    Represents a retrieval chunk derived from code components for local RAG.
    """

    def __init__(
        self,
        content: str,
        file_path: Union[str, Path],
        start_line: int,
        end_line: int,
        component_name: Optional[str] = None,
        metadata: Optional[Dict] = None,
        chunk_id: Optional[str] = None,
    ):
        self.content = content
        self.file_path = Path(file_path) if isinstance(file_path, str) else file_path
        self.start_line = start_line
        self.end_line = end_line
        self.component_name = component_name
        self.metadata = metadata if metadata is not None else {}
        self.chunk_id = chunk_id if chunk_id else str(uuid.uuid4())
        
    def __repr__(self) -> str:
        return f"<CodeChunk file='{self.file_path.name}' lines={self.start_line}-{self.end_line}>"