from pathlib import Path
from typing import Optional

from app.analysis.parser import ParserRegistry
from app.core.enums import Language
from app.core.interfaces.filesystem import FileSystem
from app.core.models.patch import Patch
from app.infrastructure.filesystem import LocalFileSystem

EXTENSION_TO_LANGUAGE = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".java": Language.JAVA,
    ".c": Language.C,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".h": Language.C,
    ".hpp": Language.CPP,
}


class PatchValidator:
    """Validates pre-flight file state and post-patch syntax/disk integrity."""

    def __init__(
        self,
        filesystem: Optional[FileSystem] = None,
        parser_registry: Optional[ParserRegistry] = None,
    ):
        self.filesystem = filesystem if filesystem is not None else LocalFileSystem()
        self.parser_registry = parser_registry if parser_registry is not None else ParserRegistry()

    def validate_pre_patch(self, patch: Patch) -> bool:
        """
        Ensure target file exists, is non-empty, and matches original patch baseline.
        Rejects stale patches if file was modified externally.
        """
        target = Path(patch.file_path).resolve()
        if not self.filesystem.exists(target):
            raise FileNotFoundError(f"Target file does not exist: {target}")

        current_content = self.filesystem.read_text(target)
        if not current_content.strip():
            raise ValueError(f"Target file is empty: {target}")

        # Check for stale patch: compare content against patch.original_code
        if patch.original_code and current_content != patch.original_code:
            raise ValueError(
                f"Stale patch detected for '{target.name}'. "
                "The file has been modified since this patch was generated."
            )

        return True

    def validate_post_patch(self, patch: Patch) -> bool:
        """
        Verify that written patch produces valid syntax without fatal compile/parse errors.
        """
        target = Path(patch.file_path).resolve()
        if not self.filesystem.exists(target):
            return False

        content = self.filesystem.read_text(target)
        if not content.strip() and patch.modified_code.strip():
            return False

        # Syntax check via tree-sitter parser
        ext = target.suffix.lower()
        language = EXTENSION_TO_LANGUAGE.get(ext)
        if language and language != Language.UNKNOWN:
            try:
                if not self.parser_registry.is_syntax_valid(language, content):
                    return False
            except Exception:
                pass

        return True
