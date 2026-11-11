import ast
from pathlib import Path
from typing import Optional, Tuple, Union

from app.analysis.language_detector import (
    EXTENSION_MAPPING,
    LanguageDetector,
    default_language_detector,
)
from app.analysis.parser import ParserRegistry
from app.core.enums import Language
from app.core.interfaces.filesystem import FileSystem
from app.core.models.patch import Patch
from app.infrastructure.filesystem import LocalFileSystem

# Backward compatibility alias
EXTENSION_TO_LANGUAGE = EXTENSION_MAPPING


class PatchValidator:
    """Validates pre-flight file state, virtual in-memory AST syntax, and post-patch disk integrity."""

    def __init__(
        self,
        filesystem: Optional[FileSystem] = None,
        parser_registry: Optional[ParserRegistry] = None,
        language_detector: Optional[LanguageDetector] = None,
    ):
        self.filesystem = filesystem if filesystem is not None else LocalFileSystem()
        self.parser_registry = parser_registry if parser_registry is not None else ParserRegistry()
        self.language_detector = language_detector if language_detector is not None else default_language_detector

    def detect_language(self, file_path: Union[str, Path]) -> Language:
        """Detect language using the unified LanguageDetector."""
        return self.language_detector.detect_language(file_path=file_path)

    def validate_virtual_syntax(
        self,
        content: str,
        language: Optional[Language] = None,
        file_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate source code syntax in-memory without writing to disk.
        Uses Python AST parsing AND bytecode compilation for Python, and Tree-sitter parsers for all languages.
        Catches both grammatical errors and semantic syntax errors ('return' outside function, duplicate args, etc.).
        Returns: (is_valid: bool, error_message: Optional[str])
        """
        lang = language
        if (lang is None or lang == Language.UNKNOWN) and file_path:
            lang = self.detect_language(file_path)

        if not content:
            return True, None

        # 1. Native AST parse & Bytecode Compilation for Python
        if lang == Language.PYTHON:
            try:
                # Strip potential UTF-8 Byte Order Mark (BOM)
                clean_content = content.lstrip("\ufeff")
                ast.parse(clean_content)
                compile(clean_content, "<patch>", "exec")
            except SyntaxError as syn_err:
                return False, f"Python SyntaxError at line {syn_err.lineno}, column {syn_err.offset}: {syn_err.msg}"
            except Exception as ex:
                return False, f"Python parsing error: {ex}"

        # 2. Tree-sitter validation for supported languages
        if lang and lang != Language.UNKNOWN and self.parser_registry.is_supported(lang):
            try:
                if not self.parser_registry.is_syntax_valid(lang, content):
                    return False, f"Tree-sitter detected syntax errors in {lang.value.capitalize()} code."
            except Exception as p_err:
                return False, f"Parser exception during syntax validation: {p_err}"

        return True, None

    def validate_patch_candidate(self, patch: Patch) -> Tuple[bool, Optional[str]]:
        """
        Validate a proposed Patch object in-memory before disk modification.
        Verifies that modified_code has valid syntax and is not corrupt.
        """
        if not patch.modified_code and patch.original_code:
            return False, "Candidate patch produced empty modified code from non-empty original."

        lang = self.detect_language(patch.file_path)
        return self.validate_virtual_syntax(
            content=patch.modified_code,
            language=lang,
            file_path=patch.file_path,
        )

    def validate_pre_patch(self, patch: Patch, validate_candidate_syntax: bool = True) -> bool:
        """
        Ensure target file exists, is non-empty, matches original baseline (not stale),
        and that the candidate modified code has valid syntax before touching disk.
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

        # Pre-application QA Syntax Validation: Check patch syntax BEFORE touching disk
        if validate_candidate_syntax and patch.modified_code:
            is_valid, err_msg = self.validate_patch_candidate(patch)
            if not is_valid:
                raise ValueError(f"Pre-application syntax validation failed: syntax errors detected. {err_msg}")

        return True

    def validate_post_patch(self, patch: Patch) -> bool:
        """
        Verify that written patch produces valid syntax without fatal compile/parse errors on disk.
        """
        target = Path(patch.file_path).resolve()
        if not self.filesystem.exists(target):
            return False

        content = self.filesystem.read_text(target)
        if not content.strip() and patch.modified_code.strip():
            return False

        # Virtual syntax check on written content
        is_valid, _ = self.validate_virtual_syntax(content=content, file_path=target)
        return is_valid