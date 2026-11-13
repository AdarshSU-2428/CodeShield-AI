import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

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
    """
    US 20 & US 21: Validates pre-flight file state, virtual in-memory AST syntax,
    extracts precise diagnostic error coordinates (line, column, token), and verifies post-patch disk integrity.
    """

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

    def _find_error_node_diagnostics(self, node, code_bytes: bytes) -> Optional[Dict[str, Any]]:
        """
        Recursively walk a Tree-sitter AST to locate the first ERROR or MISSING node
        and extract 1-indexed line and column coordinates and the erroneous code slice.
        """
        if node.type == "ERROR" or node.is_missing:
            start_row = node.start_point.row + 1
            start_col = node.start_point.column + 1
            error_slice = code_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace").strip()
            return {
                "line": start_row,
                "column": start_col,
                "token": error_slice or "unexpected syntax",
                "is_missing": node.is_missing,
            }

        for child in node.children:
            diag = self._find_error_node_diagnostics(child, code_bytes)
            if diag:
                return diag

        return None

    def get_syntax_diagnostics(
        self,
        content: str,
        language: Optional[Language] = None,
        file_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        US 21: Deep polyglot syntax inspection returning structured diagnostics:
        {
            'is_valid': bool,
            'error_message': Optional[str],
            'line': Optional[int],
            'column': Optional[int],
            'token': Optional[str],
            'language': str,
        }
        """
        lang = language
        if (lang is None or lang == Language.UNKNOWN) and file_path:
            lang = self.detect_language(file_path)

        lang_str = lang.value if hasattr(lang, "value") else str(lang or "unknown")

        if not content or not content.strip():
            return {
                "is_valid": True,
                "error_message": None,
                "line": None,
                "column": None,
                "token": None,
                "language": lang_str,
            }

        # 1. Native AST & Bytecode Compilation for Python
        if lang == Language.PYTHON:
            try:
                clean_content = content.lstrip("\ufeff")
                ast.parse(clean_content)
                compile(clean_content, "<patch_validation>", "exec")
                return {
                    "is_valid": True,
                    "error_message": None,
                    "line": None,
                    "column": None,
                    "token": None,
                    "language": "python",
                }
            except SyntaxError as syn_err:
                msg = f"Python SyntaxError at line {syn_err.lineno}, column {syn_err.offset}: {syn_err.msg}"
                return {
                    "is_valid": False,
                    "error_message": msg,
                    "line": syn_err.lineno,
                    "column": syn_err.offset,
                    "token": syn_err.text.strip() if syn_err.text else None,
                    "language": "python",
                }
            except Exception as ex:
                return {
                    "is_valid": False,
                    "error_message": f"Python parsing error: {ex}",
                    "line": 1,
                    "column": 1,
                    "token": None,
                    "language": "python",
                }

        # 2. Tree-sitter parsing for JavaScript, Java, C, and C++
        if lang and lang != Language.UNKNOWN and self.parser_registry.is_supported(lang):
            try:
                parser = self.parser_registry.get_parser(lang)
                if parser:
                    code_bytes = content.encode("utf-8") if isinstance(content, str) else content
                    tree = parser.parse(content)
                    
                    if tree and tree.root_node:
                        # Check for syntax ERROR or MISSING nodes
                        diag = self._find_error_node_diagnostics(tree.root_node, code_bytes)
                        if diag:
                            lang_name = lang.value.capitalize()
                            msg = (
                                f"Tree-sitter detected syntax errors in {lang_name} (syntax error at line {diag['line']}, "
                                f"column {diag['column']}): unexpected token '{diag['token']}'"
                            )
                            return {
                                "is_valid": False,
                                "error_message": msg,
                                "line": diag["line"],
                                "column": diag["column"],
                                "token": diag["token"],
                                "language": lang.value,
                            }

                return {
                    "is_valid": True,
                    "error_message": None,
                    "line": None,
                    "column": None,
                    "token": None,
                    "language": lang.value,
                }

            except Exception as p_err:
                return {
                    "is_valid": False,
                    "error_message": f"Parser exception during syntax validation: {p_err}",
                    "line": 1,
                    "column": 1,
                    "token": None,
                    "language": lang.value if hasattr(lang, "value") else str(lang),
                }

        return {
            "is_valid": True,
            "error_message": None,
            "line": None,
            "column": None,
            "token": None,
            "language": lang_str,
        }

    def validate_virtual_syntax(
        self,
        content: str,
        language: Optional[Language] = None,
        file_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate source code syntax in-memory without writing to disk.
        Returns: (is_valid: bool, error_message: Optional[str])
        """
        diag = self.get_syntax_diagnostics(content=content, language=language, file_path=file_path)
        return diag["is_valid"], diag["error_message"]

    def validate_patch_candidate(self, patch: Patch) -> Tuple[bool, Optional[str]]:
        """
        US 21: Validate a proposed Patch object in-memory before disk modification.
        Verifies that modified_code has valid syntax and returns detailed diagnostic messages.
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

        is_valid, _ = self.validate_virtual_syntax(content=content, file_path=target)
        return is_valid