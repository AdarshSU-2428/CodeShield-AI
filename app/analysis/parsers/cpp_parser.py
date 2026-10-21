from typing import Any
import tree_sitter_cpp
from tree_sitter import Language as TSLanguage, Parser
from app.core.enums import Language
from app.core.interfaces.parser import CodeParser

class CppParser(CodeParser):
    """Parses C++ source code into Tree-sitter syntax trees."""
    def __init__(self):
        # Initialize Tree-sitter language and parser instance
        self._ts_language = TSLanguage(tree_sitter_cpp.language())
        self._parser = Parser(self._ts_language)

    @property
    def language(self) -> Language:
        return Language.CPP

    def parse(self, code: str) -> Any:
        """Parse C++ source code into a Tree-sitter Tree."""
        if isinstance(code, str):
            code_bytes = code.encode("utf-8")
        else:
            code_bytes = code
        return self._parser.parse(code_bytes)

    def is_syntax_valid(self, code: str) -> bool:
        """Check if code parses without syntax ERROR nodes."""
        tree = self.parse(code)
        return not self._has_error_nodes(tree.root_node)
        
    def _has_error_nodes(self, node) -> bool:
        """Recursively check if an AST node or its children contain an ERROR or MISSING node."""
        if node.type == "ERROR" or node.is_missing:
            return True
        for child in node.children:
            if self._has_error_nodes(child):
                return True
        return False
