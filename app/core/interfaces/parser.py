from abc import ABC, abstractmethod
from typing import Any
from app.core.enums import Language

class CodeParser(ABC):
    """Abstract interface that all language-specific parsers must implement."""
    @property
    @abstractmethod
    def language(self) -> Language:
        """Return the Language enum supported by this parser."""
        pass
    
    @abstractmethod
    def parse(self, code: str) -> Any:
        """
        Parse raw source code text into a concrete syntax tree (Tree-sitter Tree).
        Returns the parsed Tree object.
        """
        pass
    
    @abstractmethod
    def is_syntax_valid(self, code: str) -> bool:
        """
        Check if the code parses without syntax error nodes.
        Used for verification and patch safety (US 21).
        """
        pass
