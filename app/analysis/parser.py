from typing import Dict, Optional
from app.core.enums import Language
from app.core.interfaces.parser import CodeParser
from app.core.models.code import SourceFile
from app.analysis.parsers.python_parser import PythonParser
from app.analysis.parsers.javascript_parser import JavaScriptParser
from app.analysis.parsers.java_parser import JavaParser
from app.analysis.parsers.c_parser import CParser
from app.analysis.parsers.cpp_parser import CppParser

class ParserRegistry:
    """Registry maintaining instances of CodeParser for each supported Language."""
    def __init__(self):
        self._parsers: Dict[Language, CodeParser] = {}
        self._register_default_parsers()

    def _register_default_parsers(self) -> None:
        """Register the 5 default supported language parsers."""
        self.register_parser(PythonParser())
        self.register_parser(JavaScriptParser())
        self.register_parser(JavaParser())
        self.register_parser(CParser())
        self.register_parser(CppParser())

    def register_parser(self, parser: CodeParser) -> None:
        """Register a new language parser dynamically."""
        self._parsers[parser.language] = parser

    def get_parser(self, language: Language) -> Optional[CodeParser]:
        """Retrieve the parser registered for a specific Language."""
        return self._parsers.get(language)

    def is_supported(self, language: Language) -> bool:
        """Check if a parser is available for the given language."""
        return language in self._parsers

    def parse_code(self, language: Language, code: str):
        """
        Parse raw code text for the given language.
        Returns the parsed Tree or None if the language is unsupported.
        """
        parser = self.get_parser(language)
        if not parser:
            return None
        return parser.parse(code)

    def parse_file(self, source_file: SourceFile, code: str):
        """
        Convenience method to parse a SourceFile directly using its detected language.
        """
        return self.parse_code(source_file.language, code)

    def is_syntax_valid(self, language: Language, code: str) -> bool:
        """
        Verify if the given code has valid syntax for its language.
        """
        parser = self.get_parser(language)
        if not parser:
            return False
        return parser.is_syntax_valid(code)
        
# Singleton instance for easy import and access across the application
parser_registry = ParserRegistry()
