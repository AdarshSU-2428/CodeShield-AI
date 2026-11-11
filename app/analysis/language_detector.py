from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Union

from app.core.enums import Language


EXTENSION_MAPPING: Dict[str, Language] = {
    # Python
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".pyi": Language.PYTHON,
    # JavaScript
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    # Java
    ".java": Language.JAVA,
    # C
    ".c": Language.C,
    # C++
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".hpp": Language.CPP,
    ".hh": Language.CPP,
    ".hxx": Language.CPP,
}

CPP_HEADER_INDICATORS: Set[str] = {
    "namespace",
    "template",
    "class",
    "std::",
    "public:",
    "private:",
    "protected:",
    "virtual",
    "typename",
    "constexpr",
    "#include <iostream>",
    "#include <vector>",
    "#include <string>",
    "#include <memory>",
    "#include <map>",
}


class LanguageDetector:
    """
    Intelligent language classifier combining extension mapping,
    shebang line inspection, and C vs C++ header token heuristics.
    """

    def __init__(self, custom_mapping: Optional[Dict[str, Language]] = None):
        self._extension_map = dict(EXTENSION_MAPPING)
        if custom_mapping:
            self._extension_map.update(custom_mapping)

    def detect_from_path(self, file_path: Union[str, Path]) -> Language:
        """Detect language purely based on file extension."""
        p = Path(file_path)
        ext = p.suffix.lower()

        # Handle header ambiguity: .h defaults to C if no content is provided
        if ext == ".h":
            return Language.C

        return self._extension_map.get(ext, Language.UNKNOWN)

    def detect_from_shebang(self, first_line: str) -> Language:
        """Inspect shebang interpreter directive on the first line (e.g., #!/usr/bin/env python3)."""
        line = first_line.strip()
        if not line.startswith("#!"):
            return Language.UNKNOWN

        lower_line = line.lower()
        if "python" in lower_line:
            return Language.PYTHON
        if "node" in lower_line or "deno" in lower_line:
            return Language.JAVASCRIPT

        return Language.UNKNOWN

    def disambiguate_c_header(self, content: str) -> Language:
        """
        Differentiate between C and C++ for .h files by scanning code tokens.
        If C++ keywords, templates, or STL headers exist, classify as C++; otherwise C.
        """
        if not content:
            return Language.C

        for indicator in CPP_HEADER_INDICATORS:
            if indicator in content:
                return Language.CPP

        # Regex check for template or namespace patterns
        if re.search(r"\bnamespace\s+[a-zA-Z_]", content) or re.search(r"\btemplate\s*<", content):
            return Language.CPP

        return Language.C

    def detect_language(
        self,
        file_path: Optional[Union[str, Path]] = None,
        content: Optional[str] = None,
    ) -> Language:
        """
        Unified classification entry point:
        1. Checks extension if file_path is given.
        2. If extension is .h, disambiguates via content heuristics.
        3. If no extension or UNKNOWN, inspects shebang line in content.
        """
        lang = Language.UNKNOWN

        # 1. Extension inspection
        if file_path:
            p = Path(file_path)
            ext = p.suffix.lower()
            if ext == ".h":
                return self.disambiguate_c_header(content or "")
            lang = self._extension_map.get(ext, Language.UNKNOWN)
            if lang != Language.UNKNOWN:
                return lang

        # 2. Content shebang inspection for extensionless files or UNKNOWN
        if content and content.strip():
            first_line = content.splitlines()[0]
            shebang_lang = self.detect_from_shebang(first_line)
            if shebang_lang != Language.UNKNOWN:
                return shebang_lang

        return lang

    def is_supported(self, language: Language) -> bool:
        """Check if language is an officially supported audit language."""
        return language in {
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.JAVA,
            Language.C,
            Language.CPP,
        }


# Global singleton instance for system-wide detection
default_language_detector = LanguageDetector()