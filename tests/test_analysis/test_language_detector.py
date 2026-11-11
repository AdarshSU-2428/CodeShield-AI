from pathlib import Path
import pytest

from app.analysis.language_detector import LanguageDetector, default_language_detector
from app.analysis.scanner import RepositoryScanner
from app.core.enums import FileStatus, Language
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem


class InMemoryFileSystem(LocalFileSystem):
    """In-memory filesystem for testing scanner with language detection."""

    def __init__(self, virtual_files=None):
        self._files = virtual_files or {}

    def is_directory(self, path) -> bool:
        return True

    def exists(self, path) -> bool:
        norm = Path(path).as_posix()
        return norm in self._files or str(path) in self._files

    def read_text(self, path, encoding='utf-8') -> str:
        norm = Path(path).as_posix()
        if norm in self._files:
            return self._files[norm]
        if str(path) in self._files:
            return self._files[str(path)]
        raise FileNotFoundError(f"File {path} not found.")

    def compute_hash(self, path) -> str:
        return "mock_hash_12345"


def test_detect_from_path_supported_extensions():
    """Verify standard extensions map to their respective languages."""
    detector = LanguageDetector()

    assert detector.detect_from_path("app/main.py") == Language.PYTHON
    assert detector.detect_from_path("src/script.pyw") == Language.PYTHON
    assert detector.detect_from_path("web/index.js") == Language.JAVASCRIPT
    assert detector.detect_from_path("web/component.jsx") == Language.JAVASCRIPT
    assert detector.detect_from_path("server/App.java") == Language.JAVA
    assert detector.detect_from_path("native/driver.c") == Language.C
    assert detector.detect_from_path("native/engine.cpp") == Language.CPP
    assert detector.detect_from_path("native/engine.cc") == Language.CPP
    assert detector.detect_from_path("include/defs.hpp") == Language.CPP


def test_detect_from_shebang():
    """Verify extensionless script files with shebang headers are correctly identified."""
    detector = LanguageDetector()

    python_shebang = "#!/usr/bin/env python3\nprint('hello')\n"
    assert detector.detect_from_shebang(python_shebang) == Language.PYTHON

    node_shebang = "#!/usr/bin/node\nconsole.log('hello');\n"
    assert detector.detect_from_shebang(node_shebang) == Language.JAVASCRIPT

    unknown_shebang = "#!/bin/bash\necho hello\n"
    assert detector.detect_from_shebang(unknown_shebang) == Language.UNKNOWN


def test_disambiguate_c_header_pure_c():
    """Verify that a C-style header file is classified as Language.C."""
    detector = LanguageDetector()

    c_header = (
        "#ifndef DRIVER_H\n"
        "#define DRIVER_H\n"
        "#include <stdio.h>\n"
        "struct Config {\n"
        "    int id;\n"
        "    char name[32];\n"
        "};\n"
        "int init_driver(struct Config* cfg);\n"
        "#endif\n"
    )

    lang = detector.disambiguate_c_header(c_header)
    assert lang == Language.C

    unified_lang = detector.detect_language(file_path="include/driver.h", content=c_header)
    assert unified_lang == Language.C


def test_disambiguate_c_header_cpp_keywords():
    """Verify that a .h file containing C++ keywords is classified as Language.CPP."""
    detector = LanguageDetector()

    # 1. Header with class
    cpp_header_class = (
        "#pragma once\n"
        "class SecurityFilter {\n"
        "public:\n"
        "    SecurityFilter();\n"
        "    virtual ~SecurityFilter();\n"
        "};\n"
    )
    assert detector.detect_language(file_path="include/filter.h", content=cpp_header_class) == Language.CPP

    # 2. Header with template
    cpp_header_template = (
        "#pragma once\n"
        "template<typename T>\n"
        "T compute(T a, T b) { return a + b; }\n"
    )
    assert detector.detect_language(file_path="include/algo.h", content=cpp_header_template) == Language.CPP

    # 3. Header with STL include
    cpp_header_stl = (
        "#pragma once\n"
        "#include <iostream>\n"
        "#include <vector>\n"
    )
    assert detector.detect_language(file_path="include/types.h", content=cpp_header_stl) == Language.CPP


def test_unified_detect_language_fallbacks():
    """Verify detect_language combines path, content, and shebang seamlessly."""
    detector = default_language_detector

    # File path without content
    assert detector.detect_language(file_path="foo.py") == Language.PYTHON

    # Extensionless file with python shebang in content
    assert detector.detect_language(file_path="bin/cli_runner", content="#!/usr/bin/env python\npass") == Language.PYTHON

    # Unsupported file
    assert detector.detect_language(file_path="notes.txt", content="plain notes") == Language.UNKNOWN


def test_is_supported_language():
    """Verify supported language whitelist."""
    detector = LanguageDetector()
    assert detector.is_supported(Language.PYTHON) is True
    assert detector.is_supported(Language.JAVASCRIPT) is True
    assert detector.is_supported(Language.JAVA) is True
    assert detector.is_supported(Language.C) is True
    assert detector.is_supported(Language.CPP) is True
    assert detector.is_supported(Language.UNKNOWN) is False