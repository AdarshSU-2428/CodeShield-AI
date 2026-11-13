from pathlib import Path
import pytest

from app.core.enums import Language, PatchStatus
from app.core.models.patch import Patch, PatchDiff
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.applier import PatchApplier
from app.patches.validator import PatchValidator
from app.services.patch_service import PatchService


class VirtualFS(LocalFileSystem):
    """In-memory virtual filesystem for pre-flight patch testing."""

    def __init__(self, files=None):
        self._files = files or {}

    def exists(self, path) -> bool:
        norm = Path(path).as_posix().lower()
        return any(norm.endswith(k.lower()) or k.lower().endswith(norm) for k in self._files)

    def read_text(self, path, encoding="utf-8") -> str:
        norm = Path(path).as_posix().lower()
        for k, v in self._files.items():
            if norm.endswith(k.lower()) or k.lower().endswith(norm):
                return v
        raise FileNotFoundError(str(path))

    def write_text(self, path, content: str, encoding="utf-8") -> None:
        norm = Path(path).as_posix().lower()
        self._files[norm] = content


def test_us21_python_syntax_validation_catches_line_and_column_errors():
    """Verify Python syntax errors (both grammar and semantic bytecode errors) return exact coordinates."""
    validator = PatchValidator()

    # 1. Incomplete/unclosed bracket
    broken_py = "def calculate_total(items):\n    return sum(items\n"
    diag = validator.get_syntax_diagnostics(broken_py, language=Language.PYTHON)

    assert diag["is_valid"] is False
    assert diag["language"] == "python"
    assert diag["line"] == 2
    assert "SyntaxError" in diag["error_message"]

    # 2. Return outside function (semantic syntax error)
    return_outside = "x = 10\nreturn x\n"
    diag2 = validator.get_syntax_diagnostics(return_outside, language=Language.PYTHON)
    assert diag2["is_valid"] is False
    assert "return" in diag2["error_message"].lower()


def test_us21_javascript_syntax_validation_catches_tree_sitter_diagnostics():
    """Verify JavaScript Tree-sitter error node traversal locates line and column."""
    validator = PatchValidator()

    broken_js = (
        "function handleRequest(req, res) {\n"
        "    if (req.user == null {\n"
        "        return res.status(401).send();\n"
        "    }\n"
        "}\n"
    )
    diag = validator.get_syntax_diagnostics(broken_js, language=Language.JAVASCRIPT)

    assert diag["is_valid"] is False
    assert diag["language"] == "javascript"
    assert diag["line"] == 2
    assert "syntax error at line 2" in diag["error_message"].lower()


def test_us21_java_syntax_validation_catches_errors():
    """Verify Java syntax validation detects unclosed braces or invalid member definitions."""
    validator = PatchValidator()

    broken_java = (
        "public class AuthService {\n"
        "    public boolean verify(String token) {\n"
        "        if (token == null) return false;\n"
        "    // Missing closing brace for method and class\n"
    )
    diag = validator.get_syntax_diagnostics(broken_java, language=Language.JAVA)

    assert diag["is_valid"] is False
    assert diag["language"] == "java"
    assert diag["line"] >= 3


def test_us21_c_and_cpp_syntax_validation_catches_errors():
    """Verify C and C++ syntax errors return diagnostic coordinates."""
    validator = PatchValidator()

    broken_c = (
        "#include <stdio.h>\n"
        "int main() {\n"
        "    printf(\"Hello, world!\")\n"   # Missing semicolon
        "    return 0;\n"
        "}\n"
    )
    diag = validator.get_syntax_diagnostics(broken_c, language=Language.C)

    assert diag["is_valid"] is False
    assert diag["language"] == "c"
    assert diag["line"] >= 3


def test_us21_patch_service_validate_patch_syntax_api():
    """Verify PatchService.validate_patch_syntax() returns structured diagnostics for a patch."""
    file_path = "src/auth.py"
    orig_code = "def authenticate():\n    return True\n"
    broken_patch_code = "def authenticate():\n    return True unexpected_token\n"

    fs = VirtualFS({file_path: orig_code})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(file_path=file_path, modified_code=broken_patch_code)
    diag = svc.validate_patch_syntax(patch.patch_id)

    assert diag["is_valid"] is False
    assert diag["line"] == 2
    assert "SyntaxError" in diag["error_message"]


def test_us21_patch_applier_rejects_corrupted_patch_without_touching_disk():
    """
    US 21 Critical Gate: Ensure PatchApplier refuses to apply patches with syntax errors,
    protecting the underlying file on disk from corruption.
    """
    file_path = Path("core/engine.py").resolve()
    orig_code = "def start_engine():\n    print('Engine started')\n"
    corrupt_mod_code = "def start_engine():\n    print('broken syntax(\n"

    fs = VirtualFS({file_path.as_posix(): orig_code})
    validator = PatchValidator(filesystem=fs)
    applier = PatchApplier(validator=validator, filesystem=fs)

    diff = PatchDiff(raw_diff="")
    patch = Patch(
        file_path=file_path,
        original_code=orig_code,
        modified_code=corrupt_mod_code,
        diff=diff,
    )

    with pytest.raises(ValueError, match="Pre-application syntax validation failed"):
        applier.apply_patch(patch)

    # Verify target file on disk was NOT mutated or corrupted!
    disk_content = fs.read_text(file_path)
    assert disk_content == orig_code
    assert patch.status == PatchStatus.FAILED


def test_us21_valid_polyglot_patches_pass_syntax_validation():
    """Verify valid Python, JS, Java, and C code snippets pass virtual syntax validation cleanly."""
    validator = PatchValidator()

    valid_snippets = [
        ("def add(a: int, b: int) -> int:\n    return a + b\n", Language.PYTHON),
        ("const multiply = (x, y) => x * y;\n", Language.JAVASCRIPT),
        ("public class MathUtils {\n    public static int square(int x) { return x * x; }\n}\n", Language.JAVA),
        ("int add(int a, int b) {\n    return a + b;\n}\n", Language.C),
    ]

    for code, lang in valid_snippets:
        diag = validator.get_syntax_diagnostics(code, language=lang)
        assert diag["is_valid"] is True, f"Failed for {lang.value}: {diag['error_message']}"
        assert diag["error_message"] is None