import json
import pytest

from app.analysis.component_extractor import ComponentExtractor
from app.analysis.parser import parser_registry
from app.core.enums import Language
from app.core.models.code import CodeComponent


REQUIRED_METADATA_KEYS = {
    "language",
    "component_type",
    "line_count",
    "signature",
    "parameters",
    "parameter_count",
    "visibility",
    "is_async",
    "docstring",
    "decorators",
}


def test_us26_common_metadata_schema_consistency_across_all_languages():
    """Verify every extracted component across all 5 languages shares the exact same metadata keys."""
    samples = {
        Language.PYTHON: "def py_fn(a, b):\n    return a + b\n",
        Language.JAVASCRIPT: "function jsFn(a, b) { return a + b; }\n",
        Language.JAVA: "public class Main { public int javaFn(int a, int b) { return a + b; } }\n",
        Language.C: "int c_fn(int a, int b) { return a + b; }\n",
        Language.CPP: "int cpp_fn(int a, int b) { return a + b; }\n",
    }

    extractor = ComponentExtractor()
    for lang, code in samples.items():
        tree = parser_registry.parse_code(lang, code)
        components = extractor.extract_components(tree, code, language=lang)
        assert len(components) >= 1, f"No components extracted for {lang}"
        for comp in components:
            assert REQUIRED_METADATA_KEYS.issubset(set(comp.metadata.keys()))
            assert comp.metadata["language"] == lang.value
            assert isinstance(comp.metadata["parameters"], list)
            assert comp.metadata["parameter_count"] == len(comp.metadata["parameters"])


def test_us26_python_metadata_parameters_docstring_decorators_async():
    """Verify Python extraction populates parameters, docstrings, decorators, async, and visibility."""
    code = (
        "class AuthService:\n"
        "    @staticmethod\n"
        "    async def verify_token(token: str, strict: bool = True) -> bool:\n"
        '        """Validate user JWT token."""\n'
        "        return True\n"
        "\n"
        "    def _internal_check(self):\n"
        "        pass\n"
        "\n"
        "    def __secret_key(self):\n"
        "        pass\n"
    )
    tree = parser_registry.parse_code(Language.PYTHON, code)
    components = ComponentExtractor().extract_components(tree, code, language=Language.PYTHON)

    by_name = {c.name: c for c in components}
    verify = by_name["verify_token"]
    assert verify.metadata["is_async"] is True
    assert "@staticmethod" in verify.metadata["decorators"]
    assert verify.metadata["docstring"] == "Validate user JWT token."
    assert verify.metadata["parameter_count"] == 2
    assert "token: str" in verify.metadata["parameters"]
    assert "-> bool" in verify.metadata["signature"]
    assert verify.metadata["visibility"] == "public"

    assert by_name["_internal_check"].metadata["visibility"] == "protected"
    assert by_name["__secret_key"].metadata["visibility"] == "private"


def test_us26_javascript_metadata_async_and_arrow_functions():
    """Verify JavaScript async functions and class methods."""
    code = (
        "class ApiClient {\n"
        "  async fetchUser(userId, includeRoles) {\n"
        "    return null;\n"
        "  }\n"
        "}\n"
        "function helper(x) { return x * 2; }\n"
    )
    tree = parser_registry.parse_code(Language.JAVASCRIPT, code)
    components = ComponentExtractor().extract_components(tree, code, language=Language.JAVASCRIPT)
    by_name = {c.name: c for c in components}

    fetch_comp = by_name["fetchUser"]
    assert fetch_comp.metadata["is_async"] is True
    assert fetch_comp.metadata["parameters"] == ["userId", "includeRoles"]
    assert fetch_comp.metadata["parameter_count"] == 2


def test_us26_java_metadata_visibility_annotations_and_generics():
    """Verify Java visibility modifiers, annotations, and nested generic parameters."""
    code = (
        "public class OrderService {\n"
        "    @Override\n"
        "    public void process(Map<String, Object> payload, int retries) {\n"
        "    }\n"
        "\n"
        "    private boolean validate(String id) {\n"
        "        return true;\n"
        "    }\n"
        "}\n"
    )
    tree = parser_registry.parse_code(Language.JAVA, code)
    components = ComponentExtractor().extract_components(tree, code, language=Language.JAVA)
    by_name = {c.name: c for c in components}

    proc = by_name["process"]
    assert proc.metadata["visibility"] == "public"
    assert "@Override" in proc.metadata["decorators"]
    # Generic Map<String, Object> must NOT be split on the inner comma!
    assert proc.metadata["parameter_count"] == 2
    assert "Map<String, Object> payload" in proc.metadata["parameters"]

    val = by_name["validate"]
    assert val.metadata["visibility"] == "private"
    assert val.metadata["parameters"] == ["String id"]


def test_us26_c_and_cpp_metadata_pointers_and_templates():
    """Verify C pointer functions and C++ methods extract parameters and signatures cleanly."""
    c_code = "int* parse_buffer(char* buf, size_t len) { return 0; }\n"
    c_tree = parser_registry.parse_code(Language.C, c_code)
    c_comps = ComponentExtractor().extract_components(c_tree, c_code, language=Language.C)
    assert len(c_comps) == 1
    assert c_comps[0].name == "parse_buffer"
    assert c_comps[0].metadata["parameter_count"] == 2
    assert "char* buf" in c_comps[0].metadata["parameters"]

    cpp_code = (
        "class Engine {\n"
        "private:\n"
        "    void shutdown(int code) {}\n"
        "};\n"
    )
    cpp_tree = parser_registry.parse_code(Language.CPP, cpp_code)
    cpp_comps = ComponentExtractor().extract_components(cpp_tree, cpp_code, language=Language.CPP)
    by_name = {c.name: c for c in cpp_comps}
    assert "shutdown" in by_name
    assert by_name["shutdown"].metadata["parameters"] == ["int code"]


def test_us26_code_component_to_dict_serialization():
    """Verify CodeComponent.to_dict() produces valid JSON with normalized metadata."""
    comp = CodeComponent(
        name="run_audit",
        component_type="function",
        start_line=10,
        end_line=25,
        source_content="def run_audit(project_id): pass",
        file_path="app/services/audit.py",
        language=Language.PYTHON,
        metadata={"parameters": ["project_id"], "is_async": False},
    )
    data = comp.to_dict()
    assert data["line_count"] == 16
    assert data["metadata"]["parameter_count"] == 1
    assert json.loads(json.dumps(data))["name"] == "run_audit"


def test_us26_empty_tree_graceful_handling():
    """Verify ComponentExtractor returns empty list safely on None tree."""
    extractor = ComponentExtractor()
    assert extractor.extract_components(None, "", language=Language.PYTHON) == []