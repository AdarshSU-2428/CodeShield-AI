from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time
from unittest.mock import MagicMock
import pytest

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.component_extractor import ComponentExtractor
from app.analysis.cross_file import CrossFileContextResolver
from app.analysis.parser import parser_registry
from app.analysis.quality_analyzer import ArchitecturalSmellDetector
from app.core.enums import FindingCategory, Language, Severity
from app.core.interfaces.llm import LLMClient, LLMResponse
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.infrastructure.llm import GroqLLMClient
from app.services.audit_service import AuditService


class VirtualFS(LocalFileSystem):
    def __init__(self, files=None):
        self._files = files or {}

    def exists(self, path) -> bool:
        norm = Path(path).as_posix()
        return norm in self._files or str(path) in self._files

    def read_text(self, path, encoding="utf-8") -> str:
        norm = Path(path).as_posix()
        if norm in self._files:
            return self._files[norm]
        if str(path) in self._files:
            return self._files[str(path)]
        raise FileNotFoundError(str(path))


def test_stress_us22_chaotic_cloud_null_and_empty_completions():
    """Stress test GroqLLMClient against None completions, empty choices, and missing message objects."""
    mock_sdk = MagicMock()

    # Case 1: completion is None
    mock_sdk.chat.completions.create.return_value = None
    client = GroqLLMClient(api_key="gsk_test", max_retries=0, client=mock_sdk)
    with pytest.raises(RuntimeError, match="empty or malformed"):
        client.chat([{"role": "user", "content": "hi"}])

    # Case 2: completion.choices is empty list []
    mock_sdk.chat.completions.create.return_value = MagicMock(choices=[])
    with pytest.raises(RuntimeError, match="empty or malformed"):
        client.chat([{"role": "user", "content": "hi"}])

    # Case 3: choice.message is None
    mock_sdk.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=None, finish_reason="stop")],
        model="llama-3.3-70b-versatile",
    )
    resp = client.chat([{"role": "user", "content": "hi"}])
    assert resp.content == ""


def test_stress_us22_adversarial_malformed_json_and_boolean_lines():
    """Stress test _parse_findings with boolean lines, NaNs, negative lines, and non-list payloads."""
    adversarial_payloads = [
        None,
        "string_not_dict",
        12345,
        {"vulnerabilities": "not_a_list"},
        {
            "vulnerabilities": [
                {
                    "title": 999,
                    "start_line": True,  # bool is subclass of int in Python!
                    "end_line": -50,
                    "start_column": float("nan"),
                    "severity": None,
                    "confidence": None,
                    "evidence": ["list", "instead", "of", "dict"],
                    "remediation_code": 123,
                    "remediation_steps": None,
                    "related_files": "not_a_list",
                }
            ]
        },
    ]

    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    analyzer = AIVulnerabilityAnalyzer(llm_client=mock_llm)
    sf = SourceFile(file_path="a.py", relative_path="a.py", content="x = 1\n", language=Language.PYTHON)

    for payload in adversarial_payloads:
        findings = analyzer._parse_findings(payload, sf)
        assert isinstance(findings, list)
        for f in findings:
            assert f.start_line >= 1
            assert f.end_line >= f.start_line
            assert isinstance(f.title, str)


def test_stress_us24_50_file_enterprise_dependency_graph_scale():
    """Stress test DependencyGraph across a 50-file layered enterprise codebase."""
    files = []
    # Layer 0: 10 core utils
    for i in range(10):
        files.append(SourceFile(
            file_path=f"core/util_{i}.py",
            relative_path=f"core/util_{i}.py",
            content=f"def util_{i}(): return {i}\n",
            language=Language.PYTHON,
        ))
    # Layer 1: 20 services importing core utils
    for i in range(20):
        files.append(SourceFile(
            file_path=f"services/svc_{i}.py",
            relative_path=f"services/svc_{i}.py",
            content=f"from core.util_{i % 10} import util_{i % 10}\n",
            language=Language.PYTHON,
        ))
    # Layer 2: 20 controllers importing services
    for i in range(20):
        files.append(SourceFile(
            file_path=f"api/ctrl_{i}.py",
            relative_path=f"api/ctrl_{i}.py",
            content=f"from services.svc_{i} import *\n",
            language=Language.PYTHON,
        ))

    start = time.perf_counter()
    graph = CrossFileContextResolver().build_dependency_graph(files)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert len(graph.nodes) == 50
    impacted = graph.get_impacted_files("core/util_0.py")
    assert len(impacted) >= 4  # svc_0, svc_10, ctrl_0, ctrl_10


def test_stress_us24_cyclic_diamond_impact_no_infinite_loop():
    """Verify BFS impact analysis terminates cleanly on a 10-node strongly connected cycle."""
    files = []
    for i in range(10):
        nxt = (i + 1) % 10
        files.append(SourceFile(
            file_path=f"ring/node_{i}.py",
            relative_path=f"ring/node_{i}.py",
            content=f"import ring.node_{nxt}\n",
            language=Language.PYTHON,
        ))

    graph = CrossFileContextResolver().build_dependency_graph(files)
    impacted = graph.get_impacted_files("ring/node_0.py")
    assert len(impacted) == 9
    assert "ring/node_0.py" not in impacted


def test_stress_us25_mixed_architectural_smell_storm():
    """Verify all 5 architectural smells trigger accurately in a single chaotic repository."""
    files = [
        # Circular A <-> B
        SourceFile(file_path="chaos/a.py", relative_path="chaos/a.py", content="import chaos.b\n", language=Language.PYTHON),
        SourceFile(file_path="chaos/b.py", relative_path="chaos/b.py", content="import chaos.a\n", language=Language.PYTHON),
        # God class (260 lines)
        SourceFile(
            file_path="chaos/god.py",
            relative_path="chaos/god.py",
            content="\n".join(f"def fn_{i}(): pass" for i in range(260)),
            language=Language.PYTHON,
        ),
        # Orphaned file
        SourceFile(file_path="chaos/dead.py", relative_path="chaos/dead.py", content="x = 1\n", language=Language.PYTHON),
    ]
    # Hub with 5 dependencies
    for i in range(5):
        files.append(SourceFile(file_path=f"chaos/d{i}.py", relative_path=f"chaos/d{i}.py", content="pass\n", language=Language.PYTHON))
    files.append(SourceFile(
        file_path="chaos/hub.py",
        relative_path="chaos/hub.py",
        content="\n".join(f"import chaos.d{i}" for i in range(5)),
        language=Language.PYTHON,
    ))

    findings = ArchitecturalSmellDetector(max_fan_out=5, max_god_class_lines=250).evaluate_architecture(files)
    titles = " | ".join(f.title for f in findings)
    assert "Circular Dependency" in titles
    assert "God Class" in titles
    assert "Excessive Fan-Out" in titles
    assert "Orphaned" in titles


def test_stress_us26_polyglot_complex_signatures_and_nested_generics():
    """Stress test ComponentExtractor with deeply nested generics, multiline Python hints, and pointers."""
    py_code = (
        "async def complex_handler(\n"
        "    user_id: int,\n"
        "    config: dict[str, list[int]],\n"
        ") -> tuple[bool, str]:\n"
        '    """Multi-line typed async signature."""\n'
        "    return True, 'ok'\n"
    )
    py_tree = parser_registry.parse_code(Language.PYTHON, py_code)
    py_comps = ComponentExtractor().extract_components(py_tree, py_code, language=Language.PYTHON)
    assert len(py_comps) == 1
    assert py_comps[0].metadata["is_async"] is True
    assert py_comps[0].metadata["parameter_count"] == 2
    assert "-> tuple[bool, str]" in py_comps[0].metadata["signature"]

    java_code = (
        "public class Repo {\n"
        "    private Map<String, List<Set<Integer>>> query(Map<String, Object> filters, int limit) {\n"
        "        return null;\n"
        "    }\n"
        "}\n"
    )
    java_tree = parser_registry.parse_code(Language.JAVA, java_code)
    java_comps = ComponentExtractor().extract_components(java_tree, java_code, language=Language.JAVA)
    q = next(c for c in java_comps if c.name == "query")
    assert q.metadata["visibility"] == "private"
    assert q.metadata["parameter_count"] == 2
    assert "Map<String, Object> filters" in q.metadata["parameters"]


def test_stress_sprint5_end_to_end_cloud_outage_with_architectural_smells():
    """
    Full Sprint 5 integration test:
    Cloud LLM suffers a complete 503 outage while AuditService runs on a multi-file repo
    with security bugs + architectural smells. System must not crash and must surface all findings + warnings.
    """
    f1 = SourceFile(
        file_path="svc/auth.py",
        relative_path="svc/auth.py",
        content="import os\nimport svc.db\ndef login(cmd):\n    os.system(cmd)\n",
        language=Language.PYTHON,
    )
    f2 = SourceFile(
        file_path="svc/db.py",
        relative_path="svc/db.py",
        content="import svc.auth\ndef run_sql(q):\n    pass\n",
        language=Language.PYTHON,
    )
    f3 = SourceFile(
        file_path="svc/orphan.py",
        relative_path="svc/orphan.py",
        content="unused = True\n",
        language=Language.PYTHON,
    )

    fs = VirtualFS({
        f1.file_path.as_posix(): f1.content,
        f2.file_path.as_posix(): f2.content,
        f3.file_path.as_posix(): f3.content,
    })

    class Scanner:
        def scan_project(self, project):
            return [f1, f2, f3]

    broken_llm = MagicMock()
    broken_llm.is_available.return_value = True
    broken_llm.chat_json.side_effect = ConnectionError("503 Cloud Outage")
    ai_analyzer = AIVulnerabilityAnalyzer(llm_client=broken_llm)

    service = AuditService(scanner=Scanner(), filesystem=fs, ai_analyzer=ai_analyzer)
    project = Project(name="Sprint5Chaos", root_path=".")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    assert len(report.warnings) == 3  # 1 AI warning per file
    assert "AI warning(s)" in report.summary
    assert any(f.category == FindingCategory.SECURITY for f in report.findings)
    assert any(f.category == FindingCategory.ARCHITECTURE for f in report.findings)
    assert json.loads(json.dumps(report.to_dict()))["warnings"] == report.warnings


def test_stress_us24_massive_100_file_dag_transitive_ripple_performance():
    """Stress test: 100-file 4-tier DAG. Transitive ripple impact and coupling metrics under scale."""
    files = []
    # Tier 0: 10 core configs
    for i in range(10):
        files.append(SourceFile(
            file_path=f"core/cfg_{i}.py",
            relative_path=f"core/cfg_{i}.py",
            content=f"CONFIG_{i} = {i}\n",
            language=Language.PYTHON,
        ))
    # Tier 1: 30 domain models importing configs
    for i in range(30):
        cfg_idx = i % 10
        files.append(SourceFile(
            file_path=f"models/model_{i}.py",
            relative_path=f"models/model_{i}.py",
            content=f"from core.cfg_{cfg_idx} import CONFIG_{cfg_idx}\n",
            language=Language.PYTHON,
        ))
    # Tier 2: 30 services importing models
    for i in range(30):
        files.append(SourceFile(
            file_path=f"services/service_{i}.py",
            relative_path=f"services/service_{i}.py",
            content=f"from models.model_{i} import *\n",
            language=Language.PYTHON,
        ))
    # Tier 3: 30 controllers importing services
    for i in range(30):
        files.append(SourceFile(
            file_path=f"api/ctrl_{i}.py",
            relative_path=f"api/ctrl_{i}.py",
            content=f"from services.service_{i} import *\n",
            language=Language.PYTHON,
        ))

    start = time.perf_counter()
    graph = CrossFileContextResolver().build_dependency_graph(files)
    elapsed_build = time.perf_counter() - start

    assert elapsed_build < 1.0
    assert len(graph.nodes) == 100

    # Changing core/cfg_0.py should ripple down models, services, and controllers
    start_impact = time.perf_counter()
    impacted = graph.get_impacted_files("core/cfg_0.py")
    elapsed_impact = time.perf_counter() - start_impact

    assert elapsed_impact < 0.2
    # model_0, model_10, model_20, and their corresponding services and controllers = 9 files
    assert len(impacted) == 9
    assert "models/model_0.py" in impacted
    assert "services/service_0.py" in impacted
    assert "api/ctrl_0.py" in impacted

    # Metric checks
    cfg_metrics = graph.get_coupling_metrics("core/cfg_0.py")
    assert cfg_metrics["fan_in"] == 3
    assert cfg_metrics["fan_out"] == 0
    assert cfg_metrics["instability"] == 0.0

    ctrl_metrics = graph.get_coupling_metrics("api/ctrl_0.py")
    assert ctrl_metrics["fan_in"] == 0
    assert ctrl_metrics["fan_out"] == 1
    assert ctrl_metrics["instability"] == 1.0


def test_stress_us24_windows_paths_spaces_and_mixed_slashes_resolution():
    """Stress test: Windows mixed slashes, spaces in folder/file names, and relative lookups."""
    f1 = SourceFile(
        file_path="src\\core services\\database manager.py",
        relative_path="src\\core services\\database manager.py",
        content="class DatabaseManager:\n    pass\n",
        language=Language.PYTHON,
    )
    f2 = SourceFile(
        file_path="src/api controllers/auth controller.py",
        relative_path="src/api controllers/auth controller.py",
        content="from src.core_services.database_manager import DatabaseManager\n",
        language=Language.PYTHON,
    )
    f3 = SourceFile(
        file_path="src\\utils\\helper tool.py",
        relative_path="src\\utils\\helper tool.py",
        content="from src.core_services.database_manager import DatabaseManager\n",
        language=Language.PYTHON,
    )

    graph = CrossFileContextResolver().build_dependency_graph([f1, f2, f3])
    assert len(graph.nodes) == 3

    # Query using forward slash, backslash, and relative path
    dependents = graph.get_dependents("src/core services/database manager.py")
    assert len(dependents) == 2
    assert "src/api controllers/auth controller.py" in dependents
    assert "src/utils/helper tool.py" in dependents

    impacted = graph.get_impacted_files("src\\core services\\database manager.py")
    assert len(impacted) == 2

    # Query using just filename
    deps_by_name = graph.get_dependents("database manager.py")
    assert len(deps_by_name) == 2


def test_stress_us25_pathological_overlapping_multicycle_circular_mesh():
    """Stress test: 12-file mesh containing 4 overlapping circular dependency cycles."""
    # Cycle 1: c_a -> c_b -> c_c -> c_a
    # Cycle 2: c_b -> c_d -> c_e -> c_b
    # Cycle 3: c_c -> c_f -> c_g -> c_c
    # Cycle 4: c_d -> c_f -> c_d
    files = [
        SourceFile(file_path="mesh/c_a.py", relative_path="mesh/c_a.py", content="import mesh.c_b\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/c_b.py", relative_path="mesh/c_b.py", content="import mesh.c_c\nimport mesh.c_d\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/c_c.py", relative_path="mesh/c_c.py", content="import mesh.c_a\nimport mesh.c_f\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/c_d.py", relative_path="mesh/c_d.py", content="import mesh.c_e\nimport mesh.c_f\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/c_e.py", relative_path="mesh/c_e.py", content="import mesh.c_b\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/c_f.py", relative_path="mesh/c_f.py", content="import mesh.c_g\nimport mesh.c_d\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/c_g.py", relative_path="mesh/c_g.py", content="import mesh.c_c\n", language=Language.PYTHON),
        # Extra neutral non-cyclic files in mesh
        SourceFile(file_path="mesh/neutral1.py", relative_path="mesh/neutral1.py", content="import mesh.c_a\n", language=Language.PYTHON),
        SourceFile(file_path="mesh/neutral2.py", relative_path="mesh/neutral2.py", content="import mesh.c_b\n", language=Language.PYTHON),
    ]

    start = time.perf_counter()
    detector = ArchitecturalSmellDetector()
    findings = detector.detect_circular_dependencies(files)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.2
    assert len(findings) >= 3  # At least 3-4 distinct cycles detected
    # Ensure findings are valid and deduplicated
    reported_cycles = [f.evidence.get("cycle_path") for f in findings]
    assert len(reported_cycles) == len(set(reported_cycles))


def test_stress_us25_god_class_boundaries_and_comment_minified_edge_cases():
    """Stress test: God class line boundary conditions (249 vs 250), comment-heavy files, and minified JS."""
    # Exact boundary 249 lines (should NOT trigger)
    f_249 = SourceFile(
        file_path="boundary/safe_249.py",
        relative_path="boundary/safe_249.py",
        content="\n".join(f"x_{i} = {i}" for i in range(249)),
        language=Language.PYTHON,
    )
    # Exact boundary 250 lines (SHOULD trigger)
    f_250 = SourceFile(
        file_path="boundary/god_250.py",
        relative_path="boundary/god_250.py",
        content="\n".join(f"x_{i} = {i}" for i in range(250)),
        language=Language.PYTHON,
    )
    # Minified 1-line JS with huge content (1 line, shouldn't trigger line count god class)
    f_minified = SourceFile(
        file_path="boundary/bundle.min.js",
        relative_path="boundary/bundle.min.js",
        content="function a(){};" * 500,
        language=Language.JAVASCRIPT,
    )
    # Polyglot Java God Class (350 lines)
    f_java_god = SourceFile(
        file_path="boundary/HugeService.java",
        relative_path="boundary/HugeService.java",
        content="public class HugeService {\n" + "\n".join(f"    public void m{i}() {{}}" for i in range(350)) + "\n}",
        language=Language.JAVA,
    )

    detector = ArchitecturalSmellDetector(max_god_class_lines=250)
    findings = detector.detect_god_classes([f_249, f_250, f_minified, f_java_god])

    god_files = [Path(f.relative_file_path or f.file_path).name for f in findings]
    assert "god_250.py" in god_files
    assert "HugeService.java" in god_files
    assert "safe_249.py" not in god_files
    assert "bundle.min.js" not in god_files


def test_stress_us26_polyglot_extreme_cpp_templates_and_js_destructuring_closures():
    """Stress test: Complex C++ template pointers, JS exported arrow destructuring, and Python stacked decorators."""
    # 1. C++ Template with pointer-to-pointers and static inline methods
    cpp_code = (
        "template<typename K, typename V = std::vector<K*>, int MaxDepth = 10>\n"
        "class ConcurrentHashMap {\n"
        "public:\n"
        "    static inline const unsigned long long int** calculate_matrix_stride(const int* const* matrix, size_t n) {\n"
        "        return nullptr;\n"
        "    }\n"
        "};\n"
    )
    cpp_tree = parser_registry.parse_code(Language.CPP, cpp_code)
    cpp_comps = ComponentExtractor().extract_components(cpp_tree, cpp_code, language=Language.CPP)
    assert len(cpp_comps) == 2
    cls_comp = next(c for c in cpp_comps if c.component_type == "class")
    method_comp = next(c for c in cpp_comps if c.component_type == "method")
    assert cls_comp.name == "ConcurrentHashMap"
    assert method_comp.name == "calculate_matrix_stride"
    assert method_comp.metadata["parameter_count"] == 2
    assert "const int* const* matrix" in method_comp.metadata["parameters"]

    # 2. Modern JS Exported Arrow Function with Object Pattern Destructuring
    js_code = (
        "export const processPayload = async ({ user, options }, logger) => {\n"
        "    return true;\n"
        "};\n"
    )
    js_tree = parser_registry.parse_code(Language.JAVASCRIPT, js_code)
    js_comps = ComponentExtractor().extract_components(js_tree, js_code, language=Language.JAVASCRIPT)
    assert len(js_comps) == 1
    assert js_comps[0].name == "processPayload"
    assert js_comps[0].metadata["is_async"] is True
    assert js_comps[0].metadata["parameter_count"] == 2
    assert "{ user, options }" in js_comps[0].metadata["parameters"]

    # 3. Python Function with 3 stacked decorators and *args, **kwargs
    py_code = (
        "@lru_cache(maxsize=128)\n"
        "@deprecated(reason='Use v2')\n"
        "@validate_inputs\n"
        "async def complex_worker(*args: int, **kwargs: str) -> None:\n"
        '    """Process worker tasks."""\n'
        "    pass\n"
    )
    py_tree = parser_registry.parse_code(Language.PYTHON, py_code)
    py_comps = ComponentExtractor().extract_components(py_tree, py_code, language=Language.PYTHON)
    assert len(py_comps) == 1
    assert len(py_comps[0].metadata["decorators"]) == 3
    assert py_comps[0].metadata["is_async"] is True
    assert py_comps[0].metadata["docstring"] == "Process worker tasks."


def test_stress_us22_cloudflare_gateway_timeout_and_raw_html_resilience():
    """Stress test: LLM returns Cloudflare 524 HTML error, raw text, or null responses without crashing."""
    mock_sdk = MagicMock()
    # Case 1: HTML error string inside choice message content
    mock_sdk.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="<html><head><title>524 Gateway Timeout</title></head><body>Cloudflare Error</body></html>"))],
        model="llama-3.3-70b-versatile",
    )
    client = GroqLLMClient(api_key="gsk_test", max_retries=0, client=mock_sdk)
    with pytest.raises(ValueError, match="Failed to parse LLM response as JSON"):
        client.chat_json([{"role": "user", "content": "analyze"}])

    # Case 2: AIVulnerabilityAnalyzer recovers cleanly from HTML error
    analyzer = AIVulnerabilityAnalyzer(llm_client=client)
    sf = SourceFile(file_path="test.py", relative_path="test.py", content="x = 1\n", language=Language.PYTHON)
    findings = analyzer.analyze_file(sf)
    assert findings == []
    assert len(analyzer.warnings) == 1
    assert "Failed to parse LLM response" in analyzer.warnings[0]

    # Case 3: Empty string response
    mock_sdk.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="   \n\t   "))],
        model="llama-3.3-70b-versatile",
    )
    findings_empty = analyzer.analyze_file(sf)
    assert findings_empty == []


def test_stress_sprint5_high_concurrency_multithreaded_graph_and_ast_extraction():
    """Stress test: 8 concurrent worker threads building dependency graphs and extracting AST components."""
    files = [
        SourceFile(file_path=f"thread/mod_{i}.py", relative_path=f"thread/mod_{i}.py", content=f"import thread.mod_{(i+1)%10}\ndef fn_{i}(): return {i}\n", language=Language.PYTHON)
        for i in range(10)
    ]

    resolver = CrossFileContextResolver()
    extractor = ComponentExtractor()

    def worker_task(thread_id):
        # 1. Build graph
        graph = resolver.build_dependency_graph(files)
        assert len(graph.nodes) == 10
        # 2. Transitive impact
        impacted = graph.get_impacted_files("thread/mod_0.py")
        assert len(impacted) == 9
        # 3. Component extraction
        tree = parser_registry.parse_code(Language.PYTHON, files[0].content)
        comps = extractor.extract_components(tree, files[0].content, language=Language.PYTHON)
        assert len(comps) == 1
        return thread_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_task, t) for t in range(8)]
        results = [f.result() for f in futures]

    assert len(results) == 8


def test_stress_sprint5_cascading_chaos_multi_failure_audit_pipeline():
    """
    Cascading Chaos Integration:
    - 1 file has syntax errors
    - 2 files have circular dependencies
    - 1 file is a 300-line God class
    - 1 file is an unreferenced orphan module
    - 1 file has a security command injection
    - LLM fails with a 503 outage
    Verify full audit pipeline completes, collects all warnings & smells, and serializes cleanly.
    """
    f_syntax = SourceFile(file_path="chaos/broken.py", relative_path="chaos/broken.py", content="def invalid_syntax(\n", language=Language.PYTHON)
    f_circ_a = SourceFile(file_path="chaos/circ_a.py", relative_path="chaos/circ_a.py", content="import chaos.circ_b\n", language=Language.PYTHON)
    f_circ_b = SourceFile(file_path="chaos/circ_b.py", relative_path="chaos/circ_b.py", content="import chaos.circ_a\n", language=Language.PYTHON)
    f_god = SourceFile(file_path="chaos/god.py", relative_path="chaos/god.py", content="\n".join(f"def fn_{i}(): pass" for i in range(300)), language=Language.PYTHON)
    f_orphan = SourceFile(file_path="chaos/orphan.py", relative_path="chaos/orphan.py", content="x = 42\n", language=Language.PYTHON)
    f_sec = SourceFile(file_path="chaos/vuln.py", relative_path="chaos/vuln.py", content="import os\ndef run(c):\n    os.system(c)\n", language=Language.PYTHON)

    all_chaos_files = [f_syntax, f_circ_a, f_circ_b, f_god, f_orphan, f_sec]

    fs = VirtualFS({sf.file_path.as_posix(): sf.content for sf in all_chaos_files})

    class ChaosScanner:
        def scan_project(self, project):
            return all_chaos_files

    broken_llm = MagicMock()
    broken_llm.is_available.return_value = True
    broken_llm.chat_json.side_effect = ConnectionError("503 Service Unavailable")
    ai_analyzer = AIVulnerabilityAnalyzer(llm_client=broken_llm)

    service = AuditService(scanner=ChaosScanner(), filesystem=fs, ai_analyzer=ai_analyzer)
    project = Project(name="UltimateChaos", root_path=".")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    # 1. Pipeline finished successfully without crashing
    assert report.summary is not None
    # 2. Collected AI degradation warnings for files
    assert len(report.warnings) > 0
    # 3. Collected architectural smells (Circular, God class, Orphan)
    arch_titles = [f.title for f in report.findings if f.category == FindingCategory.ARCHITECTURE]
    assert any("Circular" in t for t in arch_titles)
    assert any("God Class" in t for t in arch_titles)
    assert any("Orphaned" in t for t in arch_titles)
    # 4. Collected static security findings (os.system command injection)
    sec_titles = [f.title for f in report.findings if f.category == FindingCategory.SECURITY]
    assert any("Command Injection" in t or "Execution" in t for t in sec_titles)
    # 5. Report serializes to valid JSON with warnings
    dumped = report.to_dict()
    assert dumped["job_id"] == job.job_id
    assert "warnings" in dumped
    assert len(dumped["warnings"]) == len(report.warnings)

