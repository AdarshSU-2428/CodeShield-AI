import json
import pytest

from app.analysis.cross_file import CrossFileContextResolver, DependencyGraph
from app.core.enums import Language
from app.core.models.code import SourceFile


def test_us24_build_dependency_graph_python_imports():
    """Verify build_dependency_graph captures direct import relationships across Python files."""
    f_db = SourceFile(
        file_path="app/db.py",
        relative_path="app/db.py",
        content="def connect(): pass\n",
        language=Language.PYTHON,
    )
    f_routes = SourceFile(
        file_path="app/routes.py",
        relative_path="app/routes.py",
        content="from app.db import connect\ndef get_users(): connect()\n",
        language=Language.PYTHON,
    )
    f_main = SourceFile(
        file_path="app/main.py",
        relative_path="app/main.py",
        content="import app.routes\n",
        language=Language.PYTHON,
    )

    resolver = CrossFileContextResolver()
    graph = resolver.build_dependency_graph([f_db, f_routes, f_main])

    assert len(graph.nodes) == 3
    assert len(graph.edges) >= 2
    assert "app/db.py" in graph.get_dependencies("app/routes.py")
    assert "app/routes.py" in graph.get_dependents("app/db.py")
    assert "app/routes.py" in graph.get_dependencies("app/main.py")


def test_us24_coupling_metrics_fan_in_fan_out_instability():
    """Verify Fan-In (Ca), Fan-Out (Ce), and Instability (I = Ce / (Ca + Ce)) metrics."""
    f_core = SourceFile(
        file_path="src/core.py",
        relative_path="src/core.py",
        content="def core_fn(): pass\n",
        language=Language.PYTHON,
    )
    f_mid = SourceFile(
        file_path="src/mid.py",
        relative_path="src/mid.py",
        content="from src.core import core_fn\n",
        language=Language.PYTHON,
    )
    f_top = SourceFile(
        file_path="src/top.py",
        relative_path="src/top.py",
        content="from src.mid import core_fn\n",
        language=Language.PYTHON,
    )

    graph = CrossFileContextResolver().build_dependency_graph([f_core, f_mid, f_top])

    core_metrics = graph.get_coupling_metrics("src/core.py")
    assert core_metrics["fan_in"] == 1
    assert core_metrics["fan_out"] == 0
    assert core_metrics["instability"] == 0.0  # Maximally stable core

    mid_metrics = graph.get_coupling_metrics("src/mid.py")
    assert mid_metrics["fan_in"] == 1
    assert mid_metrics["fan_out"] == 1
    assert mid_metrics["instability"] == 0.5

    top_metrics = graph.get_coupling_metrics("src/top.py")
    assert top_metrics["fan_in"] == 0
    assert top_metrics["fan_out"] == 1
    assert top_metrics["instability"] == 1.0  # Maximally unstable entrypoint


def test_us24_transitive_impact_analysis():
    """Verify get_impacted_files traces all upstream transitive dependents."""
    f_crypto = SourceFile(file_path="src/crypto.py", relative_path="src/crypto.py", content="def hash_pw(): pass\n", language=Language.PYTHON)
    f_auth = SourceFile(file_path="src/auth.py", relative_path="src/auth.py", content="from src.crypto import hash_pw\n", language=Language.PYTHON)
    f_api = SourceFile(file_path="src/api.py", relative_path="src/api.py", content="from src.auth import hash_pw\n", language=Language.PYTHON)
    f_app = SourceFile(file_path="src/app.py", relative_path="src/app.py", content="import src.api\n", language=Language.PYTHON)

    graph = CrossFileContextResolver().build_dependency_graph([f_crypto, f_auth, f_api, f_app])
    impacted = graph.get_impacted_files("src/crypto.py")

    assert set(impacted) == {"src/auth.py", "src/api.py", "src/app.py"}


def test_us24_hub_and_orphaned_module_detection():
    """Verify detection of high fan-out hub modules and zero fan-in orphaned modules."""
    targets = [
        SourceFile(file_path=f"mod/u{i}.py", relative_path=f"mod/u{i}.py", content=f"def fn{i}(): pass\n", language=Language.PYTHON)
        for i in range(6)
    ]
    hub = SourceFile(
        file_path="mod/hub.py",
        relative_path="mod/hub.py",
        content="\n".join(f"import mod.u{i}" for i in range(6)),
        language=Language.PYTHON,
    )
    orphan = SourceFile(file_path="mod/dead_code.py", relative_path="mod/dead_code.py", content="def unused(): pass\n", language=Language.PYTHON)

    graph = CrossFileContextResolver().build_dependency_graph(targets + [hub, orphan])

    hubs = graph.get_hub_modules(min_fan_out=5)
    assert any(h["relative_path"] == "mod/hub.py" for h in hubs)

    orphans = graph.get_orphaned_modules()
    orphan_paths = {o["relative_path"] for o in orphans}
    assert "mod/dead_code.py" in orphan_paths


def test_us24_polyglot_dependency_graph_js_and_c():
    """Verify dependency graph handles JavaScript imports and C #include headers."""
    js_util = SourceFile(file_path="web/utils.js", relative_path="web/utils.js", content="export function fmt() {}\n", language=Language.JAVASCRIPT)
    js_app = SourceFile(file_path="web/app.js", relative_path="web/app.js", content="import { fmt } from './utils';\n", language=Language.JAVASCRIPT)

    c_hdr = SourceFile(file_path="native/crypto_helper.h", relative_path="native/crypto_helper.h", content="void encrypt();\n", language=Language.C)
    c_src = SourceFile(file_path="native/main.c", relative_path="native/main.c", content='#include "crypto_helper.h"\n', language=Language.C)

    graph = CrossFileContextResolver().build_dependency_graph([js_util, js_app, c_hdr, c_src])

    assert "web/utils.js" in graph.get_dependencies("web/app.js")
    assert "native/crypto_helper.h" in graph.get_dependencies("native/main.c")


def test_us24_dependency_graph_to_dict_json_serialization():
    """Verify graph.to_dict() produces valid JSON with summary node/edge counts."""
    f1 = SourceFile(file_path="a.py", relative_path="a.py", content="import b\n", language=Language.PYTHON)
    f2 = SourceFile(file_path="b.py", relative_path="b.py", content="x = 1\n", language=Language.PYTHON)

    graph = CrossFileContextResolver().build_dependency_graph([f1, f2])
    data = graph.to_dict()

    assert data["total_nodes"] == 2
    assert data["total_edges"] >= 1
    parsed = json.loads(json.dumps(data))
    assert len(parsed["nodes"]) == 2


def test_us24_empty_and_isolated_files_resilience():
    """Verify empty projects and isolated files do not cause ZeroDivisionError or crashes."""
    resolver = CrossFileContextResolver()
    empty_graph = resolver.build_dependency_graph([])
    assert empty_graph.to_dict()["total_nodes"] == 0

    isolated = SourceFile(file_path="solo.py", relative_path="solo.py", content="print('alone')\n", language=Language.PYTHON)
    solo_graph = resolver.build_dependency_graph([isolated])
    assert solo_graph.get_coupling_metrics("solo.py")["instability"] == 0.0