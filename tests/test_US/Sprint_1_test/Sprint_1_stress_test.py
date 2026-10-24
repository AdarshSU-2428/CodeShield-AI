import concurrent.futures
from pathlib import Path
import shutil
import tempfile
import time
import pytest

from app.ai.sanitizer import CodeSanitizer
from app.analysis.component_extractor import ComponentExtractor
from app.analysis.parser import ParserRegistry
from app.analysis.scanner import RepositoryScanner
from app.core.enums import Language
from app.core.models.code import CodeChunk, CodeComponent, SourceFile
from app.core.models.project import Project
from app.infrastructure.config import config
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.chroma_store import ChromaVectorStore
from app.rag.chunker import CodeChunker
from app.rag.indexer import RepositoryIndexer


@pytest.fixture
def stress_env():
    """Provides an isolated directory for hostile and chaotic stress tests."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_stress_corrupted_syntax_fuzzing(stress_env):
    """
    STRESS TEST 1: Syntax Horrors & Malformed Input Fuzzing.
    Feeds severely broken and unclosed syntax across all 5 languages to AST parsers.
    Verifies that parsers and component extractors never crash or raise unhandled exceptions.
    """
    corrupt_samples = [
        (Language.PYTHON, "def unclosed_func(a, b: return { [ ( ((\n    if else while for"),
        (Language.JAVASCRIPT, "function broken() { let x = {{{; return (;;;"),
        (Language.JAVA, "public class Corrupt { public void *( bad_syntax {{{"),
        (Language.C, "int main( { void* p = &&;;; return }"),
        (Language.CPP, "class BrokenCpp : public { template<typename>> void bad() {"),
    ]

    parser_reg = ParserRegistry()
    extractor = ComponentExtractor()

    for lang, malformed_code in corrupt_samples:
        parser = parser_reg.get_parser(lang)
        assert parser is not None
        tree = parser.parse(malformed_code)
        assert tree is not None
        assert tree.root_node is not None
        comps = extractor.extract_components(
            tree=tree,
            source_code=malformed_code,
            language=lang,
        )
        assert isinstance(comps, list)


def test_stress_pathological_scale_and_nesting(stress_env):
    """
    STRESS TEST 2: Scale Extremes.
    - Massive 1,500-line function (sliding window chunker stress)
    - 10,000-character minified single-line file
    - 35 levels of deeply nested functions
    """
    chunker = CodeChunker()

    # 1. Massive 1,500-line function
    lines = ["    step_%d = calculate_hash(%d)" % (i, i) for i in range(1500)]
    long_code = "def ultra_massive_routine():\n" + "\n".join(lines) + "\n"
    huge_comp = CodeComponent(
        name="ultra_massive_routine",
        component_type="function",
        start_line=1,
        end_line=1501,
        source_content=long_code,
        file_path="huge.py",
        language=Language.PYTHON,
    )
    chunks = chunker.chunk_component(huge_comp)
    assert len(chunks) > 25, "Expected sliding window to slice into > 25 sub-chunks"
    assert chunks[-1].metadata["is_sub_chunk"] is True

    # 2. Minified JS (10,000 characters on line 1)
    parser = ParserRegistry().get_parser(Language.JAVASCRIPT)
    minified_js = "var a=1;" * 1000 + "function minifiedHandler(){return 42;}"
    tree = parser.parse(minified_js)
    extractor = ComponentExtractor()
    comps = extractor.extract_components(tree, minified_js, language=Language.JAVASCRIPT)
    assert len(comps) == 1
    assert comps[0].name == "minifiedHandler"

    # 3. Deep nesting (35 levels of functions)
    deep_code = "def lvl_0():\n"
    for i in range(1, 35):
        deep_code += "    " * i + f"def lvl_{i}():\n"
    deep_code += "    " * 35 + "return 999\n"
    py_parser = ParserRegistry().get_parser(Language.PYTHON)
    deep_tree = py_parser.parse(deep_code)
    deep_comps = extractor.extract_components(deep_tree, deep_code, language=Language.PYTHON)
    assert len(deep_comps) == 35, "All 35 nested functions must be extracted"


def test_stress_hostile_filesystem_paths_and_unicode(stress_env):
    """
    STRESS TEST 3: Hostile Paths & Special Characters.
    Tests spaces, brackets, hashes, unicode, and emojis in paths and function names.
    """
    proj_dir = stress_env / "hostile_proj [v1.0] #test"
    proj_dir.mkdir()

    # File with brackets, hashes, and spaces
    weird_file = proj_dir / "weird [module] #1 - test.py"
    weird_file.write_text("def special_handler():\n    return 'ok'\n", encoding="utf-8")

    # File with deep directory nesting
    deep_folder = proj_dir / "a" / "b" / "c" / "d" / "e" / "f"
    deep_folder.mkdir(parents=True)
    deep_file = deep_folder / "nested.py"
    deep_file.write_text("def deep_handler():\n    return 'deep'\n", encoding="utf-8")

    # Binary file (must be ignored by indexer!)
    (proj_dir / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

    fs = LocalFileSystem()
    scanner = RepositoryScanner(filesystem=fs, config=config)
    project = Project(root_path=proj_dir, project_id="hostile_proj_#1_")

    store_dir = stress_env / "vector_db"
    vstore = ChromaVectorStore(persist_directory=store_dir)
    indexer = RepositoryIndexer(vector_store=vstore, scanner=scanner, filesystem=fs, config=config)

    summary = indexer.index_project(project)
    assert summary["files_indexed"] == 2, "Only the 2 Python files should be indexed (PNG must be skipped)"
    assert summary["chunks_indexed"] >= 2
    assert len(summary["errors"]) == 0

    res = indexer.search_project("special handler", project_id=project.project_id, top_k=1)
    assert len(res) == 1
    assert res[0]["metadata"]["component_name"] == "special_handler"


def test_stress_sanitizer_high_volume_and_redoc_immunity():
    """
    STRESS TEST 4: Sanitizer Under High-Volume Secret Density & ReDoS Torture.
    Processes 10,000 lines of mixed code with 50+ secrets to ensure sub-second completion.
    """
    sanitizer = CodeSanitizer()

    dense_secrets = [
        'GROQ_KEY = "gsk_12345678901234567890123456789012"',
        'OPENAI = "sk-12345678901234567890123456789012" ; AWS = "AKIA1234567890123456"',
        'DB_URL = "postgresql://superuser:complex_password_99@127.0.0.1:5432/main_db"',
        'WIN_PATH = "C:\\Users\\John Doe (Admin)\\secret_keys\\id_rsa"',
    ]
    large_payload = ("# Normal code comment\nx = calculate_metric()\n" * 2000) + "\n".join(dense_secrets * 20)

    start_time = time.time()
    result = sanitizer.sanitize(large_payload)
    elapsed = time.time() - start_time

    assert elapsed < 1.0, f"Sanitizer took {elapsed:.3f}s, potential ReDoS!"
    assert result.redacted_count >= 80
    assert "gsk_" not in result.sanitized_text
    assert "complex_password_99" not in result.sanitized_text


def test_stress_vector_store_adversarial_ids_and_rapid_churn(stress_env):
    """
    STRESS TEST 5: ChromaDB Project ID Torture & Rapid Invalidation Churn.
    - Hostile project IDs (symbols, trailing underscores, dots)
    - Query boundary conditions (top_k=0, empty query, 200-word query)
    - Rapid file churn (10 consecutive delete/re-index cycles)
    """
    store_dir = stress_env / "churn_store"
    vstore = ChromaVectorStore(persist_directory=store_dir)

    # 1. Adversarial project IDs
    hostile_pids = ["stress_#1_", "___", "test..collection", "123_456_"]
    for pid in hostile_pids:
        chunk = CodeChunk(content="def foo(): pass", file_path="foo.py", start_line=1, end_line=1, component_name="foo")
        added = vstore.add_chunks([chunk], project_id=pid)
        assert added == 1
        assert vstore.count(pid) == 1
        vstore.reset_project_index(pid)
        assert vstore.count(pid) == 0

    # 2. Query boundary conditions
    test_pid = "boundary_proj"
    chunk = CodeChunk(content="def authenticate_user(): return True", file_path="auth.py", start_line=1, end_line=1, component_name="authenticate_user")
    vstore.add_chunks([chunk], project_id=test_pid)

    assert vstore.query_similar("", project_id=test_pid, top_k=5) == []
    assert vstore.query_similar("authenticate", project_id=test_pid, top_k=0) == []
    assert vstore.query_similar("authenticate", project_id="does_not_exist_999", top_k=5) == []
    large_query = "word " * 200
    res = vstore.query_similar(large_query, project_id=test_pid, top_k=1)
    assert len(res) == 1

    # 3. Rapid Churn: 10 consecutive re-indexes and deletions
    for cycle in range(10):
        vstore.delete_file_chunks("auth.py", project_id=test_pid)
        assert vstore.count(test_pid) == 0
        vstore.add_chunks([chunk], project_id=test_pid)
        assert vstore.count(test_pid) == 1

    vstore.reset_project_index(test_pid)
    assert vstore.count(test_pid) == 0


def test_stress_multithreaded_concurrency(stress_env):
    """
    STRESS TEST 6: Multithreaded Concurrency Stress.
    Spawns 8 parallel worker threads querying and upserting the vector store
    simultaneously to ensure thread safety and zero database locking crashes.
    """
    store_dir = stress_env / "concurrent_store"
    vstore = ChromaVectorStore(persist_directory=store_dir)
    project_id = "concurrent_proj"

    # Pre-populate with baseline vectors
    chunks = [
        CodeChunk(content=f"def func_{i}(): return {i}", file_path=f"file_{i}.py", start_line=1, end_line=1, component_name=f"func_{i}")
        for i in range(10)
    ]
    vstore.add_chunks(chunks, project_id=project_id)

    def worker_task(worker_id: int):
        # Alternate between querying and inserting
        if worker_id % 2 == 0:
            return vstore.query_similar(f"func_{worker_id}", project_id=project_id, top_k=2)
        else:
            new_chunk = CodeChunk(
                content=f"def worker_code_{worker_id}(): pass",
                file_path=f"worker_{worker_id}.py",
                start_line=1,
                end_line=1,
                component_name=f"worker_{worker_id}",
            )
            return vstore.add_chunks([new_chunk], project_id=project_id)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_task, i) for i in range(24)]
        results = [f.result() for f in futures]

    assert len(results) == 24
    assert vstore.count(project_id) >= 10
    vstore.reset_project_index(project_id)


def test_stress_massive_multilingual_repository_scale(stress_env):
    """
    STRESS TEST 7: Massive 50-File Repository Scale.
    Generates 50 source files spanning Python, JavaScript, Java, C, and C++.
    Verifies that full scan, AST parsing, component extraction, and vector indexing
    complete smoothly under high throughput without errors.
    """
    repo_dir = stress_env / "massive_50_repo"
    repo_dir.mkdir()

    # Generate 50 files dynamically (10 per language)
    for i in range(10):
        (repo_dir / f"service_{i}.py").write_text(f"def py_compute_{i}(x):\n    return x * {i}\n", encoding="utf-8")
        (repo_dir / f"handler_{i}.js").write_text(f"function jsHandler_{i}(req) {{\n    return {i};\n}}\n", encoding="utf-8")
        (repo_dir / f"Worker_{i}.java").write_text(f"public class Worker_{i} {{\n    public int run_{i}() {{\n        return {i};\n    }}\n}}\n", encoding="utf-8")
        (repo_dir / f"buffer_{i}.c").write_text(f"int c_buffer_{i}() {{\n    return {i};\n}}\n", encoding="utf-8")
        (repo_dir / f"socket_{i}.cpp").write_text(f"class Socket_{i} {{\npublic:\n    void send_{i}() {{}}\n}};\n", encoding="utf-8")

    fs = LocalFileSystem()
    scanner = RepositoryScanner(filesystem=fs, config=config)
    project = Project(root_path=repo_dir, project_id="scale_50_repo")

    vstore = ChromaVectorStore(persist_directory=stress_env / "scale_store")
    indexer = RepositoryIndexer(vector_store=vstore, scanner=scanner, filesystem=fs, config=config)

    start = time.time()
    summary = indexer.index_project(project)
    duration = time.time() - start

    assert summary["files_scanned"] == 50
    assert summary["files_indexed"] == 50
    assert summary["chunks_indexed"] >= 50
    assert len(summary["errors"]) == 0
    assert duration < 30.0, f"Indexing 50 files took {duration:.2f}s, expected < 30s"

    # Verify semantic retrieval across the massive repo
    match = indexer.search_project("c_buffer_5", project_id="scale_50_repo", top_k=1)
    assert len(match) == 1
    assert match[0]["metadata"]["component_name"] == "c_buffer_5"
