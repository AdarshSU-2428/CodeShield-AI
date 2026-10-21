from pathlib import Path
import shutil
import tempfile
import pytest

from app.analysis.component_extractor import ComponentExtractor
from app.analysis.parser import ParserRegistry
from app.analysis.scanner import RepositoryScanner
from app.core.enums import Language
from app.core.models.code import CodeChunk, CodeComponent, SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.chroma_store import ChromaVectorStore
from app.rag.chunker import CodeChunker
from app.rag.indexer import RepositoryIndexer


@pytest.fixture
def temp_env():
    """Provides an isolated directory for code files and vector storage."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def isolated_vector_store(temp_env):
    """Provides a ChromaVectorStore writing to the temporary folder."""
    store_dir = temp_env / "vector_db"
    return ChromaVectorStore(persist_directory=store_dir)


def test_us29_code_chunker_single_chunk():
    """Verify small components fit into a single CodeChunk with a contextual header."""
    chunker = CodeChunker()
    component = CodeComponent(
        name="verify_jwt",
        component_type="function",
        start_line=10,
        end_line=15,
        source_content="def verify_jwt(token):\n    return decode(token)\n",
        file_path="src/auth.py",
        language=Language.PYTHON,
    )
    chunks = chunker.chunk_component(component)
    assert len(chunks) == 1
    chunk = chunks[0]
    assert chunk.component_name == "verify_jwt"
    assert "File: auth.py" in chunk.content
    assert "Function: verify_jwt" in chunk.content
    assert chunk.metadata["language"] == "python"


def test_us29_code_chunker_sliding_window():
    """Verify large components exceeding line limits are sliced with overlap."""
    chunker = CodeChunker()
    chunker.max_chunk_lines = 20
    chunker.overlap_lines = 5

    # Generate a function with 50 lines of code
    long_code = "\n".join([f"    x_{i} = calculate_value({i})" for i in range(50)])
    component = CodeComponent(
        name="complex_computation",
        component_type="function",
        start_line=1,
        end_line=50,
        source_content=f"def complex_computation():\n{long_code}\n",
        file_path="src/math.py",
        language=Language.PYTHON,
    )
    chunks = chunker.chunk_component(component)
    assert len(chunks) > 1
    # Check that later chunks indicate sub-chunk slicing
    assert any(c.metadata.get("is_sub_chunk") is True for c in chunks[1:])


def test_us29_chroma_store_add_and_query(isolated_vector_store):
    """Verify ChromaVectorStore stores chunks and performs semantic search."""
    project_id = "test_sec_proj"
    
    sql_chunk = CodeChunk(
        content="// [File: db.py | Function: get_user]\ndef get_user(id):\n    return db.execute(f'SELECT * FROM users WHERE id = {id}')\n",
        file_path="db.py",
        start_line=1,
        end_line=3,
        component_name="get_user",
        chunk_id="chunk_sql",
    )
    ui_chunk = CodeChunk(
        content="// [File: render.py | Function: draw_button]\ndef draw_button(color):\n    return f'<button style=color:{color}>Click</button>'\n",
        file_path="render.py",
        start_line=1,
        end_line=3,
        component_name="draw_button",
        chunk_id="chunk_ui",
    )

    added = isolated_vector_store.add_chunks([sql_chunk, ui_chunk], project_id=project_id)
    assert added == 2
    assert isolated_vector_store.count(project_id) == 2

    # Query for database vulnerability: should return get_user with higher relevance than draw_button
    matches = isolated_vector_store.query_similar(
        query_text="database SQL injection raw query execution",
        project_id=project_id,
        top_k=1,
    )
    assert len(matches) == 1
    assert matches[0]["metadata"]["component_name"] == "get_user"


def test_us29_chroma_store_incremental_deletion(isolated_vector_store):
    """Verify delete_file_chunks removes only the specific file chunks."""
    project_id = "test_incr_proj"
    
    c1 = CodeChunk(content="func A", file_path="file1.py", start_line=1, end_line=2, component_name="A")
    c2 = CodeChunk(content="func B", file_path="file2.py", start_line=1, end_line=2, component_name="B")
    isolated_vector_store.add_chunks([c1, c2], project_id=project_id)
    assert isolated_vector_store.count(project_id) == 2

    # Delete only file1
    isolated_vector_store.delete_file_chunks("file1.py", project_id=project_id)
    assert isolated_vector_store.count(project_id) == 1

    # Reset project
    isolated_vector_store.reset_project_index(project_id=project_id)
    assert isolated_vector_store.count(project_id) == 0


def test_us29_indexer_end_to_end_multilingual(temp_env, isolated_vector_store):
    """
    Integration test: Index a project containing Python, JavaScript, Java, C, and C++ files,
    verify AST parsing, chunking, and semantic search.
    """
    proj_dir = temp_env / "multi_repo"
    proj_dir.mkdir()

    # 1. Python file
    (proj_dir / "user_service.py").write_text(
        "def hash_password(plain):\n    import hashlib\n    return hashlib.sha256(plain.encode()).hexdigest()\n",
        encoding="utf-8",
    )

    # 2. JavaScript file
    (proj_dir / "jwt_handler.js").write_text(
        "function verifyJwtToken(token) {\n    return jwt.verify(token, process.env.SECRET_KEY);\n}\n",
        encoding="utf-8",
    )

    # 3. Java file
    (proj_dir / "PaymentProcessor.java").write_text(
        "public class PaymentProcessor {\n    public boolean processCard(String cardNum) {\n        return true;\n    }\n}\n",
        encoding="utf-8",
    )

    # 4. C file
    (proj_dir / "memory_ops.c").write_text(
        "int allocate_buffer(int size) {\n    char* buf = (char*)malloc(size);\n    return 0;\n}\n",
        encoding="utf-8",
    )

    # 5. C++ file
    (proj_dir / "network.cpp").write_text(
        "class NetworkSocket {\npublic:\n    void connectToHost(string host) {}\n};\n",
        encoding="utf-8",
    )

    # 6. Fallback script (no class/func)
    (proj_dir / "config_loader.py").write_text(
        "DEBUG_MODE = True\nPORT = 8080\nDB_HOST = '127.0.0.1'\n",
        encoding="utf-8",
    )

    project = Project(root_path=proj_dir, project_id="multilingual-repo")
    indexer = RepositoryIndexer(vector_store=isolated_vector_store)

    # Execute full project indexing
    summary = indexer.index_project(project)
    assert summary["files_scanned"] == 6
    assert summary["files_indexed"] == 6
    assert summary["chunks_indexed"] >= 6
    assert len(summary["errors"]) == 0

    # Semantic search across repository
    jwt_results = indexer.search_project(
        query="validate JWT secret key authentication",
        project_id="multilingual-repo",
        top_k=1,
    )
    assert len(jwt_results) == 1
    assert jwt_results[0]["metadata"]["component_name"] == "verifyJwtToken"

    # Search memory management in C
    mem_results = indexer.search_project(
        query="malloc dynamic memory allocation buffer",
        project_id="multilingual-repo",
        top_k=1,
    )
    assert len(mem_results) == 1
    assert mem_results[0]["metadata"]["component_name"] == "allocate_buffer"
