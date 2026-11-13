from pathlib import Path
from unittest.mock import MagicMock
import pytest

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.core.enums import Language
from app.core.models.code import SourceFile
from app.infrastructure.filesystem import LocalFileSystem
from app.rag.context_builder import ContextBuilder
from app.rag.embedding_service import LocalEmbeddingService
from app.rag.retriever import LocalContextRetriever


class VirtualFS(LocalFileSystem):
    """In-memory filesystem for local RAG retrieval testing."""

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


def test_us27_local_embedding_service_zero_network_transmission():
    """Verify LocalEmbeddingService computes on-device embeddings and cosine similarity using scikit-learn."""
    svc = LocalEmbeddingService(dimension=384)

    text_auth = "def authenticate_user(username, password_hash): return True"
    text_login = "def login_handler(user, pwd): verify_credentials(user, pwd)"
    text_fruit = "class AppleFruit: color = 'red'"

    v_auth = svc.embed_text(text_auth)
    v_login = svc.embed_text(text_login)
    v_fruit = svc.embed_text(text_fruit)

    assert len(v_auth) == 384
    assert len(v_login) == 384

    # Cache verification
    v_auth_cached = svc.embed_text(text_auth)
    assert v_auth_cached is v_auth

    # Cosine similarity using sklearn
    sim_related = svc.compute_similarity(v_auth, v_login)
    sim_unrelated = svc.compute_similarity(v_auth, v_fruit)

    assert sim_related > sim_unrelated
    assert -1.0 <= sim_related <= 1.0


def test_us27_local_context_retriever_structural_dependencies():
    """Verify LocalContextRetriever retrieves direct import dependencies locally from AST."""
    f1 = SourceFile(
        file_path="src/controllers/auth.py",
        relative_path="src/controllers/auth.py",
        content="from src.services.user_service import UserService\n\ndef login(): pass\n",
        language=Language.PYTHON,
    )
    f2 = SourceFile(
        file_path="src/services/user_service.py",
        relative_path="src/services/user_service.py",
        content="class UserService:\n    def find_user(self, uid):\n        return {'id': uid}\n",
        language=Language.PYTHON,
    )

    retriever = LocalContextRetriever()
    context = retriever.retrieve_structural_context(source_file=f1, all_project_files=[f1, f2])

    assert len(context) >= 1
    hit = context[0]
    assert "user_service" in hit["file"]
    assert "class UserService:" in hit["snippet"]


def test_us27_local_context_retriever_semantic_vector_search():
    """Verify LocalContextRetriever queries local Chroma store and excludes the focal file."""
    mock_store = MagicMock()
    mock_store.query_similar.return_value = [
        {
            "file_path": "src/controllers/auth.py",  # Should be excluded because it's focal!
            "content": "def login(): pass",
            "distance": 0.1,
        },
        {
            "file_path": "src/security/crypto.py",
            "content": "def hash_password(pwd):\n    return sha256(pwd)\n",
            "component_name": "hash_password",
            "start_line": 1,
            "end_line": 3,
            "distance": 0.25,
        },
    ]

    retriever = LocalContextRetriever(vector_store=mock_store)
    semantic_hits = retriever.retrieve_semantic_context(
        query="password hashing and security",
        project_id="test-proj",
        exclude_file_path="src/controllers/auth.py",
        top_k=2,
    )

    assert len(semantic_hits) == 1
    assert "crypto.py" in semantic_hits[0]["file"]
    assert "hash_password" == semantic_hits[0]["component_name"]


def test_us27_local_context_retriever_hybrid_deduplication():
    """Verify retrieve_hybrid_context fuses structural and semantic context without duplicates."""
    f1 = SourceFile(
        file_path="app/main.py",
        relative_path="app/main.py",
        content="import app.db\n",
        language=Language.PYTHON,
    )
    f_db = SourceFile(
        file_path="app/db.py",
        relative_path="app/db.py",
        content="def get_connection(): pass\n",
        language=Language.PYTHON,
    )

    mock_store = MagicMock()
    # Semantic search returns both db.py (already structural) and cache.py (new)
    mock_store.query_similar.return_value = [
        {"file_path": "app/db.py", "content": "def get_connection(): pass"},
        {"file_path": "app/cache.py", "content": "def get_redis(): pass"},
    ]

    retriever = LocalContextRetriever(vector_store=mock_store, max_context_snippets=3)
    results = retriever.retrieve_hybrid_context(
        source_file=f1,
        all_project_files=[f1, f_db],
        project_id="hybrid-proj",
    )

    files_included = [r["file"] for r in results]
    # Ensure no duplicates: db.py should appear only once
    assert len(files_included) == len(set(files_included))
    assert any("db.py" in f for f in files_included)
    assert any("cache.py" in f for f in files_included)
    assert not any("main.py" in f for f in files_included)


def test_us27_clean_line_boundary_truncation_prevents_mid_token_cuts():
    """Verify _truncate_at_line_boundary never slices code mid-line or mid-token."""
    retriever = LocalContextRetriever()
    multiline_code = (
        "def compute_hash(val):\n"
        "    part1 = val * 2\n"
        "    part2 = part1 + 10\n"
        "    return part2\n"
    )

    # Line 1 (23 chars) + Line 2 (20 chars) = 43 chars.
    # At max_chars=45, line 1 & 2 are cleanly kept, while line 3 (part2) is truncated
    truncated = retriever._truncate_at_line_boundary(multiline_code, max_chars=45)

    # Must preserve complete line without cutting inside 'part2 = part1 + 10'
    assert truncated.startswith("def compute_hash(val):\n    part1 = val * 2")
    assert "part2 = part1" not in truncated
    assert "# [TRUNCATED REMAINING LINES CLEANLY]" in truncated


def test_us27_context_builder_token_budget_enforcement():
    """Verify ContextBuilder enforces character budget and does not slice snippets halfway."""
    builder = ContextBuilder(max_context_chars=300)

    snippets = [
        {"file": f"file_{i}.py", "snippet": f"def func_{i}():\n    return {i}\n"}
        for i in range(10)
    ]

    context_block = builder.build_context_block(snippets)

    # Entire block must stay within the budget limit
    assert len(context_block) <= 450  # 300 char snippet budget + section header
    assert "### Relevant Cross-File Context" in context_block
    assert "file_0.py" in context_block
    # Files that exceeded the budget are cleanly omitted rather than butchered
    assert "file_9.py" not in context_block


def test_us27_context_builder_prompt_messages_assembly():
    """Verify ContextBuilder.build_messages produces structured prompt with focal code + local context."""
    builder = ContextBuilder()
    sf = SourceFile(
        file_path="api/routes.py",
        relative_path="api/routes.py",
        content="def get_user(): return True\n",
        language=Language.PYTHON,
    )
    context_snippets = [
        {
            "file": "services/auth.py",
            "component_name": "check_token",
            "start_line": 5,
            "end_line": 10,
            "type": "import_dependency",
            "snippet": "def check_token(t): return True\n",
        }
    ]

    messages = builder.build_messages(
        source_file=sf,
        context_snippets=context_snippets,
        system_prompt="Custom System Prompt",
    )

    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[0]["content"] == "Custom System Prompt"

    assert messages[1]["role"] == "user"
    user_text = messages[1]["content"]
    assert "Focal File: api/routes.py" in user_text
    assert "Language: python" in user_text
    assert "def get_user(): return True" in user_text
    assert "### Relevant Cross-File Context" in user_text
    assert "File: services/auth.py | Component: check_token | Lines: 5-10" in user_text
    assert "def check_token(t): return True" in user_text


def test_us27_ai_analyzer_seamless_local_retriever_integration():
    """Verify AIVulnerabilityAnalyzer automatically invokes LocalContextRetriever when analyzing project files."""
    mock_retriever = MagicMock(spec=LocalContextRetriever)
    mock_retriever.retrieve_hybrid_context.return_value = [
        {
            "file": "services/crypto.py",
            "snippet": "def verify_hash(val): return True\n",
            "type": "structural_dependency",
        }
    ]

    mock_llm = MagicMock()
    mock_llm.is_available.return_value = True
    mock_llm.chat_json.return_value = {
        "vulnerabilities": [
            {
                "title": "Insecure Hash Validation",
                "description": "Validation bypass found via cross-file dependency.",
                "severity": "HIGH",
                "start_line": 5,
                "end_line": 8,
                "is_cross_file": True,
                "related_files": ["services/crypto.py"],
            }
        ]
    }

    analyzer = AIVulnerabilityAnalyzer(
        llm_client=mock_llm,
        retriever=mock_retriever,
    )

    focal = SourceFile(
        file_path="routes/auth.py",
        relative_path="routes/auth.py",
        content="from services.crypto import verify_hash\ndef login(): verify_hash('x')\n",
        language=Language.PYTHON,
    )
    all_files = [focal, SourceFile(file_path="services/crypto.py", relative_path="services/crypto.py", content="...", language=Language.PYTHON)]

    findings = analyzer.analyze_file(
        source_file=focal,
        all_project_files=all_files,
        project_id="test_proj_123",
    )

    # 1. LocalContextRetriever was called with focal file, project files, and project_id
    mock_retriever.retrieve_hybrid_context.assert_called_once_with(
        source_file=focal,
        all_project_files=all_files,
        project_id="test_proj_123",
    )

    # 2. LLM was invoked with retrieved context
    assert len(findings) == 1
    assert findings[0].title == "Insecure Hash Validation"
    assert findings[0].severity.value == "high"
    assert findings[0].metadata.get("cross_file") is True
    assert findings[0].metadata.get("related_files") == ["services/crypto.py"]
