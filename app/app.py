"""
CodeShield AI - Main FastAPI Application Server

Combines all REST API routers:
- /api/projects: Project registration, status, tree structure, file reading, and change tracking
- /api/audit: Background audit jobs, status polling, findings, SARIF v2.1.0 and Markdown export
- /api/patches: Mode 1 (surgical file-by-file) and Mode 2 (batch whole-project) patching & rollbacks
- /api/health: Engine and dependency health diagnostics
- Static file serving for desktop frontend in app/ui
"""

from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.analysis.parser import ParserRegistry
from app.api.routes.audit import router as audit_router
from app.api.routes.patch import router as patch_router
from app.api.routes.project import router as project_router
from app.api.schemas import SystemHealthResponse
from app.core.enums import Language
from app.infrastructure.llm import GroqLLMClient

tags_metadata = [
    {
        "name": "Health",
        "description": "System health and engine availability diagnostics (Tree-sitter, ChromaDB, Groq LLM).",
    },
    {
        "name": "Projects",
        "description": "Codebase registration, recursive sidebar file tree, file content retrieval, and incremental change detection.",
    },
    {
        "name": "Audit",
        "description": "Multi-engine security & quality audits, background worker execution, live status polling, SARIF v2.1.0 and Markdown report exports.",
    },
    {
        "name": "Patches",
        "description": "Mode 1 (file-by-file surgical) and Mode 2 (batch whole-project) remediation patches, pre-flight AST syntax validation, approval gate, and byte-for-byte rollback.",
    },
]

app = FastAPI(
    title="CodeShield AI",
    description="Desktop Cloud-Assisted Code Quality & Security Auditor API",
    version="0.1.0",
    openapi_tags=tags_metadata,
)

# Enable CORS for desktop/local environments (Electron, Tauri, React/Vite dev server)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(project_router)
app.include_router(audit_router)
app.include_router(patch_router)


@app.get("/api/health", response_model=SystemHealthResponse, tags=["Health"])
def get_health() -> SystemHealthResponse:
    """Check health and availability of Tree-sitter, ChromaDB, and Groq LLM engines."""
    # Check tree-sitter
    try:
        registry = ParserRegistry()
        tree_sitter_ok = registry.is_supported(Language.PYTHON)
    except Exception:
        tree_sitter_ok = False

    # Check chromadb
    try:
        import chromadb  # type: ignore # noqa: F401
        chromadb_ok = True
    except ImportError:
        chromadb_ok = False

    # Check Groq LLM
    try:
        llm = GroqLLMClient()
        llm_ok = llm.api_key_configured
    except Exception:
        llm_ok = False

    return SystemHealthResponse(
        status="ok",
        app_name="CodeShield AI",
        version="0.1.0",
        tree_sitter_available=tree_sitter_ok,
        chromadb_available=chromadb_ok,
        llm_available=llm_ok,
        timestamp=datetime.now(timezone.utc),
    )


@app.get("/", tags=["Health"])
def root_redirect():
    """Root endpoint verifying API server is alive."""
    return {
        "app": "CodeShield AI",
        "status": "online",
        "docs_url": "/docs",
        "health_url": "/api/health",
    }


# Mount static UI if directory exists
ui_dir = Path(__file__).resolve().parent / "ui"
if ui_dir.is_dir():
    app.mount("/ui", StaticFiles(directory=str(ui_dir), html=True), name="ui")
