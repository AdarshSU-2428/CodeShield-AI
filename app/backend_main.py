"""
CodeShield AI - FastAPI Main Application Entrypoint
Allows starting the server directly via:
    python app/main.py
or
    python -m uvicorn app.main:app --reload
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.app import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    print("🛡️ Starting CodeShield AI backend on http://127.0.0.1:8000 ...")
    print("📖 Swagger UI Docs available at: http://127.0.0.1:8000/docs")
    uvicorn.run("app.app:app", host="127.0.0.1", port=8000, reload=True)
