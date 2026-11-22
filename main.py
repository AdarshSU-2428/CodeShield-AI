"""
CodeShield AI - Application Entrypoint
Run directly via:
    python main.py
"""

import uvicorn

if __name__ == "__main__":
    print("🛡️ Starting CodeShield AI on http://127.0.0.1:8000 ...")
    print("🖥️ Open UI Dashboard: http://127.0.0.1:8000/ui")
    print("📖 API Documentation: http://127.0.0.1:8000/docs")
    uvicorn.run("app.backend_main:app", host="127.0.0.1", port=8000, reload=True)
