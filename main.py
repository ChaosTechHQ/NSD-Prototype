"""
main.py — NSD v19 Application Entrypoint
ChaosTech Defense LLC

Run:
    python main.py

Environment variables:
    NSD_API_TOKEN   — shared secret for write endpoints (auto-generated if unset)
    NSD_HOST        — bind host (default: 0.0.0.0)
    NSD_PORT        — bind port (default: 8000)
    NSD_SIM_SEED    — integer seed for deterministic sim mode (optional)
    NSD_DB_PATH     — override SQLite path (default: ~/nsd-v19/data/signals.db)
"""

import os
import sys
import logging

import uvicorn
from fastapi.staticfiles import StaticFiles

# Ensure backend/ is importable regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from api.routes import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

app = create_app()

# Mount frontend at /app — NOT at "/" so WebSocket upgrades
# to the root path are not swallowed by StaticFiles (which
# only handles HTTP and raises AssertionError on WS scope).
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/app", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    host = os.getenv("NSD_HOST", "0.0.0.0")
    port = int(os.getenv("NSD_PORT", "8000"))
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
