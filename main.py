"""
main.py — NSD v19 Application Entrypoint
ChaosTech Defense LLC

Thin entrypoint: creates the FastAPI app, registers the lifespan
(startup/shutdown) and all routes via api/routes.py, then starts
Uvicorn.

Run:
    python main.py
    # or via systemd / supervisor

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
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Ensure backend/ is importable regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from api.routes import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

app = create_app()

# Serve the frontend from /
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

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
