"""
main.py — NSD v19 Application Entrypoint
ChaosTech Defense LLC
"""
import os
import sys
import logging
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

# Ensure backend/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from api.routes import create_app

# Configure Logging (Single source of truth)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("nsd.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("NSD Prototype starting up...")
    token = os.getenv("NSD_API_TOKEN")
    if not token:
        logger.warning("NSD_API_TOKEN not set. Write endpoints will be unprotected.")
    yield
    logger.info("NSD Prototype shutting down...")

app = create_app()

# Mount Fusion Pipeline sub-app
try:
    from fusion_pipeline import app as fusion_app
    app.mount("/fusion", fusion_app)
    logger.info("Fusion Pipeline sub-app mounted at /fusion")
except ImportError:
    logger.error("Could not import fusion_pipeline.py - check file location")

# Mount frontend
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/app", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    logger.info(f"Frontend mounted at /app from {frontend_dir}")

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
