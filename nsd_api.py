# nsd_api.py — ChaosTech Defense NSD RF Backend
# Bootstrap only — app init, middleware, wiring

import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import nsd_db
from scanner.state import state
from scanner.worker import start_scanner
from api.routes import register_routes, limiter

# ── App init ──────────────────────────────────────────────────
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080",
                   "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-NSD-Token"],
)

# ── Bootstrap ─────────────────────────────────────────────────
nsd_db.init_db()
state.next_threat_id = nsd_db.load_max_threat_id()
print(f"[NSD] Threat ID counter restored: {state.next_threat_id}")

register_routes(app)
start_scanner()
