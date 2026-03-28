"""
api/routes.py — NSD v19 FastAPI Routes + Lifespan
ChaosTech Defense LLC

All application objects (SDRScanner, ThreatClassifier, SignalDB) are
created in the lifespan context and attached to app.state. Routes
access them via request.app.state. Zero module-level singletons.

Endpoints:
  GET  /api/health          — liveness check
  GET  /api/hardware        — full mission state + active threats
  GET  /api/psd_scan        — latest PSD frame (legacy compat)
  GET  /api/detections      — recent detection history from SignalDB
  GET  /api/export          — CSV export of detection history
  GET  /api/report          — PDF session report (ReportLab)
  GET  /api/stats           — SignalDB summary statistics
  GET  /api/history         — alias for /api/detections (legacy compat)
  GET  /api/token           — localhost-only token reveal
  GET  /api/audit           — last 50 audit log entries (auth required)
  POST /api/control         — set system active/mode (auth required)
  POST /api/autonomous      — set autonomous mode config (auth required)
"""

import os
import sys
import time
import secrets
import logging
import asyncio
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Backend imports — sys.path extended by main.py
from sdr_engine import SDRScanner
from threat_classifier import ThreatClassifier
from signal_db import SignalDB
from report_generator import generate_report
from scanner.state import state

logger = logging.getLogger("nsd.api")

limiter = Limiter(key_func=get_remote_address)

_VALID_MODES   = {"RF_JAM", "GPS_SPOOF", "PROTOCOL", "SWARM_DISRUPT"}
_AUDIT_LOG     = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_auth(request: Request):
    token = request.headers.get("X-NSD-Token", "")
    if token != request.app.state.api_token:
        _audit("UNAUTHORIZED", request.client.host, "rejected")
        raise HTTPException(status_code=403, detail="Unauthorized")


def _audit(action: str, source: str, detail: str):
    entry = {
        "time":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "source": source,
        "detail": detail,
    }
    _AUDIT_LOG.append(entry)
    if len(_AUDIT_LOG) > 500:
        _AUDIT_LOG.pop(0)
    logger.info(f"[AUDIT] {entry['time']} {source} {action}: {detail}")


def _sanitize_mode(mode: str) -> str:
    if mode not in _VALID_MODES:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")
    return mode


def _sanitize_threshold(val) -> int:
    try:
        return max(0, min(100, int(val)))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="threshold must be 0-100")


def _threat_to_dict(t) -> dict:
    """Serialize a ThreatObject to a JSON-safe dict."""
    return {
        "id":              t.id,
        "band":            t.band_name,
        "freq_mhz":        t.freq_mhz,
        "bandwidth_khz":   t.bandwidth_khz,
        "power_dbm":       t.power_dbm,
        "noise_floor_dbm": t.noise_floor_dbm,
        "snr_db":          t.snr_db,
        "protocol":        t.protocol,
        "fp_protocol":     t.fp_protocol,
        "fp_confidence":   t.fp_confidence,
        "fp_conf_pct":     t.fp_conf_pct,
        "fp_notes":        t.fp_notes,
        "threat_score":    t.threat_score,
        "threat_level":    t.threat_level,
        "confirmed_hits":  t.confirmed_hits,
        "simulated":       t.simulated,
        "timestamp":       t.timestamp,
    }


# ---------------------------------------------------------------------------
# Background broadcast loop
# Runs as an asyncio task; polls SDRScanner, feeds ThreatClassifier + SignalDB,
# keeps NSDState.cache updated for all routes to read.
# ---------------------------------------------------------------------------

async def _broadcast_loop(app: FastAPI):
    scanner:    SDRScanner       = app.state.scanner
    classifier: ThreatClassifier = app.state.classifier
    db:         SignalDB         = app.state.db

    logged_threat_ids: set = set()
    last_cycle_ts: Optional[float] = None

    logger.info("Broadcast loop started.")

    while True:
        await asyncio.sleep(0.5)

        scan = scanner.get_latest_scan()
        if scan is None or scan.timestamp == last_cycle_ts:
            continue
        last_cycle_ts = scan.timestamp

        threats = []
        points  = []
        noise_readings = []

        for reading in scan.bands:
            # Update NSDState cache per band
            noise_readings.append(reading.noise_floor_db)

            # Build PSD points from band readings for legacy /api/psd_scan
            points.append({
                "freq_mhz":  round(reading.peak_freq_hz / 1e6, 3),
                "power_db":  reading.peak_power_db,
                "band":      reading.label,
            })

            # Run threat classifier
            threat = classifier.process_band(reading)
            if threat is not None:
                threats.append(threat)

                # Log to DB once per threat ID (not on every refresh)
                if threat.id not in logged_threat_ids:
                    logged_threat_ids.add(threat.id)
                    db.log_detection(
                        band=reading.band_name,
                        freq_mhz=threat.freq_mhz,
                        power_db=threat.power_dbm,
                        noise_floor_db=threat.noise_floor_dbm,
                        snr_db=threat.snr_db,
                        bandwidth_khz=threat.bandwidth_khz,
                        protocol=threat.fp_protocol or threat.protocol,
                        threat_level=threat.threat_level,
                        threat_score=threat.threat_score,
                        simulated=threat.simulated,
                    )

        # Prune logged IDs to active threats only (prevent unbounded growth)
        active_ids = {t.id for t in classifier.get_active_threats()}
        logged_threat_ids &= active_ids

        avg_noise = (
            sum(noise_readings) / len(noise_readings)
            if noise_readings else None
        )

        with state.lock:
            state.cache["threats"]        = [_threat_to_dict(t) for t in threats]
            state.cache["points"]         = points
            state.cache["noise_floor_db"] = avg_noise
            state.cache["timestamp"]      = scan.timestamp
            state.cache["status"]         = "ok" if scanner.hardware_ok else "simulation"
            state.cache["total_detected"] = classifier.get_total_detected()
            state.cache["active_band"]    = (
                scan.bands[-1].label if scan.bands else "UNK"
            )
            state.cache["cycle_time_s"]   = scan.cycle_time_s


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────
    api_token = os.getenv("NSD_API_TOKEN") or secrets.token_hex(16)
    db_path   = os.getenv(
        "NSD_DB_PATH",
        os.path.expanduser("~/nsd-v19/data/signals.db")
    )
    sim_seed_env = os.getenv("NSD_SIM_SEED")
    sim_seed = int(sim_seed_env) if sim_seed_env else None

    scanner    = SDRScanner(sim_fallback=True, sim_seed=sim_seed)
    classifier = ThreatClassifier()
    db         = SignalDB(db_path=db_path)

    app.state.scanner    = scanner
    app.state.classifier = classifier
    app.state.db         = db
    app.state.api_token  = api_token

    scanner.start()
    logger.info(f"NSD v19 started | hardware={'yes' if scanner.hardware_ok else 'sim'} "
                f"| db={db_path}")
    if not os.getenv("NSD_API_TOKEN"):
        logger.warning(f"NSD_API_TOKEN not set — generated token: {api_token}")

    broadcast_task = asyncio.create_task(_broadcast_loop(app))

    yield  # ── application runs ──

    # ── Shutdown ─────────────────────────────────────────────────────────
    broadcast_task.cancel()
    try:
        await broadcast_task
    except asyncio.CancelledError:
        pass
    scanner.stop()
    db.stop()
    logger.info("NSD v19 shutdown complete.")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="NSD v19 — Neuro Swarm Disruptor",
        version="19.0.0",
        lifespan=_lifespan,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    _register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _register_routes(app: FastAPI):

    # ── Health ────────────────────────────────────────────────────────────

    @app.get("/api/health")
    @limiter.limit("30/minute")
    def api_health(request: Request):
        with state.lock:
            status = state.cache["status"]
            ts     = state.cache["timestamp"]
        hw = request.app.state.scanner.hardware_ok
        return {
            "status":       "ok",
            "sdr_available": hw,
            "mode":         "hardware" if hw else "simulation",
            "last_scan":    ts,
        }

    # ── Hardware / Mission State ───────────────────────────────────────────

    @app.get("/api/hardware")
    @limiter.limit("60/minute")
    def api_hardware(request: Request):
        classifier: ThreatClassifier = request.app.state.classifier
        with state.lock:
            cache = dict(state.cache)
        return {
            "status": cache["status"],
            "mission_state": {
                "uptime_sec":          int(time.time() - state.start_time),
                "threats_detected":    classifier.get_total_detected(),
                "candidates_pending":  classifier.get_candidate_count(),
                "active_threats":      classifier.get_threat_count(),
                "swarms_detected":     state.swarms_detected,
                "active_swarms":       len(state.active_swarms),
                "threats_engaged":     state.threats_engaged,
                "threats_neutralized": state.threats_neutralized,
                "autonomous_actions":  state.autonomous_actions,
                "swarms_eliminated":   state.swarms_eliminated,
            },
            "threats":        cache.get("threats", []),
            "threat_count":   len(cache.get("threats", [])),
            "noise_floor_db": cache["noise_floor_db"],
            "cycle_time_s":   cache.get("cycle_time_s"),
            "system_state": {
                "active":        state.system_active,
                "mode":          state.system_mode,
                "power_level":   100,
                "energy_reserves": 100,
            },
            "autonomous_mode": {
                "enabled":          state.autonomous_enabled,
                "auto_engage":      state.auto_engage,
                "threat_threshold": state.threat_threshold,
            },
            "active_band": cache.get("active_band", "UNK"),
            "timestamp":   cache["timestamp"],
            "simulated":   not request.app.state.scanner.hardware_ok,
        }

    # ── PSD Scan (legacy compat) ───────────────────────────────────────────

    @app.get("/api/psd_scan")
    @limiter.limit("60/minute")
    def api_psd_scan(request: Request,
                     center_mhz: float = 1090.0,
                     span_mhz:   float = 2.0):
        with state.lock:
            s = state.cache["status"]
            if s in ("starting",):
                return JSONResponse(status_code=503,
                    content={"status": "starting", "error": "Scanner warming up"})
            return {
                "center_mhz":     state.cache["center_mhz"],
                "noise_floor_db": state.cache["noise_floor_db"],
                "points":         state.cache["points"],
                "peaks":          state.cache.get("peaks", []),
                "timestamp":      state.cache["timestamp"],
                "status":         s,
            }

    # ── Detection History ─────────────────────────────────────────────────

    @app.get("/api/detections")
    @limiter.limit("30/minute")
    def api_detections(request: Request,
                       limit:     int  = 100,
                       real_only: bool = False):
        limit = max(1, min(limit, 1000))
        db: SignalDB = request.app.state.db
        records = db.get_recent(limit=limit, real_only=real_only)
        return {
            "count":   len(records),
            "records": [r.to_dict() for r in records],
        }

    # Legacy alias
    @app.get("/api/history")
    @limiter.limit("20/minute")
    def api_history(request: Request):
        db: SignalDB = request.app.state.db
        records  = db.get_recent(limit=100)
        threats  = db.get_recent(limit=100, real_only=True)
        return {
            "scans":   [r.to_dict() for r in records],
            "threats": [r.to_dict() for r in threats],
        }

    # ── Stats ─────────────────────────────────────────────────────────────

    @app.get("/api/stats")
    @limiter.limit("20/minute")
    def api_stats(request: Request):
        db: SignalDB = request.app.state.db
        return db.get_stats()

    # ── CSV Export ────────────────────────────────────────────────────────

    @app.get("/api/export")
    @limiter.limit("5/minute")
    def api_export(request: Request,
                   limit:     int  = 5000,
                   real_only: bool = False):
        _require_auth(request)
        db: SignalDB = request.app.state.db
        csv_data = db.export_csv(limit=limit, real_only=real_only)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=nsd_detections.csv"},
        )

    # ── PDF Report ────────────────────────────────────────────────────────

    @app.get("/api/report")
    @limiter.limit("3/minute")
    def api_report(request: Request, real_only: bool = True):
        _require_auth(request)
        db:      SignalDB   = request.app.state.db
        scanner: SDRScanner = request.app.state.scanner
        with state.lock:
            cycle_s = state.cache.get("cycle_time_s") or 0.0
        uptime  = time.time() - state.start_time
        try:
            pdf_bytes = generate_report(
                db=db,
                uptime_s=uptime,
                scan_cycle_s=cycle_s,
                hardware_ok=scanner.hardware_ok,
                real_only=real_only,
            )
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=nsd_report.pdf"},
        )

    # ── Token (localhost only) ─────────────────────────────────────────────

    @app.get("/api/token")
    @limiter.limit("5/minute")
    def api_token(request: Request):
        if request.client.host not in ("127.0.0.1", "::1", "localhost"):
            return JSONResponse(status_code=403, content={"error": "local only"})
        return {"token": request.app.state.api_token}

    # ── Autonomous Config ─────────────────────────────────────────────────

    @app.post("/api/autonomous")
    @limiter.limit("10/minute")
    async def api_autonomous(request: Request):
        _require_auth(request)
        body = await request.json()
        with state.lock:
            if "autonomous_enabled" in body:
                state.autonomous_enabled = bool(body["autonomous_enabled"])
            if "auto_engage" in body:
                state.auto_engage = bool(body["auto_engage"])
            if "threat_threshold" in body:
                state.threat_threshold = _sanitize_threshold(body["threat_threshold"])
        _audit("AUTONOMOUS_UPDATE", request.client.host,
               f"enabled={state.autonomous_enabled} auto={state.auto_engage}")
        return {
            "status":             "ok",
            "autonomous_enabled": state.autonomous_enabled,
            "auto_engage":        state.auto_engage,
            "threat_threshold":   state.threat_threshold,
        }

    # ── System Control ────────────────────────────────────────────────────

    @app.post("/api/control")
    @limiter.limit("10/minute")
    async def api_control(request: Request):
        _require_auth(request)
        body = await request.json()
        with state.lock:
            if "active" in body:
                state.system_active = bool(body["active"])
            if "mode" in body:
                state.system_mode = _sanitize_mode(body["mode"])
        _audit("CONTROL", request.client.host,
               f"active={state.system_active} mode={state.system_mode}")
        return {
            "status": "ok",
            "active": state.system_active,
            "mode":   state.system_mode,
        }

    # ── Audit Log ─────────────────────────────────────────────────────────

    @app.get("/api/audit")
    @limiter.limit("10/minute")
    async def api_audit(request: Request):
        _require_auth(request)
        return {"audit_log": list(_AUDIT_LOG[-50:])}
