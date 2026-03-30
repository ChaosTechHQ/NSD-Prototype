"""
api/routes.py — NSD v19 FastAPI Routes + Lifespan
ChaosTech Defense LLC

Endpoints:
  GET  /                    — redirect to /app
  GET  /app                 — serves index.html with NSD_TOKEN injected
  WS   /ws/live             — real-time scan + threat push (500ms)
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
  POST /api/drone/connect   — connect to intercept drone via MAVLink / SIM
  POST /api/drone/command   — send flight command (takeoff/land/rth/hover/patrol/emergency)
  GET  /api/drone/status    — live telemetry snapshot
"""

import os
import json
import time
import secrets
import logging
import asyncio
import threading
import random
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response, RedirectResponse, HTMLResponse
from pydantic import BaseModel
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

_VALID_MODES = {"RF_JAM", "GPS_SPOOF", "PROTOCOL", "SWARM_DISRUPT"}
_AUDIT_LOG   = []

# Path to index.html — resolved relative to this file
_FRONTEND_HTML = Path(__file__).parent.parent / "frontend" / "index.html"

# ---------------------------------------------------------------------------
# Drone state
# ---------------------------------------------------------------------------

@dataclass
class DroneState:
    connected:  bool   = False
    simulated:  bool   = False
    ip:         str    = ""
    state_str:  str    = "DISARMED"
    altitude:   float  = 0.0
    battery:    int    = 0
    gps:        str    = "NO FIX"
    signal:     str    = "--"
    mode:       str    = "STABILIZE"
    error:      str    = ""
    _vehicle:   object = field(default=None, repr=False)
    _lock:      threading.Lock = field(default_factory=threading.Lock, repr=False)

drone = DroneState()

try:
    import dronekit
    _DRONEKIT_AVAILABLE = True
    logger.info("DroneKit available — real MAVLink connections enabled")
except ImportError:
    _DRONEKIT_AVAILABLE = False
    logger.warning("DroneKit not installed — drone endpoints will use simulation mode")


def _connect_drone_thread(ip: str):
    conn_str = f"udp:{ip}:14550"
    logger.info(f"Drone connect thread started — {conn_str}")
    with drone._lock:
        drone.ip    = ip
        drone.error = ""

    if not _DRONEKIT_AVAILABLE:
        time.sleep(1.2)
        with drone._lock:
            drone.connected = True
            drone.simulated = True
            drone.state_str = "STANDBY"
            drone.altitude  = 0.0
            drone.battery   = random.randint(75, 99)
            drone.gps       = "3D FIX (8 sats)"
            drone.signal    = "STRONG"
            drone.mode      = "GUIDED"
        logger.info("Drone SIM connected")
        return

    try:
        vehicle = dronekit.connect(conn_str, wait_ready=True, timeout=15)
        with drone._lock:
            drone._vehicle  = vehicle
            drone.connected = True
            drone.simulated = False
            drone.state_str = str(vehicle.system_status.state)
            drone.altitude  = vehicle.location.global_relative_frame.alt or 0.0
            drone.battery   = vehicle.battery.level or 0
            drone.gps       = f"{vehicle.gps_0.fix_type}D FIX ({vehicle.gps_0.satellites_visible} sats)"
            drone.signal    = "OK"
            drone.mode      = vehicle.mode.name
        logger.info(f"Drone connected via MAVLink: {conn_str}")

        @vehicle.on_attribute('location.global_relative_frame')
        def _on_location(self, attr_name, value):
            with drone._lock:
                drone.altitude = round(value.alt or 0.0, 2)

        @vehicle.on_attribute('battery')
        def _on_battery(self, attr_name, value):
            with drone._lock:
                drone.battery = value.level or 0

        @vehicle.on_attribute('mode')
        def _on_mode(self, attr_name, value):
            with drone._lock:
                drone.mode = value.name

        @vehicle.on_attribute('system_status')
        def _on_status(self, attr_name, value):
            with drone._lock:
                drone.state_str = str(value.state)

    except Exception as e:
        with drone._lock:
            drone.connected = False
            drone.error     = str(e)
        logger.error(f"Drone connect failed: {e}")


def _sim_apply_command(cmd: str):
    with drone._lock:
        if cmd == "takeoff":
            drone.state_str = "ACTIVE"
            drone.mode      = "GUIDED"
            drone.altitude  = 20.0
        elif cmd == "land":
            drone.state_str = "LANDING"
            drone.mode      = "LAND"
            drone.altitude  = 0.0
        elif cmd == "rth":
            drone.state_str = "RETURNING"
            drone.mode      = "RTL"
        elif cmd == "hover":
            drone.mode      = "LOITER"
        elif cmd == "patrol":
            drone.state_str = "ACTIVE"
            drone.mode      = "AUTO"
            drone.altitude  = round(random.uniform(15.0, 40.0), 1)
        elif cmd == "emergency":
            drone.state_str = "DISARMED"
            drone.mode      = "STABILIZE"
            drone.altitude  = 0.0
            drone.connected = False


def _sim_drone_tick():
    if not (drone.connected and drone.simulated):
        return
    with drone._lock:
        if drone.state_str == "ACTIVE":
            drone.altitude = round(
                max(0.0, min(120.0, drone.altitude + random.uniform(-0.3, 0.5))), 1
            )
        drone.battery = max(0, drone.battery - random.randint(0, 1))


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


def _build_live_frame(app: FastAPI) -> dict:
    classifier: ThreatClassifier = app.state.classifier
    scanner:    SDRScanner       = app.state.scanner
    hw_ok = scanner.hardware_ok

    with state.lock:
        cache = dict(state.cache)

    bands = []
    for pt in cache.get("points", []):
        bands.append({
            "band":            pt.get("band", ""),
            "label":           pt.get("band", ""),
            "protocol":        pt.get("protocol", "--"),
            "freq_mhz":        pt.get("freq_mhz", 0),
            "power_dbm":       pt.get("power_db", 0),
            "noise_floor_dbm": cache.get("noise_floor_db"),
            "snr_db":          pt.get("snr_db"),
            "bandwidth_khz":   pt.get("bandwidth_khz"),
            "is_detection":    pt.get("is_detection", False),
            "simulated":       pt.get("simulated", not hw_ok),
        })

    return {
        "type":           "scan_update",
        "timestamp":      cache.get("timestamp"),
        "uptime_s":       round(time.time() - state.start_time, 1),
        "hardware_ok":    hw_ok,
        "simulated":      not hw_ok,
        "cycle_time_s":   cache.get("cycle_time_s"),
        "bands":          bands,
        "threats":        cache.get("threats", []),
        "threat_count":   classifier.get_threat_count(),
        "total_detected": classifier.get_total_detected(),
    }


# ---------------------------------------------------------------------------
# Background broadcast loop
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
            noise_readings.append(reading.noise_floor_db)
            points.append({
                "freq_mhz":      round(reading.peak_freq_hz / 1e6, 3),
                "power_db":      reading.peak_power_db,
                "band":          reading.label,
                "protocol":      reading.protocol,
                "snr_db":        reading.snr_db,
                "bandwidth_khz": round(reading.bandwidth_hz / 1e3, 1),
                "is_detection":  reading.is_detection,
                "simulated":     reading.simulated,
            })
            threat = classifier.process_band(reading)
            if threat is not None:
                threats.append(threat)
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

        # Tick simulated drone telemetry
        _sim_drone_tick()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(app: FastAPI):
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

    await asyncio.sleep(2.0)

    logger.info(f"NSD v19 started | hardware={'yes' if scanner.hardware_ok else 'sim'} "
                f"| db={db_path}")
    if not os.getenv("NSD_API_TOKEN"):
        logger.warning(f"NSD_API_TOKEN not set — generated token: {api_token}")

    broadcast_task = asyncio.create_task(_broadcast_loop(app))

    yield

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

    # ── Root redirect ────────────────────────────────────────────────────

    @app.get("/")
    def root_redirect():
        return RedirectResponse(url="/app", status_code=302)

    # ── Frontend ─────────────────────────────────────────────────────────

    @app.get("/app", response_class=HTMLResponse)
    @app.get("/app/", response_class=HTMLResponse)
    def serve_frontend(request: Request):
        try:
            html = _FRONTEND_HTML.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Frontend not found")
        token = request.app.state.api_token
        injection = f'<script>window.NSD_TOKEN="{token}";</script>\n'
        html = html.replace("<head>", "<head>\n" + injection, 1)
        return HTMLResponse(content=html)

    # ── WebSocket live feed ───────────────────────────────────────────────

    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket):
        await websocket.accept()
        logger.info(f"WebSocket connected: {websocket.client}")
        last_ts: Optional[float] = None
        try:
            while True:
                with state.lock:
                    ts = state.cache["timestamp"]
                if ts != last_ts and ts is not None:
                    last_ts = ts
                    frame = _build_live_frame(websocket.app)
                    await websocket.send_text(json.dumps(frame))
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected: {websocket.client}")
        except Exception as e:
            logger.warning(f"WebSocket error: {e}")

    # ── Health ────────────────────────────────────────────────────────────

    @app.get("/api/health")
    @limiter.limit("30/minute")
    def api_health(request: Request):
        with state.lock:
            status = state.cache["status"]
            ts     = state.cache["timestamp"]
        hw = request.app.state.scanner.hardware_ok
        return {
            "status":        "ok",
            "sdr_available": hw,
            "mode":          "hardware" if hw else "simulation",
            "last_scan":     ts,
        }

    # ── Hardware / Mission State ───────────────────────────────────────────

    @app.get("/api/hardware")
    @limiter.limit("60/minute")
    def api_hardware(request: Request):
        classifier: ThreatClassifier = request.app.state.classifier
        scanner:    SDRScanner       = request.app.state.scanner
        hw_ok = scanner.hardware_ok
        with state.lock:
            cache = dict(state.cache)

        bands = []
        for pt in cache.get("points", []):
            bands.append({
                "band":            pt.get("band", ""),
                "label":           pt.get("band", ""),
                "protocol":        pt.get("protocol", "--"),
                "freq_mhz":        pt.get("freq_mhz", 0),
                "power_dbm":       pt.get("power_db", 0),
                "noise_floor_dbm": cache.get("noise_floor_db"),
                "snr_db":          pt.get("snr_db"),
                "bandwidth_khz":   pt.get("bandwidth_khz"),
                "is_detection":    pt.get("is_detection", False),
                "simulated":       pt.get("simulated", not hw_ok),
            })

        return {
            "type":           "scan_update",
            "hardware_ok":    hw_ok,
            "simulated":      not hw_ok,
            "uptime_s":       round(time.time() - state.start_time, 1),
            "cycle_time_s":   cache.get("cycle_time_s"),
            "bands":          bands,
            "threats":        cache.get("threats", []),
            "threat_count":   classifier.get_threat_count(),
            "total_detected": classifier.get_total_detected(),
            "status":         cache["status"],
        }

    # ── PSD Scan (legacy compat) ───────────────────────────────────────────

    @app.get("/api/psd_scan")
    @limiter.limit("60/minute")
    def api_psd_scan(request: Request,
                     center_mhz: float = 1090.0,
                     span_mhz:   float = 2.0):
        with state.lock:
            s = state.cache["status"]
            if s == "starting":
                return JSONResponse(status_code=503,
                    content={"status": "starting", "error": "Scanner warming up"})
            return {
                "center_mhz":     state.cache.get("center_mhz"),
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

    @app.get("/api/history")
    @limiter.limit("20/minute")
    def api_history(request: Request,
                    limit:     int  = 100,
                    real_only: bool = False):
        limit = max(1, min(limit, 1000))
        db: SignalDB = request.app.state.db
        records = db.get_recent(limit=limit, real_only=real_only)
        return {
            "count":   len(records),
            "records": [r.to_dict() for r in records],
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
        uptime = time.time() - state.start_time
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

    # ── Drone Intercept ───────────────────────────────────────────────────

    class DroneConnectRequest(BaseModel):
        ip: str = "192.168.0.1"

    class DroneCommandRequest(BaseModel):
        command: str

    @app.post("/api/drone/connect")
    @limiter.limit("10/minute")
    def api_drone_connect(req: DroneConnectRequest, request: Request):
        """
        Initiate MAVLink connection to intercept drone.
        Non-blocking — returns immediately; poll /api/drone/status for result.
        Falls back to simulation when DroneKit is not installed.
        """
        with drone._lock:
            if drone.connected and drone._vehicle:
                try:
                    drone._vehicle.close()
                except Exception:
                    pass
            drone.connected = False
            drone._vehicle  = None

        t = threading.Thread(
            target=_connect_drone_thread,
            args=(req.ip,),
            daemon=True,
            name="drone-connect",
        )
        t.start()

        mode = "simulation" if not _DRONEKIT_AVAILABLE else "MAVLink"
        logger.info(f"Drone connect initiated: {req.ip} via {mode}")
        return {
            "status":    "ok",
            "connected": False,
            "message":   f"Connecting to {req.ip} via {mode}...",
        }

    @app.post("/api/drone/command")
    @limiter.limit("30/minute")
    def api_drone_command(req: DroneCommandRequest, request: Request):
        """
        Send flight command to intercept drone.
        Valid commands: takeoff | land | rth | hover | patrol | emergency
        """
        cmd = req.command.lower().strip()
        VALID = {"takeoff", "land", "rth", "hover", "patrol", "emergency"}
        if cmd not in VALID:
            return {"status": "error", "message": f"Unknown command '{cmd}'. Valid: {sorted(VALID)}"}

        with drone._lock:
            connected = drone.connected
            vehicle   = drone._vehicle
            simulated = drone.simulated

        if not connected and cmd != "emergency":
            return {"status": "error", "message": "Drone not connected"}

        if simulated or not _DRONEKIT_AVAILABLE:
            _sim_apply_command(cmd)
            logger.info(f"[SIM] Drone command: {cmd}")
            return {"status": "ok", "message": f"{cmd.upper()} executed (SIM)"}

        try:
            import dronekit as dk
            if cmd == "takeoff":
                vehicle.mode  = dk.VehicleMode("GUIDED")
                vehicle.armed = True
                while not vehicle.armed:
                    time.sleep(0.5)
                vehicle.simple_takeoff(20)
            elif cmd == "land":
                vehicle.mode = dk.VehicleMode("LAND")
            elif cmd == "rth":
                vehicle.mode = dk.VehicleMode("RTL")
            elif cmd == "hover":
                vehicle.mode = dk.VehicleMode("LOITER")
            elif cmd == "patrol":
                vehicle.mode = dk.VehicleMode("AUTO")
            elif cmd == "emergency":
                vehicle.armed = False

            logger.info(f"Drone MAVLink command sent: {cmd}")
            return {"status": "ok", "message": f"{cmd.upper()} sent"}

        except Exception as e:
            logger.error(f"Drone command error ({cmd}): {e}")
            return {"status": "error", "message": str(e)}

    @app.get("/api/drone/status")
    @limiter.limit("60/minute")
    def api_drone_status(request: Request):
        """Return current drone telemetry snapshot."""
        with drone._lock:
            return {
                "connected": drone.connected,
                "simulated": drone.simulated,
                "state":     drone.state_str,
                "altitude":  drone.altitude,
                "battery":   drone.battery,
                "gps":       drone.gps,
                "signal":    drone.signal,
                "mode":      drone.mode,
                "error":     drone.error,
            }



    @app.get("/api/drone/location")
    def api_drone_location():
        """Return base coordinates and geofence radius from env."""
        return {
            "base_lat": float(os.environ.get("NSD_BASE_LAT", "38.8318")),
            "base_lon": float(os.environ.get("NSD_BASE_LON", "-76.9425")),
            "geofence_radius": int(os.environ.get("NSD_GEOFENCE_RADIUS", "500")),
        }

        # ── Autonomous Intercept Engine ──────────────────────────────────
        _auto_state = {"enabled": False, "threshold": "HIGH", "cooldown": 60, "last_intercept": 0}

        @app.post("/api/autonomous")
        @require_token
        def api_autonomous(request: Request, body: dict = None):
            """Enable / configure autonomous intercept mode."""
            import time
            data = body or {}
            if "enabled" in data:
                _auto_state["enabled"] = bool(data["enabled"])
            if "threshold" in data:
                _auto_state["threshold"] = str(data["threshold"]).upper()
            if "cooldown" in data:
                _auto_state["cooldown"] = int(data["cooldown"])
            logger.info(f"Autonomous mode updated: {_auto_state}")
            return {"status": "ok", "autonomous": _auto_state}

        @app.get("/api/autonomous")
        def api_autonomous_status():
            """Return current autonomous intercept state."""
            return {"autonomous": _auto_state}

        def _autonomous_watcher():
            """Background thread: fires drone intercept on CRITICAL/HIGH threats."""
            import time
            LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            while True:
                try:
                    time.sleep(3)
                    if not _auto_state["enabled"]:
                        continue
                    now = time.time()
                    if now - _auto_state["last_intercept"] < _auto_state["cooldown"]:
                        continue
                    threats = scanner.get_active_threats() if hasattr(scanner, 'get_active_threats') else []
                    threshold_idx = LEVELS.index(_auto_state["threshold"]) if _auto_state["threshold"] in LEVELS else 2
                    triggered = [t for t in threats if LEVELS.index(t.get("level", "LOW")) >= threshold_idx]
                    if triggered:
                        t = triggered[0]
                        logger.warning(f"[AUTO] Threat {t.get('id')} triggered intercept — {t.get('freq_mhz')} MHz | {t.get('level')}")
                        _auto_state["last_intercept"] = now
                        drone._sim_command("takeoff")
                        time.sleep(2)
                        drone._sim_command("patrol")
                except Exception as e:
                    logger.error(f"[AUTO] Watcher error: {e}")

        import threading
        _watcher_thread = threading.Thread(target=_autonomous_watcher, daemon=True)
        _watcher_thread.start()
        logger.info("Autonomous intercept watcher started.")

    return app
