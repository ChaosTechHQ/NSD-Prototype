"""
NSD v19 - FastAPI Backend
ChaosTech Defense LLC

Architecture:
  SDRScanner (background thread) → ThreatClassifier → SignalDB → FastAPI REST + WebSocket

Endpoints:
  GET  /                     — serve frontend/index.html
  GET  /api/status           — system health
  GET  /api/hardware         — full threat + band snapshot (REST fallback)
  GET  /api/signal_count     — active / total counts
  GET  /api/psd_scan         — per-band power summary
  GET  /api/history          — recent detections from SQLite
  GET  /api/history/stats    — summary statistics
  GET  /api/export/csv       — download all detections as CSV
  GET  /api/report/pdf       — generate PDF session report
  POST /api/drone/connect    — connect to intercept drone via MAVLink
  POST /api/drone/command    — send flight command (takeoff/land/rth/hover/patrol/emergency)
  GET  /api/drone/status     — live telemetry (state, altitude, battery, gps, signal, mode)
  WS   /ws/live              — ~1 Hz scan_update broadcast

Run:
  uvicorn nsd_api:app --host 0.0.0.0 --port 8000
"""

import asyncio
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sdr_engine import SDRScanner, ScanCycle
from threat_classifier import ThreatClassifier, ThreatObject
from signal_db import SignalDB
from report_generator import generate_report

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nsd.api")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
scanner    = SDRScanner(device_index=0, sim_fallback=True)
classifier = ThreatClassifier(dedup_window_s=8.0, max_threats=100)
db         = SignalDB()
_start_time = time.time()

_logged_threat_ids: set = set()
_last_scan_cycle_s: float = 0.0

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        logger.info(f"WS client connected. Total: {len(self._connections)}")

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info(f"WS client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Drone state
# ---------------------------------------------------------------------------
@dataclass
class DroneState:
    connected:   bool  = False
    simulated:   bool  = False
    ip:          str   = ""
    state:       str   = "DISARMED"
    altitude:    float = 0.0
    battery:     int   = 0
    gps:         str   = "NO FIX"
    signal:      str   = "--"
    mode:        str   = "STABILIZE"
    error:       str   = ""
    _vehicle:    object = field(default=None, repr=False)  # dronekit Vehicle
    _lock:       threading.Lock = field(default_factory=threading.Lock, repr=False)

drone = DroneState()

# Try to import DroneKit; fall back to simulation if not installed
try:
    import dronekit
    _DRONEKIT_AVAILABLE = True
    logger.info("DroneKit available — real MAVLink connections enabled")
except ImportError:
    _DRONEKIT_AVAILABLE = False
    logger.warning("DroneKit not installed — drone endpoints will use simulation mode")


def _connect_drone_thread(ip: str):
    """Background thread: establish MAVLink connection and update DroneState."""
    conn_str = f"udp:{ip}:14550"
    logger.info(f"Drone connect thread started — {conn_str}")
    with drone._lock:
        drone.ip = ip
        drone.error = ""

    if not _DRONEKIT_AVAILABLE:
        # Simulation mode
        import random
        time.sleep(1.2)
        with drone._lock:
            drone.connected  = True
            drone.simulated  = True
            drone.state      = "STANDBY"
            drone.altitude   = 0.0
            drone.battery    = random.randint(75, 99)
            drone.gps        = "3D FIX (8 sats)"
            drone.signal     = "STRONG"
            drone.mode       = "GUIDED"
        logger.info("Drone SIM connected")
        return

    try:
        vehicle = dronekit.connect(conn_str, wait_ready=True, timeout=15)
        with drone._lock:
            drone._vehicle  = vehicle
            drone.connected = True
            drone.simulated = False
            drone.state     = str(vehicle.system_status.state)
            drone.altitude  = vehicle.location.global_relative_frame.alt or 0.0
            drone.battery   = vehicle.battery.level or 0
            drone.gps       = f"{vehicle.gps_0.fix_type}D FIX ({vehicle.gps_0.satellites_visible} sats)"
            drone.signal    = "OK"
            drone.mode      = vehicle.mode.name
        logger.info(f"Drone connected via MAVLink: {conn_str}")

        # Attribute listeners for live telemetry
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
                drone.state = str(value.state)

    except Exception as e:
        with drone._lock:
            drone.connected = False
            drone.error     = str(e)
        logger.error(f"Drone connect failed: {e}")


def _sim_drone_update():
    """Periodically nudge simulated telemetry so the UI looks alive."""
    import random
    if not (drone.connected and drone.simulated):
        return
    with drone._lock:
        if drone.state == "ACTIVE":
            drone.altitude = round(drone.altitude + random.uniform(-0.3, 0.5), 1)
            drone.altitude = max(0.0, min(drone.altitude, 120.0))
        drone.battery = max(0, drone.battery - random.randint(0, 1))


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    scanner.start()
    logger.info("NSD v19 backend started.")
    asyncio.create_task(_broadcast_loop())
    asyncio.create_task(_sim_telemetry_loop())
    yield
    scanner.stop()
    db.stop()
    if drone._vehicle:
        try:
            drone._vehicle.close()
        except Exception:
            pass
    logger.info("NSD v19 backend stopped.")

app = FastAPI(title="NSD v19 API", version="19.1.0", lifespan=lifespan)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------
async def _sim_telemetry_loop():
    """Update simulated drone telemetry every 2 s."""
    while True:
        await asyncio.sleep(2)
        _sim_drone_update()


async def _broadcast_loop():
    """Runs as a background asyncio task. Broadcasts at ~1 Hz."""
    global _logged_threat_ids
    last_cycle_ts = 0.0

    while True:
        await asyncio.sleep(0.5)
        scan = scanner.get_latest_scan()
        if scan is None or scan.timestamp == last_cycle_ts:
            continue
        last_cycle_ts = scan.timestamp

        band_data = []
        for reading in scan.bands:
            classifier.process_band(reading)
            band_data.append({
                "band":            reading.band_name,
                "label":           reading.label,
                "protocol":        reading.protocol,
                "freq_mhz":        round(reading.peak_freq_hz / 1e6, 3),
                "power_dbm":       reading.peak_power_db,
                "noise_floor_dbm": reading.noise_floor_db,
                "snr_db":          reading.snr_db,
                "bandwidth_khz":   round(reading.bandwidth_hz / 1e3, 1),
                "is_detection":    reading.is_detection,
                "simulated":       reading.simulated,
            })

        active_threats = classifier.get_active_threats()

        for t in active_threats:
            if t.id not in _logged_threat_ids:
                db.log_detection(
                    band=t.band_name,
                    freq_mhz=t.freq_mhz,
                    power_db=t.power_dbm,
                    noise_floor_db=t.noise_floor_dbm,
                    snr_db=t.snr_db,
                    bandwidth_khz=t.bandwidth_khz,
                    protocol=t.protocol,
                    threat_level=t.threat_level,
                    threat_score=t.threat_score,
                    simulated=t.simulated,
                )
                _logged_threat_ids.add(t.id)

        active_ids = {t.id for t in active_threats}
        _logged_threat_ids &= active_ids | {
            tid for tid in _logged_threat_ids
            if any(tid == t.id for t in active_threats)
        }

        global _last_scan_cycle_s
        _last_scan_cycle_s = round(scan.cycle_time_s, 3)

        payload = {
            "type":           "scan_update",
            "timestamp":      scan.timestamp,
            "uptime_s":       round(time.time() - _start_time, 1),
            "hardware_ok":    scanner.hardware_ok,
            "simulated":      scan.simulated,
            "cycle_time_s":   round(scan.cycle_time_s, 3),
            "bands":          band_data,
            "threats":        [_threat_to_dict(t) for t in active_threats],
            "threat_count":   classifier.get_threat_count(),
            "total_detected": classifier.get_total_detected(),
        }

        await ws_manager.broadcast(payload)

# ---------------------------------------------------------------------------
# REST Endpoints — core
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    index = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index):
        return FileResponse(index)
    return HTMLResponse("<h1>NSD v19 — Frontend not found</h1>")

@app.get("/api/status")
async def api_status():
    return {
        "status":      "ACTIVE" if scanner.hardware_ok else "SIMULATION",
        "hardware_ok": scanner.hardware_ok,
        "uptime_s":    round(time.time() - _start_time, 1),
        "version":     "19.1.0",
    }

@app.get("/api/hardware")
async def api_hardware():
    scan = scanner.get_latest_scan()
    active_threats = classifier.get_active_threats()
    bands = []
    if scan:
        for r in scan.bands:
            bands.append({
                "band":            r.band_name,
                "label":           r.label,
                "protocol":        r.protocol,
                "freq_mhz":        round(r.peak_freq_hz / 1e6, 3),
                "power_dbm":       r.peak_power_db,
                "noise_floor_dbm": r.noise_floor_db,
                "snr_db":          r.snr_db,
                "bandwidth_khz":   round(r.bandwidth_hz / 1e3, 1),
                "is_detection":    r.is_detection,
                "simulated":       r.simulated,
            })
    return {
        "status":         "ACTIVE" if scanner.hardware_ok else "SIMULATION",
        "hardware_ok":    scanner.hardware_ok,
        "uptime_s":       round(time.time() - _start_time, 1),
        "threat_count":   classifier.get_threat_count(),
        "total_detected": classifier.get_total_detected(),
        "threats":        [_threat_to_dict(t) for t in active_threats],
        "bands":          bands,
        "simulated":      scan.simulated if scan else True,
    }

@app.get("/api/signal_count")
async def api_signal_count():
    return {
        "active": classifier.get_threat_count(),
        "total":  classifier.get_total_detected(),
    }

@app.get("/api/psd_scan")
async def api_psd_scan():
    scan = scanner.get_latest_scan()
    if scan is None:
        return {"bands": [], "simulated": True}
    return {
        "bands": [
            {
                "label":      r.label,
                "center_mhz": round(r.center_hz / 1e6, 3),
                "power_dbm":  r.peak_power_db,
                "noise_dbm":  r.noise_floor_db,
                "snr_db":     r.snr_db,
                "detection":  r.is_detection,
                "simulated":  r.simulated,
            }
            for r in scan.bands
        ],
        "simulated": scan.simulated,
    }

# ---------------------------------------------------------------------------
# History endpoints
# ---------------------------------------------------------------------------

@app.get("/api/history")
async def api_history(
    limit:     int  = Query(default=100, ge=1, le=1000),
    real_only: bool = Query(default=False),
):
    records = db.get_recent(limit=limit, real_only=real_only)
    return {
        "count":   len(records),
        "records": [r.to_dict() for r in records],
    }

@app.get("/api/history/stats")
async def api_history_stats():
    return db.get_stats()

@app.get("/api/export/csv")
async def api_export_csv(
    limit:     int  = Query(default=5000, ge=1, le=50000),
    real_only: bool = Query(default=False),
):
    csv_data = db.export_csv(limit=limit, real_only=real_only)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=nsd_detections.csv"},
    )

@app.get("/api/report/pdf")
async def api_report_pdf(real_only: bool = Query(default=True)):
    import datetime
    uptime  = time.time() - _start_time
    hw_ok   = scanner.hardware_ok if scanner else False
    cycle_s = _last_scan_cycle_s
    try:
        pdf_bytes = generate_report(
            db=db,
            uptime_s=uptime,
            scan_cycle_s=cycle_s,
            hardware_ok=hw_ok,
            real_only=real_only,
        )
    except Exception as e:
        logger.error(f"PDF report generation failed: {e}")
        return Response(content=f"Report generation failed: {e}",
                        status_code=500, media_type="text/plain")
    now_str  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"NSD_v19_Report_{now_str}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

# ---------------------------------------------------------------------------
# Drone intercept endpoints
# ---------------------------------------------------------------------------

class DroneConnectRequest(BaseModel):
    ip: str = "192.168.0.1"

class DroneCommandRequest(BaseModel):
    command: str   # takeoff | land | rth | hover | patrol | emergency


@app.post("/api/drone/connect")
async def api_drone_connect(req: DroneConnectRequest):
    """
    Initiate a MAVLink connection to the intercept drone.
    Runs in a background thread; returns immediately with { status, message }.
    If DroneKit is not installed, enters simulation mode automatically.
    """
    with drone._lock:
        if drone.connected:
            # Already connected — close existing before reconnecting
            if drone._vehicle:
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
    return {
        "status":  "ok",
        "connected": False,   # connection is async; poll /api/drone/status
        "message": f"Connecting to {req.ip} via {mode}...",
    }


@app.post("/api/drone/command")
async def api_drone_command(req: DroneCommandRequest):
    """
    Send a flight command to the connected intercept drone.

    Supported commands:
      takeoff   — arm + takeoff to 20 m AGL
      land      — initiate landing sequence
      rth       — return-to-home
      hover     — hold current position (LOITER mode)
      patrol    — resume autonomous patrol mission
      emergency — immediate disarm / kill switch
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

    # — Simulation path —
    if simulated or not _DRONEKIT_AVAILABLE:
        _sim_apply_command(cmd)
        logger.info(f"[SIM] Drone command executed: {cmd}")
        return {"status": "ok", "message": f"{cmd.upper()} executed (SIM)"}

    # — Real MAVLink path —
    try:
        import dronekit
        if cmd == "takeoff":
            vehicle.mode = dronekit.VehicleMode("GUIDED")
            vehicle.armed = True
            while not vehicle.armed:
                time.sleep(0.5)
            vehicle.simple_takeoff(20)
        elif cmd == "land":
            vehicle.mode = dronekit.VehicleMode("LAND")
        elif cmd == "rth":
            vehicle.mode = dronekit.VehicleMode("RTL")
        elif cmd == "hover":
            vehicle.mode = dronekit.VehicleMode("LOITER")
        elif cmd == "patrol":
            vehicle.mode = dronekit.VehicleMode("AUTO")
        elif cmd == "emergency":
            vehicle.armed = False

        logger.info(f"Drone command sent via MAVLink: {cmd}")
        return {"status": "ok", "message": f"{cmd.upper()} sent"}

    except Exception as e:
        logger.error(f"Drone command error ({cmd}): {e}")
        return {"status": "error", "message": str(e)}


@app.get("/api/drone/status")
async def api_drone_status():
    """
    Return current drone telemetry snapshot.
    Reads from DroneState which is updated either by DroneKit attribute
    listeners (real mode) or by the _sim_telemetry_loop (sim mode).
    """
    with drone._lock:
        return {
            "connected": drone.connected,
            "simulated": drone.simulated,
            "state":     drone.state,
            "altitude":  drone.altitude,
            "battery":   drone.battery,
            "gps":       drone.gps,
            "signal":    drone.signal,
            "mode":      drone.mode,
            "error":     drone.error,
        }


def _sim_apply_command(cmd: str):
    """Apply simulated state changes for a given flight command."""
    import random
    with drone._lock:
        if cmd == "takeoff":
            drone.state    = "ACTIVE"
            drone.mode     = "GUIDED"
            drone.altitude = 20.0
        elif cmd == "land":
            drone.state    = "LANDING"
            drone.mode     = "LAND"
            drone.altitude = 0.0
        elif cmd == "rth":
            drone.state    = "RETURNING"
            drone.mode     = "RTL"
        elif cmd == "hover":
            drone.mode     = "LOITER"
        elif cmd == "patrol":
            drone.state    = "ACTIVE"
            drone.mode     = "AUTO"
            drone.altitude = round(random.uniform(15.0, 40.0), 1)
        elif cmd == "emergency":
            drone.state    = "DISARMED"
            drone.mode     = "STABILIZE"
            drone.altitude = 0.0
            drone.connected = False

# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _threat_to_dict(t: ThreatObject) -> dict:
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
        "simulated":       t.simulated,
        "timestamp":       t.timestamp,
    }

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("nsd_api:app", host="0.0.0.0", port=8000, reload=False)
