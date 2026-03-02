# api/routes.py — ChaosTech NSD API endpoints
import time, os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from scanner.state import state
import nsd_db

limiter = Limiter(key_func=get_remote_address)

_API_TOKEN = os.getenv("NSD_API_TOKEN", "")
_AUDIT_LOG = []
_VALID_MODES = {"RF_JAM", "GPS_SPOOF", "PROTOCOL", "SWARM_DISRUPT"}

def _require_auth(request: Request):
    token = request.headers.get("X-NSD-Token", "")
    if token != _API_TOKEN:
        _audit("UNAUTHORIZED", request.client.host, "rejected")
        raise HTTPException(status_code=403, detail="Unauthorized")

def _audit(action, source, detail):
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "action": action, "source": source, "detail": detail}
    _AUDIT_LOG.append(entry)
    if len(_AUDIT_LOG) > 500:
        _AUDIT_LOG.pop(0)
    print(f"[AUDIT] {entry['time']} {source} {action}: {detail}")

def _sanitize_mode(mode):
    if mode not in _VALID_MODES:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")
    return mode

def _sanitize_threshold(val):
    try:
        return max(0, min(100, int(val)))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="threshold must be 0-100")

def register_routes(app: FastAPI):

    @app.get("/api/health")
    @limiter.limit("30/minute")
    def api_health(request: Request):
        with state.lock:
            status = state.cache["status"]
            ts     = state.cache["timestamp"]
        return {"status": "ok", "sdr_available": status == "ok", "last_scan": ts}

    @app.get("/api/psd_scan")
    @limiter.limit("60/minute")
    def api_psd_scan(request: Request, center_mhz: float = 1090.0, span_mhz: float = 2.0):
        with state.lock:
            if state.cache["status"] == "starting" or state.cache["timestamp"] is None:
                return JSONResponse(status_code=503,
                    content={"status": "starting", "error": "Scanner warming up"})
            if state.cache["status"] in ("sdr_error", "error"):
                return JSONResponse(status_code=503,
                    content={"status": state.cache["status"], "error": state.cache["error"]})
            return {
                "center_mhz":     state.cache["center_mhz"],
                "noise_floor_db": state.cache["noise_floor_db"],
                "points":         state.cache["points"],
                "peaks":          state.cache["peaks"],
                "timestamp":      state.cache["timestamp"],
                "status":         "ok",
            }

    @app.get("/api/hardware")
    @limiter.limit("60/minute")
    def api_hardware(request: Request):
        with state.lock:
            return {
                "status":   state.cache["status"],
                "mission_state": {
                    "uptime_sec":          int(time.time() - state.start_time),
                    "threats_detected":    state.cache.get("total_detected", 0),
                    "swarms_detected":     state.swarms_detected,
                    "active_swarms":       len(state.active_swarms),
                    "threats_engaged":     state.threats_engaged,
                    "threats_neutralized": state.threats_neutralized,
                    "autonomous_actions":  state.autonomous_actions,
                    "swarms_eliminated":   state.swarms_eliminated,
                },
                "threats":        list(state.cache.get("threats", [])),
                "threat_count":   len(state.cache.get("threats", [])),
                "noise_floor_db": state.cache["noise_floor_db"],
                "system_state":   {"active": state.system_active, "mode": state.system_mode,
                                   "power_level": 100, "energy_reserves": 100},
                "autonomous_mode": {"enabled": state.autonomous_enabled,
                                    "auto_engage": state.auto_engage,
                                    "threat_threshold": state.threat_threshold},
                "active_band":    state.cache.get("active_band", "UNK"),
                "timestamp":      state.cache["timestamp"],
            }

    @app.get("/api/history")
    @limiter.limit("20/minute")
    def api_history(request: Request):
        return JSONResponse({
            "scans":   nsd_db.get_scan_history(50),
            "threats": nsd_db.get_threat_history(100),
        })

    @app.get("/api/token")
    @limiter.limit("5/minute")
    def api_token(request: Request):
        if request.client.host not in ("127.0.0.1", "::1", "localhost"):
            return JSONResponse(status_code=403, content={"error": "local only"})
        return {"token": _API_TOKEN}

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
        return {"status": "ok", "autonomous_enabled": state.autonomous_enabled,
                "auto_engage": state.auto_engage,
                "threat_threshold": state.threat_threshold}

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
        return {"status": "ok", "active": state.system_active, "mode": state.system_mode}

    @app.get("/api/audit")
    @limiter.limit("10/minute")
    async def api_audit(request: Request):
        _require_auth(request)
        return {"audit_log": list(_AUDIT_LOG[-50:])}
