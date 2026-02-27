# nsd_api.py — ChaosTech Defense NSD RF Backend
# PROTOTYPE — not production

import time
import threading
import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from rtlsdr.rtlsdr import LibUSBError
from psd_scanner import scan_band, detect_peaks

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared state ──────────────────────────────────────────────
_lock   = threading.Lock()
_cache  = {
    "center_mhz":     1090.0,
    "noise_floor_db": None,
    "points":         [],
    "peaks":          [],
    "timestamp":      None,
    "status":         "starting",
    "error":          None,
}

_scan_center_mhz = 1090.0
_scan_span_mhz   = 2.0

# ── Background scanner thread ────────────────────────────────
def scanner_loop():
    global _scan_center_mhz, _scan_span_mhz

    print("[NSD] Background scanner started.")
    while True:
        try:
            center_hz = _scan_center_mhz * 1e6
            span_hz   = _scan_span_mhz   * 1e6

            freqs, psd_db = scan_band(center_hz, span_hz=span_hz)
            detection = detect_peaks(freqs, psd_db)

            points = [
                {"freq_mhz": float(f / 1e6), "power_db": float(p)}
                for f, p in zip(freqs, psd_db)
            ]

            with _lock:
                _cache["center_mhz"]     = _scan_center_mhz
                _cache["noise_floor_db"] = detection["noise_floor_db"]
                _cache["points"]         = points
                _cache["peaks"]          = [
                    {"freq_mhz": pk["freq_hz"] / 1e6, "power_db": pk["power_db"]}
                    for pk in detection["peaks"]
                ]
                _cache["timestamp"] = time.time()
                _cache["status"]    = "ok"
                _cache["error"]     = None

        except LibUSBError as e:
            with _lock:
                _cache["status"] = "sdr_error"
                _cache["error"]  = str(e)
            print(f"[NSD] SDR error: {e} — retrying in 3s")
            time.sleep(3)
            continue

        except Exception as e:
            with _lock:
                _cache["status"] = "error"
                _cache["error"]  = str(e)
            print(f"[NSD] Scan error: {e} — retrying in 3s")
            time.sleep(3)
            continue

        # Successful scan — small delay before next capture
        time.sleep(1)


# Start background thread on startup
_scanner_thread = threading.Thread(target=scanner_loop, daemon=True)
_scanner_thread.start()


# ── API endpoints ─────────────────────────────────────────────
@app.get("/api/health")
def api_health():
    with _lock:
        status    = _cache["status"]
        timestamp = _cache["timestamp"]
    return {
        "status":        "ok",
        "sdr_available": status == "ok",
        "last_scan":     timestamp,
    }


@app.get("/api/psd_scan")
def api_psd_scan(center_mhz: float = 1090.0, span_mhz: float = 2.0):
    global _scan_center_mhz, _scan_span_mhz

    # Update scan target if changed
    if center_mhz != _scan_center_mhz or span_mhz != _scan_span_mhz:
        _scan_center_mhz = center_mhz
        _scan_span_mhz   = span_mhz

    with _lock:
        status = _cache["status"]
        if status == "starting" or _cache["timestamp"] is None:
            return JSONResponse(
                status_code=503,
                content={"status": "starting", "error": "Scanner warming up"},
            )
        if status in ("sdr_error", "error"):
            return JSONResponse(
                status_code=503,
                content={"status": status, "error": _cache["error"]},
            )
        return {
            "center_mhz":     _cache["center_mhz"],
            "noise_floor_db": _cache["noise_floor_db"],
            "points":         _cache["points"],
            "peaks":          _cache["peaks"],
            "timestamp":      _cache["timestamp"],
            "status":         "ok",
        }
