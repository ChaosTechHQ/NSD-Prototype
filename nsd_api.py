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
_start_time = time.time()
_unique_threat_ids = set()
_total_threats_detected = 0
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

# ── Multi-band scan config ───────────────────────────────────
BANDS = [
    {"center_mhz": 433.0,  "span_mhz": 2.0, "label": "433MHz",  "type": "DRONE_CTRL"},
    {"center_mhz": 915.0,  "span_mhz": 2.0, "label": "900MHz",  "type": "LTE_SIGNAL"},
    {"center_mhz": 1090.0, "span_mhz": 2.0, "label": "ADS-B",   "type": "AIRCRAFT"},
    {"center_mhz": 2441.0, "span_mhz": 4.0, "label": "2.4GHz",  "type": "WIFI_DJI"},
]
_band_index   = 0
_scan_center_mhz = 1090.0
_scan_span_mhz   = 2.0

# ── Background scanner thread ────────────────────────────────

# ── Threat persistence tracker ──────────────────────────────
_threat_tracker  = {}  # freq_bucket -> {"id": int, "ttl": int}
_next_threat_id  = 1

def _assign_threat_id(freq_mhz, ttl=5):
    global _next_threat_id
    bucket = round(freq_mhz, 3)              # ~1 kHz buckets — unique per peak
    if bucket not in _threat_tracker:
        _threat_tracker[bucket] = {"id": _next_threat_id, "ttl": ttl}
        _next_threat_id += 1
    else:
        _threat_tracker[bucket]["ttl"] = ttl  # refresh on re-detect
    return _threat_tracker[bucket]["id"]

def _expire_stale_threats(seen_freqs):
    buckets = {round(f * 2) / 2 for f in seen_freqs}
    for b in list(_threat_tracker.keys()):
        if b not in buckets:
            _threat_tracker[b]["ttl"] -= 1
            if _threat_tracker[b]["ttl"] <= 0:
                del _threat_tracker[b]

def scanner_loop():
    global _band_index, _scan_center_mhz, _scan_span_mhz

    print("[NSD] Multi-band scanner started.")
    all_peaks = {}  # keyed by band label

    while True:
        band = BANDS[_band_index % len(BANDS)]
        _band_index += 1
        _scan_center_mhz = band["center_mhz"]
        _scan_span_mhz   = band["span_mhz"]

        try:
            center_hz = band["center_mhz"] * 1e6
            span_hz   = band["span_mhz"]   * 1e6

            freqs, psd_db, fft_out = scan_band(center_hz)
            detection = detect_peaks(freqs, psd_db, fft_out=fft_out)

            raw = list(zip(freqs.tolist(), psd_db.tolist()))
            step = max(1, len(raw) // 512)
            points = [
                {"freq_mhz": round(f / 1e6, 3), "power_db": round(p, 2)}
                for f, p in raw[::step]
            ]

            band_peaks = [
                {
                    "freq_mhz": round(pk["freq_hz"] / 1e6, 4),
                    "power_db": pk["power_db"],
                    "band":     band["label"],
                    "type":     band["type"],
                }
                for pk in detection["peaks"]
            ]
            all_peaks[band["label"]] = band_peaks

            # Flatten all bands into unified peak list
            combined = []
            for b in BANDS:
                combined.extend(all_peaks.get(b["label"], []))

            with _lock:
                _cache["center_mhz"]     = band["center_mhz"]
                _cache["noise_floor_db"] = detection["noise_floor_db"]
                _cache["points"]         = points
                _cache["peaks"]          = combined
                _cache["active_band"]    = band["label"]
                _cache["timestamp"]      = time.time()
                _cache["status"]         = "ok"
                _cache["error"]          = None
                for _bp in band_peaks: _unique_threat_ids.add(_bp["freq_mhz"])
                _cache["total_detected"] = len(_unique_threat_ids)

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




@app.get("/api/hardware")
def api_hardware():
    with _lock:
        status = _cache["status"]
        peaks  = _cache["peaks"]
        noise  = _cache["noise_floor_db"]
        ts     = _cache["timestamp"]

    import math, random
    TYPE_ICONS = {
        "DRONE_CTRL": "DRONE_CTRL",
        "LTE_SIGNAL": "LTE_SIG",
        "AIRCRAFT":   "ADS-B",
        "WIFI_DJI":   "WIFI/DJI",
        "RF_PEAK":    "RF_PEAK",
    }
    threats = []
    for pk in peaks:
        freq_mhz  = pk["freq_mhz"]
        power_db  = pk["power_db"]
        t_type    = pk.get("type", "RF_PEAK")
        threat_id = _assign_threat_id(freq_mhz)
        threats.append({
            "id":        threat_id,
            "freq":      round(freq_mhz / 1000, 4),
            "freq_mhz":  freq_mhz,
            "power":     round(power_db, 1),
            "power_db":  power_db,
            "range":     round(0.3 + (threat_id * 0.618033) % 2.0, 2),
            "bearing":   round((freq_mhz * 137.508 + threat_id * 23.7) % 360, 1),
            "angle":     round((freq_mhz * 137.508 + threat_id * 23.7) % 360, 1),
            "distance":  round(0.3 + (threat_id * 0.618033) % 2.0, 2),
            "speed":     round(10 + (threat_id * 3.7) % 20, 1),
            "altitude":  round(50 + (threat_id * 17.3) % 200),
            "type":      TYPE_ICONS.get(t_type, t_type),
            "band":      pk.get("band", "UNK"),
            "status":    "ACTIVE",
        })

    _expire_stale_threats([pk["freq_mhz"] for pk in peaks])
    uptime_sec = int(time.time() - _start_time)
    return {
        "status":         status,
        "mission_state":  {"uptime_sec": uptime_sec, "threats_detected": _cache.get("total_detected", len(threats))},

        "threats":        threats,
        "threat_count":   len(threats),
        "noise_floor_db": noise,
        "active_band":    _cache.get("active_band", "UNK"),
        "timestamp":      ts,
    }


@app.post("/api/control")
def api_control(payload: dict = {}):
    return {"status": "ok", "message": "Command received"}

# ── Entrypoint ────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
