# nsd_rf_bridge.py — FastAPI wrapper around psd_scanner.py
# ChaosTech Defense NSD — RF Bridge Layer

import threading, time, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from psd_scanner import scan_band, detect_peaks
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DEFAULT_CENTER_MHZ = 1090
DEFAULT_SPAN_MHZ   = 2

latest_scan = {"status": "waiting", "points": [], "peaks": [], "noise_floor_db": None, "timestamp": None}
scan_lock   = threading.Lock()

def scanner_loop():
    time.sleep(3)  # wait for uvicorn to finish starting
    while True:
        try:
            center_hz = DEFAULT_CENTER_MHZ * 1e6
            freqs, psd_db = scan_band(center_hz, span_hz=DEFAULT_SPAN_MHZ * 1e6)
            detection = detect_peaks(freqs, psd_db)

            # Downsample to 512 points for frontend
            raw = list(zip(freqs.tolist(), psd_db.tolist()))
            step = max(1, len(raw) // 512)
            points = [
                 {"freq_mhz": round(f / 1e6, 3), "power_db": round(p, 2)}
                 for f, p in raw[::step]
            ]

            peaks = [
                {"freq_mhz": round(pk["freq_hz"] / 1e6, 3), "power_db": round(pk["power_db"], 2)}
                for pk in detection["peaks"]
            ]

            with scan_lock:
                latest_scan["status"]        = "ok"
                latest_scan["points"]        = points
                latest_scan["peaks"]         = peaks
                latest_scan["noise_floor_db"] = detection["noise_floor_db"]
                latest_scan["timestamp"]     = time.time()

            print(f"[Bridge] Scan OK — {len(points)} pts, {len(peaks)} peaks, noise={detection['noise_floor_db']:.1f} dB")

        except Exception as e:
            print(f"[Bridge] Scan error: {e}")
            with scan_lock:
                latest_scan["status"] = "error"
                latest_scan["error"]  = str(e)

        time.sleep(2)

threading.Thread(target=scanner_loop, daemon=True).start()

@app.get("/api/psd_scan")
def psd_scan():
    with scan_lock:
        return dict(latest_scan)

@app.get("/api/status")
def status():
    with scan_lock:
        return {"status": "online", "service": "NSD RF Bridge", "last_scan": latest_scan.get("timestamp")}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
