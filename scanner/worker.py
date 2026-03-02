# scanner/worker.py — background RF scanner thread
import time, threading
from rtlsdr.rtlsdr import LibUSBError
from psd_scanner import scan_band, detect_peaks
from scanner.state import state
from scanner.threats import _build_threat_list
import nsd_db

BANDS = [
    {"center_mhz": 433.0,  "span_mhz": 2.0, "label": "433MHz",  "type": "DRONE_CTRL"},
    {"center_mhz": 915.0,  "span_mhz": 2.0, "label": "900MHz",  "type": "LTE_SIGNAL"},
    {"center_mhz": 1090.0, "span_mhz": 2.0, "label": "ADS-B",   "type": "AIRCRAFT"},
    {"center_mhz": 2441.0, "span_mhz": 4.0, "label": "2.4GHz",  "type": "WIFI_DJI"},
]

def scanner_loop():
    print("[NSD] Multi-band scanner started.")
    all_peaks = {}

    while True:
        with state.lock:
            bi   = state.band_index % len(BANDS)
            state.band_index += 1
        band = BANDS[bi]

        try:
            freqs, psd_db, fft_out = scan_band(band["center_mhz"] * 1e6)
            detection = detect_peaks(freqs, psd_db, fft_out=fft_out)

            raw  = list(zip(freqs.tolist(), psd_db.tolist()))
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
            combined = []
            for b in BANDS:
                combined.extend(all_peaks.get(b["label"], []))

            with state.lock:
                state.scan_center_mhz     = band["center_mhz"]
                state.scan_span_mhz       = band["span_mhz"]
                state.cache["center_mhz"] = band["center_mhz"]
                state.cache["noise_floor_db"] = detection["noise_floor_db"]
                state.cache["points"]     = points
                state.cache["peaks"]      = combined
                state.cache["active_band"] = band["label"]
                state.cache["timestamp"]  = time.time()
                state.cache["status"]     = "ok"
                state.cache["error"]      = None
                for bp in band_peaks:
                    state.unique_threat_ids.add(bp["freq_mhz"])
                state.cache["total_detected"] = len(state.unique_threat_ids)
                state.cache["threats"] = _build_threat_list(
                    combined, detection["noise_floor_db"])
                nsd_db.save_scan(band["label"], len(state.cache["threats"]),
                                 detection["noise_floor_db"], "ok")
                for t in state.cache["threats"]:
                    nsd_db.upsert_threat(t["id"], t["freq_mhz"], t.get("band", ""),
                                         t["type"], t["power_db"], t["first_seen"])

        except LibUSBError as e:
            with state.lock:
                state.cache["status"] = "sdr_error"
                state.cache["error"]  = "scan_error"
            print(f"[NSD] SDR error: {e} — retrying in 3s")
            time.sleep(3)
            continue

        except Exception as e:
            with state.lock:
                state.cache["status"] = "error"
                state.cache["error"]  = "scan_error"
            print(f"[NSD] Scan error: {e} — retrying in 3s")
            time.sleep(3)
            continue

        time.sleep(1)

def start_scanner():
    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()
    print("[NSD] Scanner thread started.")
    return t
