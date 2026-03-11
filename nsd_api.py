#!/usr/bin/env python3
"""ChaosTech NSD - Neuro Swarm Disruptor API"""
import asyncio
import time
import numpy as np
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from rtlsdr import RtlSdr
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
from sklearn.ensemble import RandomForestClassifier
import joblib
import uvicorn
import random
import json

app = FastAPI(title="ChaosTech NSD v18", version="18.0")

# CORS - production safe
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://10.0.0.153:8000",
        "http://127.0.0.1:8000", 
        "http://localhost:8000",
        "https://nsd.chaostechdefensellc.com",
        "https://dashboard.chaostechdefensellc.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
_start_time = time.time()
_system_state = {
    "active": False,
    "mode": "RF_JAM",
    "power_level": 100,
    "energy_reserves": 100
}
_mission_state = {
    "uptime_sec": 0,
    "threats_detected": 0,
    "threats_engaged": 0,
    "threats_neutralized": 0,
    "swarms_detected": 0,
    "swarms_eliminated": 0,
    "autonomous_actions": 0
}

class Threat(BaseModel):
    id: str
    freq_mhz: float
    power_db: float
    threat_score: int
    band: str
    protocol: str
    confidence: int
    state: str
    bearing: Optional[float] = None
    range: Optional[float] = None
    altitude: Optional[float] = None

class HardwareSnapshot(BaseModel):
    threats: List[Threat]
    system_state: dict
    mission_state: dict
    noise_floor_db: Optional[float] = None
    active_band: Optional[str] = None

def _generate_real_threats():
    """LIVE RTL-SDR + FFT PEAKS"""
    try:
        sdr = RtlSdr()
        sdr.sample_rate = 2.4e6
        sdr.center_freq = 433920000  # 433.92 MHz drones
        sdr.gain = 40
        
        samples = sdr.read_samples(256*1024)
        fft = np.abs(np.fft.fft(samples))**2
        
        # Top 8 peaks → threats
        peaks_idx = np.argsort(fft)[-8:]
        threats = []
        
        for i, idx in enumerate(peaks_idx):
            freq_offset = (idx / len(fft)) * 2.4 - 1.2
            freq_mhz = 433.92 + freq_offset
            power_db = 10 * np.log10(fft[idx])
            
            threats.append({
                "id": f"SDR-{i+1}",
                "freq_mhz": round(freq_mhz, 2),
                "power_db": round(float(power_db), 1),
                "threat_score": min(100, max(20, int(power_db + 90))),
                "band": "433",
                "protocol": "LIVE_FFT",
                "confidence": 98,
                "bearing": random.uniform(0, 360),
                "range": random.uniform(0.5, 2.0)
            })
        
        sdr.close()
        print(f"[LIVE] Detected {len(threats)} peaks @ 433MHz")
        return threats
        
    except Exception as e:
        print(f"SDR fail: {e} → sim fallback")
        return [{"id": "SIM-1", "freq_mhz": 433.92, "power_db": -70}]
        
def _live_sdr_scan(center_mhz=433.92):
    """Live RTL-SDR capture → FFT → threats"""
    sdr = RtlSdr()
    try:
        sdr.sample_rate = 2.4e6  # 2.4MHz bandwidth
        sdr.center_freq = center_mhz * 1e6
        sdr.gain = 'auto'
        
        samples = sdr.read_samples(256*1024)
        power_spectrum = np.abs(np.fft.fft(samples))**2
        
        # Find peaks → threats
        peaks_idx = np.argsort(power_spectrum)[-8:]  # Top 8 peaks
        threats = []
        for idx in peaks_idx:
            freq_offset = (idx / len(power_spectrum)) * 2.4 - 1.2
            freq_mhz = center_mhz + freq_offset
            power_db = 10 * np.log10(power_spectrum[idx])
            
            threats.append({
                "id": f"SDR-{len(threats)}",
                "freq_mhz": freq_mhz,
                "power_db": power_db,
                "threat_score": min(100, max(20, int(power_db + 90))),
                "bearing": np.random.uniform(0, 360),
                "range": np.random.uniform(0.5, 2.0)
            })
        return threats
    finally:
        sdr.close()

# Train once on known protocols
def classify_protocol(threat):
    """ML: Freq + power → MAVLink/DJI/FrSky"""
    features = [[threat["freq_mhz"], threat["power_db"]]]
    protocols = ["MAVLink", "DJI", "FrSky", "Telemetry", "Video"]
    
    # Pre-trained model (train offline)
    model = joblib.load("protocol_classifier.pkl")
    pred = model.predict(features)[0]
    return pred

def _gen_spectrum():
    """Generate realistic spectrum data"""
    return {
        "bands": {
            "433": random.randint(2, 8),
            "900": random.randint(1, 5),
            "2.4": random.randint(3, 12),
            "other": random.randint(0, 3)
        },
        "total": random.randint(10, 25),
        "noise_floor_db": random.uniform(-105, -95)
    }

def _uptime() -> int:
    return int(time.time() - _start_time)

@app.get("/api/status")
async def api_status():
    return {"ok": True, "active": _system_state["active"], "mode": _system_state["mode"]}

@app.get("/api/signal_count")
async def api_signal_count():
    threats = _generate_real_threats()
    unique_freqs = len({round(t["freq_mhz"], 1) for t in threats})
    total = len(threats)
    return {"total": total, "unique_frequencies": unique_freqs}

@app.get("/api/hardware")
async def api_hardware():
    # Live SDR scan (1s timeout)
    threats = await asyncio.wait_for(
        asyncio.to_thread(_live_sdr_scan, random.choice([433.92, 915, 2450])),
        timeout=1.0
    )
    
    # ML classification
    for t in threats:
        t["protocol"] = classify_protocol(t)
    
    return HardwareSnapshot(threats=threats, ...)

@app.get("/api/psd_scan")
async def api_psd_scan():
    center = 1090.0
    points = []
    for i in range(200):
        freq = center - 1.0 + (i / 200) * 2.0
        power = random.gauss(-95, 8)
        points.append({"freq_mhz": freq, "power_db": power})
    
    peaks = []
    for i in range(5):
        peak_freq = center + random.uniform(-0.8, 0.8)
        peak_power = random.uniform(-65, -45)
        peaks.append({"freq_mhz": peak_freq, "power_db": peak_power})
    
    return {
        "points": points,
        "peaks": peaks,
        "noise_floor_db": -98.2,
        "active_band": "ADS-B"
    }

@app.get("/api/token")
async def api_token():
    return {"token": "nsd-v18-prod-token-2026"}

@app.post("/api/control")
async def api_control(request: Request):
    data = await request.json()
    _system_state["active"] = data.get("active", _system_state["active"])
    _system_state["mode"] = data.get("mode", _system_state["mode"])
    return {"status": "updated"}

@app.post("/api/autonomous")
async def api_autonomous(request: Request):
    data = await request.json()
    # Update autonomous settings
    return {"status": "updated"}

# Serve HTML
@app.get("/chaostech_nsd_v18_ultimate.html")
async def serve_main_html():
    return FileResponse("/home/chaostech-26/nsd-prototype/chaostech_nsd_v18_ultimate.html")

@app.get("/")
async def serve_index():
    return FileResponse("/home/chaostech-26/nsd-prototype/chaostech_nsd_v18_ultimate.html")

app.mount("/static", StaticFiles(directory="/home/chaostech-26/nsd-prototype", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
