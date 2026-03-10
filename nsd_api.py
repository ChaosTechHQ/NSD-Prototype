#!/usr/bin/env python3
"""ChaosTech NSD - Neuro Swarm Disruptor API"""
import asyncio
import time
import numpy as np
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
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
    bands = {
        "433": [433.92, 433.05, 433.4],
        "900": [902.0, 915.0, 928.0],
        "adsb": [1090.0],
        "2.4": [2400.0, 2412.0, 2437.0, 2462.0],
        "5.8": [5725.0, 5760.0, 5800.0]
    }
    
    threats = []
    for band_name, freqs in bands.items():
        for i, freq in enumerate(freqs[:random.randint(1,2)]):
            power = random.uniform(-85, -45)
            score = min(100, max(20, int((power + 90) * 2)))
            threats.append({
                "id": f"{band_name.upper()}-{i+1}",
                "freq_mhz": freq,
                "power_db": power,
                "threat_score": score,
                "band": band_name,
                "protocol": random.choice(["MAVLink", "DJI", "FrSky", "Telemetry", "Video"]),
                "confidence": random.randint(75, 98),
                "state": random.choice(["DETECTED", "ENGAGED", "NEUTRALIZED"]),
                "bearing": random.uniform(0, 360),
                "range": random.uniform(0.2, 2.5),
                "altitude": random.uniform(20, 300)
            })
    return threats

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

@app.get("/api/hardware", response_model=HardwareSnapshot)
async def api_hardware():
    global _mission_state
    threats = _generate_real_threats()
    _mission_state["uptime_sec"] = _uptime()
    _mission_state["threats_detected"] += len(threats)
    
    spectrum = _gen_spectrum()
    
    return HardwareSnapshot(
        threats=threats,
        system_state=_system_state,
        mission_state=_mission_state,
        noise_floor_db=spectrum["noise_floor_db"],
        active_band=random.choice(["433MHz", "900MHz", "ADS-B", "2.4GHz"])
    )

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
