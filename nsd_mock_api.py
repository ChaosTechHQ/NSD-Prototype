from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
import time, random, uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/hardware")
def get_hardware():
    threats = []
    for i in range(random.randint(2, 4)):
        angle = random.uniform(0, 360)
        dist = random.uniform(0.5, 4.0)
        threats.append({
            "id": 1000 + i,
            "freq_mhz": random.choice([433.9, 915.0, 2400.0, 5800.0]),
            "power_db": round(random.uniform(-40, -80), 2),
            "range": dist, "distance": dist, "bearing": angle, "angle": angle,
            "speed": round(random.uniform(5, 25), 1),
            "altitude": int(random.uniform(50, 400)),
            "type": random.choice(["DRONE_CTRL", "WIFI/DJI", "TELEM"]),
            "protocol": "UNK", "confidence": random.randint(60, 99),
            "status": "ACTIVE", "first_seen": time.time() - 10,
            "threat_score": random.randint(50, 95), "swarm_member": False,
            "state": "DETECTED"
        })
        
    state = {
        "status": "ok", "threats": threats, "threat_count": len(threats),
        "noise_floor_db": round(random.uniform(-90, -85), 2),
        "timestamp": time.time(),
        "mission_state": {
            "uptime_sec": 120, "threats_detected": len(threats), "swarms_detected": 0,
            "active_swarms": 0, "threats_engaged": 0, "threats_neutralized": 0,
            "autonomous_actions": 0, "swarms_eliminated": 0
        },
        "system_state": {"active": False, "mode": "SCAN", "power_level": 100, "energy_reserves": 100},
        "autonomous_mode": {"enabled": False, "auto_engage": False, "threat_threshold": 70},
        "active_band": "SCAN"
    }
    return JSONResponse(state)

@app.get("/api/token")
def get_token():
    return {"token": "MOCK_TOKEN_123"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
