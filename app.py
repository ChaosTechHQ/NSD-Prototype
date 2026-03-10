import random
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/status")
async def get_status():
    return {
        "radar_signals": random.randint(0, 12),
        "radar_tracks": random.randint(0, 3),
        "active_threats": random.randint(0, 2),
        "threat_score": f"{random.randint(-95, -65)}dB",
        "system_mode": random.choice(["STANDBY", "SCAN", "TRACK", "ENGAGE"]),
        "disruption_mode": random.choice(["RF_JAM", "PROTOCOL", "GPS_DENY"]),
        "power_level": f"{random.randint(75, 100)}%",
        "energy_reserves": random.randint(85, 100),
        "autonomous_mode": random.choice(["OFF", "ON", "LEARNING"]),
        "threat_threshold": f"{random.randint(-90, -75)}dB"
    }
