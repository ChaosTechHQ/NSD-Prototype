import sqlite3, time, random, json

def run_mock():
    conn = sqlite3.connect('/home/chaostech-26/nsd-prototype/nsd_data.db', timeout=5)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS hardware_state 
                 (id INTEGER PRIMARY KEY, timestamp REAL, state_json TEXT)''')
    
    print("Mock SDR running in background...")
    
    while True:
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
            "mission_state": {"active_swarms": 0, "threats_engaged": 0},
            "system_state": {"active": False, "mode": "SCAN", "power_level": 100},
            "autonomous_mode": {"enabled": False}
        }
        
        c.execute("INSERT INTO hardware_state (timestamp, state_json) VALUES (?, ?)", 
                  (time.time(), json.dumps(state)))
        conn.commit()
        c.execute("DELETE FROM hardware_state WHERE timestamp < ?", (time.time() - 10,))
        conn.commit()
        time.sleep(1)

if __name__ == "__main__":
    run_mock()
