# scanner/threats.py — threat detection, scoring, swarm logic
import time
from scanner.state import state

def _assign_threat_id(freq_mhz, ttl=5):
    bucket = round(freq_mhz, 3)
    if bucket not in state.threat_tracker:
        state.threat_tracker[bucket] = {
            "id": state.next_threat_id, "ttl": ttl, "first_seen": time.time()
        }
        state.next_threat_id += 1
    else:
        state.threat_tracker[bucket]["ttl"] = ttl
    return state.threat_tracker[bucket]["id"]

def _expire_stale_threats(seen_freqs):
    buckets = {round(f * 2) / 2 for f in seen_freqs}
    for b in list(state.threat_tracker.keys()):
        if b not in buckets:
            state.threat_tracker[b]["ttl"] -= 1
            if state.threat_tracker[b]["ttl"] <= 0:
                del state.threat_tracker[b]

def _detect_swarms(threats):
    drone_threats = [t for t in threats if t["type"] == "DRONE_CTRL"]
    swarm_groups, used = [], set()
    for i, t in enumerate(drone_threats):
        if i in used:
            continue
        group = [t]
        for j, t2 in enumerate(drone_threats):
            if j != i and j not in used and abs(t["freq_mhz"] - t2["freq_mhz"]) <= 2.0:
                group.append(t2)
                used.add(j)
        if len(group) >= 2:
            swarm_groups.append(group)
            used.add(i)
    new_swarm_ids = {id(g[0]) for g in swarm_groups}
    state.swarms_detected += len(swarm_groups) - len(state.active_swarms)
    for sg in list(state.active_swarms):
        if sg not in new_swarm_ids:
            state.swarms_eliminated += 1
    state.active_swarms = new_swarm_ids
    swarm_freqs = {t["freq_mhz"] for g in swarm_groups for t in g}
    for t in threats:
        t["swarm_member"] = t["freq_mhz"] in swarm_freqs
    return swarm_groups, threats

def _score_threat(freq_mhz, power_db, band, t_type, swarm_member, threat_id):
    BAND_SCORES = {"433MHz": 40, "900MHz": 30, "2.4GHz": 35, "ADS-B": 10, "UNK": 20}
    band_score   = BAND_SCORES.get(band, 20)
    power_score  = min(30, max(0, int((power_db + 60) / 2)))
    swarm_score  = 20 if swarm_member else 0
    bucket       = round(freq_mhz, 3)
    ttl_remaining = state.threat_tracker.get(bucket, {}).get("ttl", 0)
    persist_score = min(10, (5 - ttl_remaining) * 2 + 10)
    return min(100, band_score + power_score + swarm_score + persist_score)

def _false_positive_filter(peaks, noise_floor_db):
    if noise_floor_db is None:
        return peaks
    return [p for p in peaks if p.get("power_db", -999) > noise_floor_db + 6]

TYPE_ICONS = {
    "DRONE_CTRL": "DRONE_CTRL", "LTE_SIGNAL": "LTE_SIG",
    "AIRCRAFT": "ADS-B", "WIFI_DJI": "WIFI/DJI", "RF_PEAK": "RF_PEAK",
}

def _build_threat_list(peaks, noise):
    """Build full threat list. MUST be called with state.lock held."""
    peaks = _false_positive_filter(peaks, noise)
    threats = []
    for pk in peaks:
        freq_mhz  = pk["freq_mhz"]
        power_db  = pk["power_db"]
        t_type    = pk.get("type", "RF_PEAK")
        bw_hz     = pk.get("bandwidth_hz", 0)
        band_lbl  = pk.get("band", "UNK")
        threat_id = _assign_threat_id(freq_mhz)
        threats.append({
            "id":          threat_id,
            "freq":        round(freq_mhz / 1000, 4),
            "freq_mhz":    freq_mhz,
            "power":       round(power_db, 1),
            "power_db":    power_db,
            "range":       round(0.3 + (threat_id * 0.618033) % 2.0, 2),
            "bearing":     round((freq_mhz * 137.508 + threat_id * 23.7) % 360, 1),
            "angle":       round((freq_mhz * 137.508 + threat_id * 23.7) % 360, 1),
            "distance":    round(0.3 + (threat_id * 0.618033) % 2.0, 2),
            "speed":       round(10 + (threat_id * 3.7) % 20, 1),
            "altitude":    round(50 + (threat_id * 17.3) % 200),
            "type":        TYPE_ICONS.get(t_type, t_type),
            "protocol":    band_lbl,
            "confidence":  75,
            "description": "RF signal detected",
            "bandwidth_hz": bw_hz,
            "band":        band_lbl,
            "status":      "ACTIVE",
            "first_seen":  state.threat_tracker.get(round(freq_mhz, 3), {}).get("first_seen", time.time()),
            "threat_score": _score_threat(freq_mhz, power_db, band_lbl, t_type, False, threat_id),
        })
    for t in threats:
        t.setdefault("swarm_member", False)
    _, threats = _detect_swarms(threats)
    _expire_stale_threats([pk["freq_mhz"] for pk in peaks])
    for t in threats:
        t["threat_score"] = _score_threat(
            t["freq_mhz"], t["power_db"], t.get("band", ""),
            t["type"], t.get("swarm_member", False), t["id"])
    # ── State machine ──────────────────────────────────────
    now = time.time()
    for t in threats:
        tid   = t["id"]
        tstate = state.threat_states.get(tid, "DETECTED")
        age   = now - t.get("first_seen", now)
        if tstate == "DETECTED" and state.system_active and age > 4:
            state.threat_states[tid] = "ENGAGED"
            state.threats_engaged += 1
            if state.auto_engage and state.autonomous_enabled:
                state.autonomous_actions += 1
        elif tstate == "ENGAGED" and age > 10:
            state.threat_states[tid] = "NEUTRALIZED"
            state.threats_neutralized += 1
        t["state"] = state.threat_states.get(tid, "DETECTED")
    active_ids = {t["id"] for t in threats}
    for tid in list(state.threat_states.keys()):
        if tid not in active_ids:
            del state.threat_states[tid]
    return threats
