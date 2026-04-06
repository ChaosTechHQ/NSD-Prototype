from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Literal, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

import logging
logger = logging.getLogger("nsd.fusion")

APP_TITLE = "H-NSD Fusion-to-FastAPI Pipeline"


class RfObservation(BaseModel):
    protocol: str = "unknown"
    center_freq_mhz: float = 2437.0
    bandwidth_mhz: float = 20.0
    power_db: float = -52.0
    burst_rate_hz: float = 14.0
    confidence: float = 0.5


class MmwaveObservation(BaseModel):
    range_m: float = 120.0
    radial_velocity_mps: float = 5.4
    micro_doppler_hz: float = 240.0
    angle_deg: float = 42.0
    confidence: float = 0.5


class AcousticObservation(BaseModel):
    bearing_deg: float = 45.0
    harmonic_hz: float = 220.0
    snr_db: float = 11.0
    confidence: float = 0.5


class ThermalObservation(BaseModel):
    hot_spot_c: float = 48.0
    ambient_c: float = 22.0
    blob_count: int = 2
    confidence: float = 0.5


class FusionInput(BaseModel):
    timestamp: Optional[datetime] = None
    rf: Optional[RfObservation] = None
    mmwave: Optional[MmwaveObservation] = None
    acoustic: Optional[AcousticObservation] = None
    thermal: Optional[ThermalObservation] = None
    mode: Literal["software", "akida"] = "software"


class FusionAlert(BaseModel):
    timestamp: datetime
    alert_id: str
    classification: Literal["scout", "attack", "dispersed", "unknown"]
    confidence: float
    swarm_count: int
    bearing_deg: float
    range_m: Optional[float]
    sensors: List[str]
    feature_vector: Dict[str, float]
    fusion_scores: Dict[str, float]
    source_mode: Literal["software", "akida-simulated"]


@dataclass
class PipelineConfig:
    rf_weight: float = 0.35 # up from 0.28 - RF is our real sensor
    mmwave_weight: float = 0.28 # down slightly
    acoustic_weight: float = 0.17
    thermal_weight: float = 0.20
    history_limit: int = 200


class FusionEngine:
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.history: Deque[Dict[str, Any]] = deque(maxlen=config.history_limit)

    def _clip(self, value: float, low: float = 0.0, high: float = 1.0) -> float:
        return max(low, min(high, value))

    def build_feature_vector(self, payload: FusionInput) -> Dict[str, float]:
        rf_energy         = self._clip((payload.rf.power_db + 100.0) / 50.0) if payload.rf else 0.0
        rf_burst          = self._clip(payload.rf.burst_rate_hz / 22.0) if payload.rf else 0.0
        mmwave_motion     = self._clip(payload.mmwave.micro_doppler_hz / 320.0) if payload.mmwave else 0.0
        mmwave_velocity   = self._clip(abs(payload.mmwave.radial_velocity_mps) / 12.0) if payload.mmwave else 0.0
        acoustic_harmonic = self._clip(payload.acoustic.harmonic_hz / 320.0) if payload.acoustic else 0.0
        acoustic_snr      = self._clip(payload.acoustic.snr_db / 20.0) if payload.acoustic else 0.0
        thermal_delta     = self._clip((payload.thermal.hot_spot_c - payload.thermal.ambient_c) / 32.0) if payload.thermal else 0.0
        thermal_blobs     = self._clip(payload.thermal.blob_count / 6.0) if payload.thermal else 0.0
        return {
            "rf_energy":         round(rf_energy, 4),
            "rf_burst":          round(rf_burst, 4),
            "mmwave_motion":     round(mmwave_motion, 4),
            "mmwave_velocity":   round(mmwave_velocity, 4),
            "acoustic_harmonic": round(acoustic_harmonic, 4),
            "acoustic_snr":      round(acoustic_snr, 4),
            "thermal_delta":     round(thermal_delta, 4),
            "thermal_blobs":     round(thermal_blobs, 4),
        }

    def classify(self, features: Dict[str, float], payload: FusionInput) -> Dict[str, Any]:
        scout = (
            0.20 * features["rf_energy"] +
            0.30 * features["mmwave_motion"] +
            0.22 * features["acoustic_harmonic"] +
            0.15 * features["thermal_delta"] +
            0.13 * (1.0 - features["thermal_blobs"])
        )
        attack = (
            0.22 * features["rf_burst"] +
            0.28 * features["mmwave_velocity"] +
            0.18 * features["mmwave_motion"] +
            0.16 * features["thermal_delta"] +
            0.16 * features["thermal_blobs"]
        )
        dispersed = (
            0.15 * features["rf_energy"] +
            0.08 * features["rf_burst"] +
            0.12 * features["mmwave_motion"] +
            0.20 * features["acoustic_snr"] +
            0.45 * features["thermal_blobs"]
        )
        scores = {
            "scout":     round(self._clip(scout), 4),
            "attack":    round(self._clip(attack), 4),
            "dispersed": round(self._clip(dispersed), 4),
        }
        classification = max(scores, key=scores.get)
        confidence     = round(scores[classification], 4)
        swarm_count    = max(1, round(
            1 + 8 * ((features["thermal_blobs"] + features["rf_burst"] + features["mmwave_motion"]) / 3.0)
        ))
        bearing_candidates = []
        if payload.mmwave:
            bearing_candidates.append(payload.mmwave.angle_deg)
        if payload.acoustic:
            bearing_candidates.append(payload.acoustic.bearing_deg)
        bearing = round(sum(bearing_candidates) / len(bearing_candidates), 2) if bearing_candidates else 0.0
        range_m = round(payload.mmwave.range_m, 2) if payload.mmwave else None
        sensors = [s for s in [
            "rf"       if payload.rf       else None,
            "mmwave"   if payload.mmwave   else None,
            "acoustic" if payload.acoustic else None,
            "thermal"  if payload.thermal  else None,
        ] if s]
        return {
            "classification": classification,
            "confidence":     confidence,
            "swarm_count":    swarm_count,
            "bearing_deg":    bearing,
            "range_m":        range_m,
            "sensors":        sensors,
            "scores":         scores,
        }

    def infer(self, payload: FusionInput) -> FusionAlert:
        features = self.build_feature_vector(payload)
        result   = self.classify(features, payload)
        alert = FusionAlert(
            timestamp      = payload.timestamp or datetime.now(timezone.utc),
            alert_id       = f"fusion-{int(time.time() * 1000)}",
            classification = result["classification"],
            confidence     = result["confidence"],
            swarm_count    = result["swarm_count"],
            bearing_deg    = result["bearing_deg"],
            range_m        = result["range_m"],
            sensors        = result["sensors"],
            feature_vector = features,
            fusion_scores  = result["scores"],
            source_mode    = "akida-simulated" if payload.mode == "akida" else "software",
        )
        self.history.appendleft(alert.model_dump())
        logger.info(
            "fusion_alert id=%s cls=%s conf=%.3f swarm=%d bearing=%.1f range=%.1f rf=%.2f mmwave=%.2f acoustic=%.2f thermal=%.2f scores=%s",
            alert.alert_id, alert.classification, alert.confidence,
            alert.swarm_count, alert.bearing_deg, alert.range_m or -1.0,
            features["rf_energy"], features["mmwave_motion"],
            features["acoustic_snr"], features["thermal_blobs"],
            alert.fusion_scores,
        )
        global FUSION_TOTAL, FUSION_CONF_SUM
        FUSION_CLASS_COUNTS[alert.classification] += 1
        FUSION_TOTAL += 1
        FUSION_CONF_SUM += alert.confidence
        return alert


class CotBridge:
    @staticmethod
    def to_cot(alert: FusionAlert, lat: float = 0.0, lon: float = 0.0, hae: float = 0.0) -> str:
        ts    = alert.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        stale = datetime.fromtimestamp(alert.timestamp.timestamp() + 120, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        remarks = (
            f"class={alert.classification}; conf={alert.confidence}; "
            f"count={alert.swarm_count}; bearing={alert.bearing_deg}; "
            f"sensors={','.join(alert.sensors)}"
        )
        return (
            f'<event version="2.0" uid="{alert.alert_id}" type="a-h-A-M-F-U-C" '
            f'how="m-g" time="{ts}" start="{ts}" stale="{stale}">'
            f'<point lat="{lat}" lon="{lon}" hae="{hae}" ce="25.0" le="15.0" />'
            f'<detail><contact callsign="H-NSD Fusion" />'
            f'<remarks>{remarks}</remarks>'
            f'<track course="{alert.bearing_deg}" speed="0.0" /></detail></event>'
        )


config = PipelineConfig()
engine = FusionEngine(config)
from collections import Counter
FUSION_CLASS_COUNTS: Counter = Counter()
FUSION_TOTAL: int = 0
FUSION_CONF_SUM: float = 0.0
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

app    = FastAPI(title=APP_TITLE, version="0.1.0")
clients: List[WebSocket] = []


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "service": APP_TITLE,
        "history_depth": len(engine.history),
        "websocket_clients": len(clients),
    }


@app.get("/metrics")
def metrics() -> Dict[str, Any]:
    avg_conf = round(FUSION_CONF_SUM / FUSION_TOTAL, 4) if FUSION_TOTAL > 0 else 0.0
    return {
        "total_fusions": FUSION_TOTAL,
        "avg_confidence": avg_conf,
        "class_counts": dict(FUSION_CLASS_COUNTS),
        "class_distribution": {
            k: round(v / FUSION_TOTAL, 3) if FUSION_TOTAL > 0 else 0.0
            for k, v in FUSION_CLASS_COUNTS.items()
        },
    }


@app.get("/config")
def get_config() -> Dict[str, float]:
    return asdict(config)


@app.post("/fuse", response_model=FusionAlert)
def fuse(payload: FusionInput) -> FusionAlert:
    return engine.infer(payload)


@app.post("/fuse/cot")
def fuse_to_cot(payload: FusionInput) -> Dict[str, Any]:
    alert = engine.infer(payload)
    return {"alert": alert.model_dump(), "cot": CotBridge.to_cot(alert)}


@app.get("/history")
def history(limit: int = 20) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, config.history_limit))
    return list(engine.history)[:limit]


@app.get("/sample")
def sample() -> Dict[str, Any]:
    payload = FusionInput(
        mode    = "akida",
        rf      = RfObservation(protocol="wifi", center_freq_mhz=2437.0, bandwidth_mhz=20.0, power_db=-44.0, burst_rate_hz=18.0, confidence=0.88),
        mmwave  = MmwaveObservation(range_m=185.0, radial_velocity_mps=7.3, micro_doppler_hz=268.0, angle_deg=47.0, confidence=0.91),
        acoustic= AcousticObservation(bearing_deg=44.0, harmonic_hz=236.0, snr_db=15.0, confidence=0.82),
        thermal = ThermalObservation(hot_spot_c=51.0, ambient_c=23.0, blob_count=4, confidence=0.79),
    )
    alert = engine.infer(payload)
    return {"alert": alert.model_dump(), "cot": CotBridge.to_cot(alert)}


async def broadcaster() -> None:
    import random
    while True:
        if clients:
            payload = FusionInput(
                timestamp = datetime.now(timezone.utc),
                mode      = random.choice(["software", "akida"]),
                rf        = RfObservation(
                    protocol        = random.choice(["wifi", "fhss", "unknown"]),
                    center_freq_mhz = random.choice([915.0, 2437.0, 5800.0]),
                    bandwidth_mhz   = random.choice([5.0, 20.0, 40.0]),
                    power_db        = random.uniform(-70, -38),
                    burst_rate_hz   = random.uniform(6, 22),
                    confidence      = random.uniform(0.4, 0.95),
                ),
                mmwave   = MmwaveObservation(
                    range_m              = random.uniform(40, 240),
                    radial_velocity_mps  = random.uniform(1, 11),
                    micro_doppler_hz     = random.uniform(120, 320),
                    angle_deg            = random.uniform(5, 95),
                    confidence           = random.uniform(0.5, 0.95),
                ),
                acoustic = AcousticObservation(
                    bearing_deg  = random.uniform(0, 120),
                    harmonic_hz  = random.uniform(140, 310),
                    snr_db       = random.uniform(5, 18),
                    confidence   = random.uniform(0.4, 0.9),
                ),
                thermal  = ThermalObservation(
                    hot_spot_c = random.uniform(34, 58),
                    ambient_c  = random.uniform(15, 30),
                    blob_count = random.randint(1, 6),
                    confidence = random.uniform(0.4, 0.85),
                ),
            )
            alert = engine.infer(payload)
            dead  = []
            for ws in clients:
                try:
                    await ws.send_text(json.dumps(alert.model_dump(), default=str))
                except Exception:
                    dead.append(ws)
            for ws in dead:
                if ws in clients:
                    clients.remove(ws)
        await asyncio.sleep(1.0)


@app.on_event("startup")
async def startup_event() -> None:
    asyncio.create_task(broadcaster())


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in clients:
            clients.remove(websocket)
