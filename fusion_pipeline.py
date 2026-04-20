from __future__ import annotations
import asyncio
import json
import time
import os
import uuid
from collections import deque, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Literal, Optional, Set
from contextlib import asynccontextmanager
import xml.etree.ElementTree as ET

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Security, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import logging

logger = logging.getLogger("nsd.fusion")

APP_TITLE = "H-NSD Fusion-to-FastAPI Pipeline"

# Metrics globals
FUSION_CLASS_COUNTS: Counter = Counter()
FUSION_TOTAL: int = 0
FUSION_CONF_SUM: float = 0.0
FUSION_MARGIN_SUM: float = 0.0

# Auth setup
api_key_header = APIKeyHeader(name="X-NSD-Token", auto_error=False)

def verify_token(key: str = Security(api_key_header)):
    token = os.getenv("NSD_API_TOKEN", "")
    if not token:
        return
    if key != token:
        raise HTTPException(status_code=403, detail="Invalid NSD API Token")

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
    swarm_estimate_index: int
    bearing_deg: float
    range_m: Optional[float]
    sensors: List[str]
    feature_vector: Dict[str, float]
    fusion_scores: Dict[str, float]
    source_mode: Literal["software", "akida-simulated"]

@dataclass
class PipelineConfig:
    rf_weight: float = 0.35
    mmwave_weight: float = 0.28
    acoustic_weight: float = 0.17
    thermal_weight: float = 0.20
    history_limit: int = 200

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        async with self.lock:
            dead_links = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except Exception:
                    dead_links.append(connection)
            for dead in dead_links:
                self.active_connections.remove(dead)

manager = ConnectionManager()

class FusionEngine:
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.history: Deque[Dict[str, Any]] = deque(maxlen=config.history_limit)

    def _clip(self, value: float, low: float = 0.0, high: float = 1.0) -> float:
        return max(low, min(high, value))

    def build_feature_vector(self, payload: FusionInput) -> Dict[str, float]:
        rf_energy = self._clip((payload.rf.power_db + 100.0) / 50.0) if payload.rf else 0.0
        rf_burst = self._clip(payload.rf.burst_rate_hz / 22.0) if payload.rf else 0.0
        mmwave_motion = self._clip(payload.mmwave.micro_doppler_hz / 320.0) if payload.mmwave else 0.0
        mmwave_velocity = self._clip(abs(payload.mmwave.radial_velocity_mps) / 12.0) if payload.mmwave else 0.0
        acoustic_harmonic = self._clip(payload.acoustic.harmonic_hz / 320.0) if payload.acoustic else 0.0
        acoustic_snr = self._clip(payload.acoustic.snr_db / 20.0) if payload.acoustic else 0.0
        thermal_delta = self._clip((payload.thermal.hot_spot_c - payload.thermal.ambient_c) / 32.0) if payload.thermal else 0.0
        thermal_blobs = self._clip(payload.thermal.blob_count / 6.0) if payload.thermal else 0.0

        return {
            "rf_energy": round(rf_energy, 4),
            "rf_burst": round(rf_burst, 4),
            "mmwave_motion": round(mmwave_motion, 4),
            "mmwave_velocity": round(mmwave_velocity, 4),
            "acoustic_harmonic": round(acoustic_harmonic, 4),
            "acoustic_snr": round(acoustic_snr, 4),
            "thermal_delta": round(thermal_delta, 4),
            "thermal_blobs": round(thermal_blobs, 4),
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
            "scout": round(self._clip(scout), 4),
            "attack": round(self._clip(attack), 4),
            "dispersed": round(self._clip(dispersed), 4),
        }

        classification = max(scores, key=scores.get)
        confidence = round(scores[classification], 4)

        swarm_idx = max(1, round(
            1 + 8 * ((features["thermal_blobs"] + features["rf_burst"] + features["mmwave_motion"]) / 3.0)
        ))

        bearing_candidates = []
        if payload.mmwave: bearing_candidates.append(payload.mmwave.angle_deg)
        if payload.acoustic: bearing_candidates.append(payload.acoustic.bearing_deg)
        bearing = round(sum(bearing_candidates) / len(bearing_candidates), 2) if bearing_candidates else 0.0

        range_m = round(payload.mmwave.range_m, 2) if payload.mmwave else None

        sensors = [s for s in [
            "rf" if payload.rf else None,
            "mmwave" if payload.mmwave else None,
            "acoustic" if payload.acoustic else None,
            "thermal" if payload.thermal else None,
        ] if s]

        return {
            "classification": classification,
            "confidence": confidence,
            "swarm_estimate_index": swarm_idx,
            "bearing_deg": bearing,
            "range_m": range_m,
            "sensors": sensors,
            "scores": scores,
        }

    def infer(self, payload: FusionInput) -> FusionAlert:
        features = self.build_feature_vector(payload)
        result = self.classify(features, payload)

        alert = FusionAlert(
            timestamp = payload.timestamp or datetime.now(timezone.utc),
            alert_id = f"fusion-{uuid.uuid4().hex[:12]}",
            classification = result["classification"],
            confidence = result["confidence"],
            swarm_estimate_index = result["swarm_estimate_index"],
            bearing_deg = result["bearing_deg"],
            range_m = result["range_m"],
            sensors = result["sensors"],
            feature_vector = features,
            fusion_scores = result["scores"],
            source_mode = "akida-simulated" if payload.mode == "akida" else "software",
        )

        self.history.appendleft(alert.model_dump())
        logger.info(
            "fusion_alert id=%s cls=%s conf=%.3f swarm=%d bearing=%.1f range=%.1f rf=%.2f mmwave=%.2f acoustic=%.2f thermal=%.2f",
            alert.alert_id, alert.classification, alert.confidence, alert.swarm_estimate_index,
            alert.bearing_deg, alert.range_m or -1.0, features["rf_energy"],
            features["mmwave_motion"], features["acoustic_snr"], features["thermal_blobs"]
        )

        global FUSION_TOTAL, FUSION_CONF_SUM, FUSION_MARGIN_SUM
        FUSION_CLASS_COUNTS[alert.classification] += 1
        FUSION_TOTAL += 1
        FUSION_CONF_SUM += alert.confidence

        if alert.fusion_scores and len(alert.fusion_scores) >= 2:
            sorted_scores = sorted(alert.fusion_scores.values(), reverse=True)
            FUSION_MARGIN_SUM += sorted_scores[0] - sorted_scores[1]

        return alert

class CotBridge:
    @staticmethod
    def to_cot(alert: FusionAlert, lat: float = 0.0, lon: float = 0.0, hae: float = 0.0) -> str:
        ts = alert.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        stale = datetime.fromtimestamp(alert.timestamp.timestamp() + 120, tz=timezone.utc).isoformat().replace("+00:00", "Z")

        event = ET.Element("event", {
            "version": "2.0",
            "uid": alert.alert_id,
            "type": f"a-f-G-U-X-L",
            "time": ts,
            "start": ts,
            "stale": stale,
            "how": "h-e"
        })

        point = ET.SubElement(event, "point", {
            "lat": str(lat),
            "lon": str(lon),
            "hae": str(hae),
            "ce": "10",
            "le": "10"
        })

        detail = ET.SubElement(event, "detail")
        ET.SubElement(detail, "contact", {"callsign": f"NSD-{alert.classification.upper()}"})
        
        remarks_text = (
            f"class={alert.classification}; conf={alert.confidence}; "
            f"swarm_idx={alert.swarm_estimate_index}; bearing={alert.bearing_deg}; "
            f"sensors={','.join(alert.sensors)}"
        )
        remarks = ET.SubElement(detail, "remarks")
        remarks.text = remarks_text

        return ET.tostring(event, encoding='unicode')

config = PipelineConfig()
engine = FusionEngine(config)

async def broadcaster() -> None:
    import random
    while True:
        try:
            if manager.active_connections:
                payload = FusionInput(
                    timestamp = datetime.now(timezone.utc),
                    mode = random.choice(["software", "akida"]),
                    rf = RfObservation(
                        protocol = random.choice(["wifi", "fhss", "unknown"]),
                        center_freq_mhz = random.choice([915.0, 2437.0, 5800.0]),
                        bandwidth_mhz = random.choice([5.0, 20.0, 40.0]),
                        power_db = random.uniform(-70, -38),
                        burst_rate_hz = random.uniform(6, 22),
                        confidence = random.uniform(0.4, 0.95),
                    ),
                    mmwave = MmwaveObservation(
                        range_m = random.uniform(40, 240),
                        radial_velocity_mps = random.uniform(1, 11),
                        micro_doppler_hz = random.uniform(120, 320),
                        angle_deg = random.uniform(5, 95),
                        confidence = random.uniform(0.5, 0.95),
                    ),
                    acoustic = AcousticObservation(
                        bearing_deg = random.uniform(0, 120),
                        harmonic_hz = random.uniform(140, 310),
                        snr_db = random.uniform(5, 18),
                        confidence = random.uniform(0.4, 0.9),
                    ),
                    thermal = ThermalObservation(
                        hot_spot_c = random.uniform(34, 58),
                        ambient_c = random.uniform(15, 30),
                        blob_count = random.randint(1, 6),
                        confidence = random.uniform(0.4, 0.85),
                    ),
                )
                alert = engine.infer(payload)
                await manager.broadcast(json.dumps(alert.model_dump(), default=str))
        except Exception:
            logger.exception("broadcaster loop encountered an error")
        
        await asyncio.sleep(1.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Fusion Pipeline broadcaster")
    task = asyncio.create_task(broadcaster())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    logger.info("Fusion Pipeline broadcaster stopped")

app = FastAPI(title=APP_TITLE, version="0.1.0", lifespan=lifespan)

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "service": APP_TITLE,
        "history_depth": len(engine.history),
        "websocket_clients": len(manager.active_connections),
    }

@app.get("/metrics")
def metrics() -> Dict[str, Any]:
    avg_conf = round(FUSION_CONF_SUM / FUSION_TOTAL, 4) if FUSION_TOTAL > 0 else 0.0
    return {
        "total_fusions": FUSION_TOTAL,
        "avg_confidence": avg_conf,
        "class_counts": dict(FUSION_CLASS_COUNTS),
        "avg_top_margin": round(FUSION_MARGIN_SUM / FUSION_TOTAL, 4) if FUSION_TOTAL > 0 else 0.0,
        "class_distribution": {
            k: round(v / FUSION_TOTAL, 3) if FUSION_TOTAL > 0 else 0.0 for k, v in FUSION_CLASS_COUNTS.items()
        },
    }

@app.get("/config")
def get_config() -> Dict[str, float]:
    return asdict(config)

@app.post("/fuse", response_model=FusionAlert, dependencies=[Depends(verify_token)])
def fuse(payload: FusionInput) -> FusionAlert:
    return engine.infer(payload)

@app.post("/fuse/cot", dependencies=[Depends(verify_token)])
def fuse_to_cot(payload: FusionInput) -> Dict[str, Any]:
    alert = engine.infer(payload)
    return {"alert": alert.model_dump(), "cot": CotBridge.to_cot(alert)}

@app.get("/history")
def history(limit: int = 20) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, config.history_limit))
    return list(engine.history)[:limit]

@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
