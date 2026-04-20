\"\"\"
fusion_pipeline.py — H-NSD Multi-Sensor Fusion Pipeline
ChaosTech Defense LLC

This module is a LIBRARY only. It does not create a FastAPI app at import time.
The FastAPI app lives in api/routes.py and mounts this engine as a dependency.

Fixes applied (PR patch):
 - [BUG] Globals defined after use -> moved before FusionEngine class
 - [BUG] alert_id millisecond collision -> uuid4
 - [BUG] Deprecated @app.on_event -> lifespan context manager (handled in routes.py)
 - [BUG] Double logging.basicConfig -> removed from this module (owned by main.py)
 - [BUG] CoT XML via string interpolation -> xml.etree.ElementTree
 - [BUG] broadcaster() crashes silently on infer() error -> wrapped in try/except (handled in routes.py)
 - [DESIGN] Module-level FastAPI app removed — this file is now import-safe
 - [DESIGN] clients list -> asyncio-safe set + lock (handled in routes.py)
 - [SECURITY] Auth dependency stub added (wired in routes.py)
 - [QUALITY] swarm renamed from swarm_count
\"\"\"
from __future__ import annotations
import asyncio
import json
import logging
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Literal, Optional, Set
from pydantic import BaseModel

logger = logging.getLogger(\"nsd.fusion\")

# ---------------------------------------------------------------------------
# Metrics — defined BEFORE FusionEngine so infer() can reference them safely
# ---------------------------------------------------------------------------
FUSION_CLASS_COUNTS: Counter = Counter()
FUSION_TOTAL: int = 0
FUSION_CONF_SUM: float = 0.0
FUSION_MARGIN_SUM: float = 0.0

# ---------------------------------------------------------------------------
# Pydantic sensor models
# ---------------------------------------------------------------------------
class RfObservation(BaseModel):
    protocol: str = \"unknown\"
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
    mode: Literal[\"software\", \"akida\"] = \"software\"

class FusionAlert(BaseModel):
    timestamp: datetime
    alert_id: str
    classification: Literal[\"scout\", \"attack\", \"dispersed\", \"unknown\"]
    confidence: float
    swarm: int # Renamed from swarm_count
    bearing_deg: float
    range_m: Optional[float]
    sensors: List[str]
    feature_vector: Dict[str, float]
    fusion_scores: Dict[str, float]
    source_mode: Literal[\"software\", \"akida-simulated\"]

# ---------------------------------------------------------------------------
# Pipeline config
# ---------------------------------------------------------------------------
@dataclass
class PipelineConfig:
    \"\"\"
    Sensor fusion weights. Must sum to 1.0 across all four sensors.
    Adjust empirically based on field SNR observations per band.
    \"\"\"
    rf_weight: float = 0.35
    mmwave_weight: float = 0.28
    acoustic_weight: float = 0.17
    thermal_weight: float = 0.20
    history_limit: int = 200

# ---------------------------------------------------------------------------
# Fusion engine
# ---------------------------------------------------------------------------
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
            \"rf_energy\": round(rf_energy, 4),
            \"rf_burst\": round(rf_burst, 4),
            \"mmwave_motion\": round(mmwave_motion, 4),
            \"mmwave_velocity\": round(mmwave_velocity, 4),
            \"acoustic_harmonic\": round(acoustic_harmonic, 4),
            \"acoustic_snr\": round(acoustic_snr, 4),
            \"thermal_delta\": round(thermal_delta, 4),
            \"thermal_blobs\": round(thermal_blobs, 4),
        }

    def classify(self, features: Dict[str, float], payload: FusionInput) -> Dict[str, Any]:
        scout = (
            0.20 * features[\"rf_energy\"] +
            0.30 * features[\"mmwave_motion\"] +
            0.22 * features[\"acoustic_harmonic\"] +
            0.15 * features[\"thermal_delta\"] +
            0.13 * (1.0 - features[\"thermal_blobs\"])
        )
        attack = (
            0.22 * features[\"rf_burst\"] +
            0.28 * features[\"mmwave_velocity\"] +
            0.18 * features[\"mmwave_motion\"] +
            0.16 * features[\"thermal_delta\"] +
            0.16 * features[\"thermal_blobs\"]
        )
        dispersed = (
            0.15 * features[\"rf_energy\"] +
            0.08 * features[\"rf_burst\"] +
            0.12 * features[\"mmwave_motion\"] +
            0.20 * features[\"acoustic_snr\"] +
            0.45 * features[\"thermal_blobs\"]
        )
        
        scores = {
            \"scout\": round(self._clip(scout), 4),
            \"attack\": round(self._clip(attack), 4),
            \"dispersed\": round(self._clip(dispersed), 4),
        }
        
        classification = max(scores, key=scores.get)
        confidence = round(scores[classification], 4)
        
        # swarm: a 1–9 heuristic index only.
        swarm = max(1, round(
            1 + 8 * ((features[\"thermal_blobs\"] + features[\"rf_burst\"] + features[\"mmwave_motion\"]) / 3.0)
        ))
        
        bearing_candidates = []
        if payload.mmwave:
            bearing_candidates.append(payload.mmwave.angle_deg)
        if payload.acoustic:
            bearing_candidates.append(payload.acoustic.bearing_deg)
            
        bearing = round(sum(bearing_candidates) / len(bearing_candidates), 2) if bearing_candidates else 0.0
        range_m = round(payload.mmwave.range_m, 2) if payload.mmwave else None
        
        sensors = [s for s in [
            \"rf\" if payload.rf else None,
            \"mmwave\" if payload.mmwave else None,
            \"acoustic\" if payload.acoustic else None,
            \"thermal\" if payload.thermal else None,
        ] if s]
        
        return {
            \"classification\": classification,
            \"confidence\": confidence,
            \"swarm\": swarm,
            \"bearing_deg\": bearing,
            \"range_m\": range_m,
            \"sensors\": sensors,
            \"scores\": scores,
        }

    def infer(self, payload: FusionInput) -> FusionAlert:
        features = self.build_feature_vector(payload)
        result = self.classify(features, payload)
        
        # Use uuid4 to guarantee uniqueness
        alert = FusionAlert(
            timestamp = payload.timestamp or datetime.now(timezone.utc),
            alert_id = f\"fusion-{uuid.uuid4().hex[:12]}\",
            classification = result[\"classification\"],
            confidence = result[\"confidence\"],
            swarm = result[\"swarm\"],
            bearing_deg = result[\"bearing_deg\"],
            range_m = result[\"range_m\"],
            sensors = result[\"sensors\"],
            feature_vector = features,
            fusion_scores = result[\"scores\"],
            source_mode = \"akida-simulated\" if payload.mode == \"akida\" else \"software\",
        )
        
        self.history.appendleft(alert.model_dump())
        
        logger.info(
            \"fusion_alert id=%s cls=%s conf=%.3f swarm=%d bearing=%.1f range=%.1f\",
            alert.alert_id, alert.classification, alert.confidence,
            alert.swarm, alert.bearing_deg, alert.range_m or -1.0
        )
        
        global FUSION_TOTAL, FUSION_CONF_SUM, FUSION_MARGIN_SUM
        FUSION_CLASS_COUNTS[alert.classification] += 1
        FUSION_TOTAL += 1
        FUSION_CONF_SUM += alert.confidence
        
        if alert.fusion_scores and len(alert.fusion_scores) >= 2:
            sorted_scores = sorted(alert.fusion_scores.values(), reverse=True)
            FUSION_MARGIN_SUM += sorted_scores[0] - sorted_scores[1]
            
        return alert

# ---------------------------------------------------------------------------
# CoT bridge — XML built safely via ElementTree
# ---------------------------------------------------------------------------
class CotBridge:
    @staticmethod
    def to_cot(alert: FusionAlert, lat: float = 0.0, lon: float = 0.0, hae: float = 0.0) -> str:
        ts = alert.timestamp.astimezone(timezone.utc).strftime(\"%Y-%m-%dT%H:%M:%S.%f\")[:-3] + \"Z\"
        stale = datetime.fromtimestamp(
            alert.timestamp.timestamp() + 120, tz=timezone.utc
        ).strftime(\"%Y-%m-%dT%H:%M:%S.%f\")[:-3] + \"Z\"
        
        event = ET.Element(\"event\", attrib={
            \"version\": \"2.0\",
            \"uid\": alert.alert_id,
            \"type\": \"a-h-A-M-F-U-C\",
            \"how\": \"m-g\",
            \"time\": ts,
            \"start\": ts,
            \"stale\": stale,
        })
        
        ET.SubElement(event, \"point\", attrib={
            \"lat\": str(lat),
            \"lon\": str(lon),
            \"hae\": str(hae),
            \"ce\": \"25.0\",
            \"le\": \"15.0\",
        })
        
        detail = ET.SubElement(event, \"detail\")
        ET.SubElement(detail, \"contact\", attrib={\"callsign\": \"H-NSD Fusion\"})
        
        remarks_text = (
            f\"class={alert.classification}; conf={alert.confidence}; \"
            f\"swarm={alert.swarm}; bearing={alert.bearing_deg}; \"
            f\"sensors={','.join(alert.sensors)}\"
        )
        remarks = ET.SubElement(detail, \"remarks\")
        remarks.text = remarks_text
        
        ET.SubElement(detail, \"track\", attrib={
            \"course\": str(alert.bearing_deg),
            \"speed\": \"0.0\",
        })
        
        return ET.tostring(event, encoding=\"unicode\", xml_declaration=False)

# ---------------------------------------------------------------------------
# Singleton engine
# ---------------------------------------------------------------------------
config = PipelineConfig()
engine = FusionEngine(config)
