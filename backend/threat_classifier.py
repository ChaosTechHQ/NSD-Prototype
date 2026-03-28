"""
NSD v19 - Threat Classifier
ChaosTech Defense LLC

Converts raw BandReading objects from the SDR engine into structured
ThreatObject records suitable for the tactical display.

Persistence filter (added v19.2):
  A signal must be detected in `persist_hits` consecutive scan cycles
  before it is promoted to an active ThreatObject. This eliminates
  single-scan noise spikes and transient interference from being
  reported as threats. The hit counter resets if the band goes quiet
  for more than `persist_timeout_s` seconds.

  Default: 3 consecutive hits required (~3 scan cycles ≈ 1.5 seconds
  at 0.5 s/cycle). Configurable at construction time.

Classification logic is rule-based (Phase 1). Phase 2 replaces this
with a trained scikit-learn / tflite model on real I/Q feature vectors.

No bearing or range is computed here — the NESDR Nano 2+ with a single
omnidirectional antenna cannot determine AoA or time-of-flight range.
Those fields are explicitly absent to maintain technical honesty.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from sdr_engine import BandReading, DETECTION_THRESHOLD_DB
from protocol_fingerprint import fingerprint, FingerprintResult

logger = logging.getLogger("nsd.threat_classifier")


# ---------------------------------------------------------------------------
# Threat classification rules
# ---------------------------------------------------------------------------
BAND_RISK_WEIGHT = {
    "433MHz_ISM":   0.70,
    "868MHz_ISM":   0.75,
    "915MHz_ISM":   0.80,
    "1090MHz_ADSB": 0.40,
    "2437MHz_WiFi": 0.90,
    "5800MHz_FPV":  0.65,
}

MIN_SNR_FOR_THREAT = DETECTION_THRESHOLD_DB


@dataclass
class _Candidate:
    band_name:      str
    hit_count:      int   = 0
    last_seen:      float = field(default_factory=time.time)
    snr_sum:        float = 0.0
    latest_reading: Optional[BandReading] = None


@dataclass
class ThreatObject:
    """
    A classified RF threat event.
    bearing_deg and range_km are intentionally absent — a single
    omnidirectional antenna cannot determine AoA or range.
    """
    id:              str
    band_name:       str
    freq_mhz:        float
    bandwidth_khz:   float
    power_dbm:       float
    noise_floor_dbm: float
    snr_db:          float
    protocol:        str
    threat_score:    int
    threat_level:    str
    simulated:       bool
    fp_protocol:     str   = ""
    fp_confidence:   str   = ""
    fp_conf_pct:     int   = 0
    fp_notes:        str   = ""
    confirmed_hits:  int   = 1
    timestamp:       float = field(default_factory=time.time)


class ThreatClassifier:
    """
    Stateful classifier with a two-stage pipeline:

    Stage 1 — Candidate tracking (persistence filter):
      Each band detection increments a hit counter. Only after
      `persist_hits` consecutive detections is a ThreatObject created.

    Stage 2 — Active threat registry:
      Confirmed threats are held in the registry and updated on each
      subsequent detection. Threats expire after `dedup_window_s * 3`
      seconds without a refresh.
    """

    def __init__(
        self,
        dedup_window_s:    float = 8.0,
        max_threats:       int   = 100,
        persist_hits:      int   = 3,
        persist_timeout_s: float = 5.0,
    ):
        self._dedup_window_s    = dedup_window_s
        self._max_threats       = max_threats
        self._persist_hits      = persist_hits
        self._persist_timeout_s = persist_timeout_s
        self._candidates: Dict[str, _Candidate]    = {}
        self._threat_registry: Dict[str, ThreatObject] = {}
        self._threat_counter = 0
        self._all_threats: List[ThreatObject] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_band(self, reading: BandReading) -> Optional[ThreatObject]:
        now = time.time()

        if not reading.is_detection or reading.snr_db < MIN_SNR_FOR_THREAT:
            self._decay_candidate(reading.band_name, now)
            self._expire_threat(reading.band_name, now)
            return None

        if reading.band_name in self._threat_registry:
            threat = self._threat_registry[reading.band_name]
            threat.power_dbm    = reading.peak_power_db
            threat.snr_db       = reading.snr_db
            threat.timestamp    = now
            threat.threat_score = self._compute_score(reading)
            threat.threat_level = self._score_to_level(threat.threat_score)
            fp = fingerprint(
                band_name=reading.band_name,
                bandwidth_hz=reading.bandwidth_hz,
                snr_db=reading.snr_db,
                freq_hz=reading.peak_freq_hz,
                center_hz=reading.center_hz,
            )
            threat.fp_protocol   = fp.protocol
            threat.fp_confidence = fp.confidence
            threat.fp_conf_pct   = fp.conf_pct
            threat.fp_notes      = fp.notes
            return threat

        cand = self._candidates.get(reading.band_name)
        if cand is None or (now - cand.last_seen) > self._persist_timeout_s:
            cand = _Candidate(band_name=reading.band_name)
            self._candidates[reading.band_name] = cand

        cand.hit_count      += 1
        cand.snr_sum        += reading.snr_db
        cand.last_seen       = now
        cand.latest_reading  = reading

        if cand.hit_count < self._persist_hits:
            logger.debug(
                f"Candidate {reading.band_name}: hit {cand.hit_count}/{self._persist_hits} "
                f"SNR={reading.snr_db:.1f} dB"
            )
            return None

        avg_snr = cand.snr_sum / cand.hit_count
        r = cand.latest_reading

        self._threat_counter += 1
        threat = ThreatObject(
            id=f"T-{self._threat_counter:04d}",
            band_name=r.band_name,
            freq_mhz=round(r.peak_freq_hz / 1e6, 3),
            bandwidth_khz=round(r.bandwidth_hz / 1e3, 1),
            power_dbm=r.peak_power_db,
            noise_floor_dbm=r.noise_floor_db,
            snr_db=avg_snr,
            protocol=r.protocol,
            threat_score=self._compute_score(r),
            threat_level="",
            simulated=r.simulated,
            confirmed_hits=cand.hit_count,
        )
        threat.threat_level = self._score_to_level(threat.threat_score)

        fp = fingerprint(
            band_name=r.band_name,
            bandwidth_hz=r.bandwidth_hz,
            snr_db=avg_snr,
            freq_hz=r.peak_freq_hz,
            center_hz=r.center_hz,
        )
        threat.fp_protocol   = fp.protocol
        threat.fp_confidence = fp.confidence
        threat.fp_conf_pct   = fp.conf_pct
        threat.fp_notes      = fp.notes

        self._threat_registry[reading.band_name] = threat
        self._all_threats.append(threat)
        del self._candidates[reading.band_name]

        if len(self._all_threats) > self._max_threats:
            self._all_threats = self._all_threats[-self._max_threats:]

        logger.info(
            f"Threat confirmed: {threat.id} | {threat.freq_mhz} MHz | "
            f"Protocol: {fp.protocol} [{fp.confidence} {fp.conf_pct}%] | "
            f"SNR={threat.snr_db:.1f} dB (avg over {threat.confirmed_hits} hits) | "
            f"Score={threat.threat_score} | {threat.threat_level}"
        )
        return threat

    def get_active_threats(self) -> List[ThreatObject]:
        now = time.time()
        return [
            t for t in self._threat_registry.values()
            if now - t.timestamp < self._dedup_window_s * 3
        ]

    def get_threat_count(self) -> int:
        return len(self.get_active_threats())

    def get_total_detected(self) -> int:
        return self._threat_counter

    def get_candidate_count(self) -> int:
        return len(self._candidates)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _decay_candidate(self, band_name: str, now: float) -> None:
        cand = self._candidates.get(band_name)
        if cand and (now - cand.last_seen) > self._persist_timeout_s:
            del self._candidates[band_name]
            logger.debug(f"Candidate {band_name} timed out — hit counter reset.")

    def _expire_threat(self, band_name: str, now: float) -> None:
        threat = self._threat_registry.get(band_name)
        if threat and (now - threat.timestamp) > self._dedup_window_s * 3:
            del self._threat_registry[band_name]
            logger.info(f"Threat expired: {threat.id} | {band_name}")

    def _compute_score(self, reading: BandReading) -> int:
        risk_weight = BAND_RISK_WEIGHT.get(reading.band_name, 0.5)
        snr_norm    = min(reading.snr_db / 30.0, 1.0)
        score       = int(snr_norm * risk_weight * 100)
        return max(0, min(100, score))

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 75:   return "CRITICAL"
        elif score >= 50: return "HIGH"
        elif score >= 25: return "MEDIUM"
        else:             return "LOW"
