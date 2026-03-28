"""
NSD v19 - Protocol Fingerprinter
ChaosTech Defense LLC

Rule-based RF protocol identification using measured signal characteristics:
  - Occupied bandwidth (3 dB)
  - Frequency offset from band center
  - SNR
  - Band (provides coarse prior)

This is Phase 1 classification — deterministic rules derived from published
protocol specifications and empirical SDR observations. Phase 2 will replace
or augment this with a trained classifier on real I/Q feature vectors.

Rules are grounded in published protocol specs (verify against current specs):
  - FrSky D16: 8 channels, 2 ms hop, ~500 kHz occupied BW @ 433 MHz
  - LoRa (Semtech SX127x): BW configurable 7.8–500 kHz, typically 125 kHz
  - ELRS (ExpressLRS): FHSS, ~500 kHz channel BW, 433/868/915 MHz
  - DJI OcuSync 2/3: OFDM, 10 MHz BW @ 2.4 GHz
  - MAVLink over telemetry radio: narrowband, <100 kHz BW
  - ADS-B Mode S: 1090 MHz, ~1 MHz BW, 1 µs pulses (PPM)
  - WiFi 802.11n/ac: 20/40/80 MHz BW @ 2.4/5 GHz

IMPORTANT: These rules produce a best-guess identification with a confidence
score. They are NOT definitive. Multiple protocols share bands and overlapping
bandwidth ranges. The confidence field communicates this honestly.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FingerprintResult:
    protocol:   str
    confidence: str   # HIGH / MEDIUM / LOW
    conf_pct:   int   # 0–100
    notes:      str


# ---------------------------------------------------------------------------
# Rule tables
# Each entry: (min_bw_khz, max_bw_khz, protocol_name, confidence_pct, notes)
# Rules evaluated in order; first match wins.
# ---------------------------------------------------------------------------

_433_RULES = [
    (0,    50,   "LoRa/FSK Beacon",      70, "Very narrowband 433 MHz — LoRa or narrowband FSK"),
    (50,   200,  "LoRa Telemetry",       85, "Narrowband 433 MHz — consistent with LoRa 125/250 kHz BW"),
    (200,  800,  "FrSky D16/FHSS",       75, "Mid-band 433 MHz — consistent with FrSky D16 hop channel BW"),
    (200,  800,  "ELRS 433 MHz",         70, "Mid-band 433 MHz — also consistent with ExpressLRS"),
    (800,  2048, "FHSS Spread Spectrum", 50, "Wideband 433 MHz — possible FHSS drone control link"),
    (0,    9999, "Unknown 433 MHz ISM",  30, "No specific protocol match — generic ISM activity"),
]

_868_RULES = [
    (0,    50,   "LoRa/FSK 868 MHz",  70, "Very narrowband 868 MHz — LoRa or narrowband FSK"),
    (50,   200,  "LoRa 868 MHz",      85, "Narrowband 868 MHz — LoRa 125/250 kHz BW"),
    (200,  800,  "ELRS 868 MHz",      80, "Mid-band 868 MHz — consistent with ExpressLRS hop channel"),
    (800,  2048, "FHSS 868 MHz",      50, "Wideband 868 MHz — possible FHSS control link"),
    (0,    9999, "Unknown 868 MHz ISM", 30, "No specific protocol match"),
]

_915_RULES = [
    (0,    100,  "MAVLink Telemetry", 80, "Very narrowband 915 MHz — consistent with MAVLink telemetry radio"),
    (100,  600,  "ELRS 915 MHz",     80, "Mid-band 915 MHz — consistent with ExpressLRS"),
    (600,  2048, "FHSS 915 MHz",     50, "Wideband 915 MHz — possible FHSS control"),
    (0,    9999, "Unknown 915 MHz ISM", 30, "No specific protocol match"),
]

_1090_RULES = [
    (30,   2000, "ADS-B Mode S",        85, "1090 MHz signal — consistent with ADS-B Mode S"),
    (0,    30,   "1090 MHz Narrowband", 35, "Very narrowband 1090 MHz — unusual for ADS-B"),
    (0,    9999, "Unknown 1090 MHz",    30, "No specific protocol match"),
]

_2437_RULES = [
    (0,    50,   "MAVLink/Telemetry",  65, "Very narrowband 2.4 GHz — possible MAVLink over WiFi"),
    (50,   500,  "DJI OcuSync RC",     70, "Narrowband 2.4 GHz — possible DJI RC control channel"),
    (500,  5000, "DJI OcuSync/WiFi",   65, "Mid-band 2.4 GHz — DJI OcuSync 2/3 or 802.11 WiFi"),
    (5000, 99999,"WiFi 802.11 n/ac",   75, "Wideband 2.4 GHz — consistent with WiFi 20/40 MHz channel"),
    (0,    9999, "Unknown 2.4 GHz",    30, "No specific protocol match"),
]

_5800_RULES = [
    (0,    500,  "FPV Analog Video", 60, "Narrowband 5.8 GHz — possible analog FPV video"),
    (500,  5000, "DJI HD FPV",       65, "Mid-band 5.8 GHz — possible DJI HD FPV link"),
    (5000, 99999,"WiFi 5 GHz",       70, "Wideband 5.8 GHz — consistent with 802.11ac"),
    (0,    9999, "Unknown 5.8 GHz",  30, "No specific protocol match"),
]

_BAND_RULE_MAP = {
    "433MHz_ISM":   _433_RULES,
    "868MHz_ISM":   _868_RULES,
    "915MHz_ISM":   _915_RULES,
    "1090MHz_ADSB": _1090_RULES,
    "2437MHz_WiFi": _2437_RULES,
    "5800MHz_FPV":  _5800_RULES,
}


def _conf_pct_to_label(pct: int) -> str:
    if pct >= 75:  return "HIGH"
    elif pct >= 50: return "MEDIUM"
    else:           return "LOW"


def fingerprint(
    band_name:    str,
    bandwidth_hz: float,
    snr_db:       float,
    freq_hz:      float,
    center_hz:    float,
) -> FingerprintResult:
    """
    Classify a detected signal using rule-based protocol fingerprinting.

    Args:
        band_name:    Band identifier from SCAN_BANDS
        bandwidth_hz: Measured 3 dB occupied bandwidth in Hz
        snr_db:       Signal-to-noise ratio in dB
        freq_hz:      Peak frequency in Hz
        center_hz:    Band center frequency in Hz

    Returns:
        FingerprintResult with protocol name, confidence, and rationale.
    """
    rules = _BAND_RULE_MAP.get(band_name)
    if rules is None:
        return FingerprintResult(
            protocol="Unknown Band", confidence="LOW", conf_pct=0,
            notes=f"No fingerprint rules defined for band: {band_name}",
        )

    bw_khz = bandwidth_hz / 1e3

    for (min_bw, max_bw, protocol, conf_pct, notes) in rules:
        if min_bw <= bw_khz < max_bw:
            if snr_db < 15.0:
                conf_pct = max(conf_pct - 15, 20)
                notes    = notes + f" [confidence reduced: low SNR {snr_db:.1f} dB]"
            offset_mhz = abs(freq_hz - center_hz) / 1e6
            if offset_mhz > 2.0:
                conf_pct = max(conf_pct - 10, 20)
                notes    = notes + f" [offset {offset_mhz:.1f} MHz from center]"
            return FingerprintResult(
                protocol=protocol,
                confidence=_conf_pct_to_label(conf_pct),
                conf_pct=conf_pct,
                notes=notes,
            )

    return FingerprintResult(
        protocol=f"Unknown {band_name}", confidence="LOW", conf_pct=20,
        notes="No rule matched.",
    )
