# NSD v19 — Neuro Swarm Disruptor
**ChaosTech Defense LLC** | Passive RF Drone Detection System

---

## Overview
NSD v19 is a real-time passive RF sensing platform designed to detect, classify, and log drone activity across six frequency bands. It runs on a Raspberry Pi 4 with a NESDR Nano 2+ (RTL2832U / R820T2) dongle.

The system is **receive-only**. It does not transmit, jam, or interfere with any signals.

---

## Hardware
| Component | Details |
|---|---|
| SBC | Raspberry Pi 4 Model B (4 GB) |
| SDR | NooElec NESDR Nano 2+ (RTL2832U / R820T2) |
| LNA | Broadband LNA inline, SMA |
| Antenna | Omnidirectional wideband, SMA-MCX adapter |
| OS | Raspberry Pi OS Lite (64-bit), Python 3.11 |

---

## Monitored Bands
| Band | Center | Protocol |
|---|---|---|
| 433 MHz ISM | 433.920 MHz | FrSky / LoRa / Telemetry |
| 868 MHz ISM | 868.000 MHz | ELRS / Telemetry |
| 915 MHz ISM | 915.000 MHz | ELRS / MAVLink |
| 1090 MHz | 1090.000 MHz | ADS-B Mode S |
| 2.4 GHz | 2437.000 MHz | DJI OcuSync / WiFi / MAVLink |
| 5.8 GHz | 5800.000 MHz | FPV Video (simulated — out of R820T2 range) |

---

## Repository Structure
```
NSD-Prototype/
├── backend/                  # Core Python backend
│   ├── sdr_engine.py         # RTL-SDR band-hopping scanner + sim fallback
│   ├── threat_classifier.py  # Persistence filter + ThreatObject registry
│   ├── signal_db.py          # Thread-safe SQLite persistence layer
│   ├── protocol_fingerprint.py # Rule-based protocol ID (6 bands)
│   └── report_generator.py   # ReportLab PDF session report
├── api/                      # FastAPI application layer
├── frontend/                 # Tactical web UI
├── scanner/                  # Legacy scanner modules (reference only)
├── requirements.txt          # Python dependencies
└── README.md
```

---

## Quick Start
```bash
# 1. Install system dependencies
sudo apt-get install rtl-sdr librtlsdr-dev
sudo pip3 install -r requirements.txt

# 2. Blacklist DVB-T kernel driver (required for RTL-SDR access)
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/rtlsdr.conf
sudo rmmod dvb_usb_rtl28xxu 2>/dev/null || true

# 3. Run the API server
cd api/
uvicorn nsd_api:app --host 0.0.0.0 --port 8000

# 4. Open the tactical display
# Navigate to http://<pi-ip>:8000 in a browser on the same network
```

---

## Detection Pipeline
```
RTL-SDR hardware
    ↓ (I/Q samples)
sdr_engine.py         → BandReading per band (FFT, PSD, SNR)
    ↓
threat_classifier.py  → Persistence filter (3 hits) → ThreatObject
    ↓
signal_db.py          → SQLite (WAL mode, async writer queue)
    ↓
protocol_fingerprint.py → Rule-based protocol ID + confidence
    ↓
FastAPI (api/)        → WebSocket + REST endpoints
    ↓
frontend/             → Tactical display (browser)
```

---

## Limitations
- **No bearing or range.** A single omnidirectional antenna cannot determine angle-of-arrival or time-of-flight range. These fields are intentionally absent from all data structures.
- **5.8 GHz is always simulated.** The R820T2 tuner maximum is ~1.76 GHz (with degraded sensitivity to ~2.4 GHz). 5.8 GHz FPV detection requires a separate hardware stage.
- **Protocol ID is probabilistic.** The rule-based fingerprinter produces a best-guess with a stated confidence score. Multiple protocols share bands and bandwidth ranges.
- **RTL-SDR is not calibrated.** Power readings are relative, not absolute dBm. SNR thresholds are empirically tuned, not traceable to a reference.

---

*ChaosTech Defense LLC — For Official Use Only*
