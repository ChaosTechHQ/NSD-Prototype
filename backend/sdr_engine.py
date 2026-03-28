"""
NSD v19 - SDR Scanning Engine
ChaosTech Defense LLC

Real-time RF scanning using NESDR Nano 2+ (RTL2832U / R820T2).
Performs band-hopping FFT energy detection across drone-relevant frequencies.
Outputs structured ScanResult objects consumed by the FastAPI backend.

Hardware chain:
  Antenna → LNA → SMA-MCX adapter → NESDR Nano 2+ → Pi USB

IMPORTANT: This module requires librtlsdr to be installed on the host:
  sudo apt-get install rtl-sdr librtlsdr-dev
  sudo pip3 install pyrtlsdr
"""

import time
import threading
import logging
import numpy as np
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Deque
from collections import deque

logger = logging.getLogger("nsd.sdr_engine")

# ---------------------------------------------------------------------------
# Band definitions — all frequencies in Hz
# These cover the primary drone control, telemetry, and video link bands.
# ---------------------------------------------------------------------------
SCAN_BANDS = [
    {"name": "433MHz_ISM",   "center": 433.920e6, "label": "433 MHz",  "protocol": "FrSky/LoRa/Telemetry"},
    {"name": "868MHz_ISM",   "center": 868.000e6, "label": "868 MHz",  "protocol": "ELRS/Telemetry"},
    {"name": "915MHz_ISM",   "center": 915.000e6, "label": "915 MHz",  "protocol": "ELRS/MAVLink"},
    {"name": "1090MHz_ADSB", "center": 1090.00e6, "label": "1090 MHz", "protocol": "ADS-B"},
    {"name": "2437MHz_WiFi", "center": 2437.00e6, "label": "2.4 GHz",  "protocol": "DJI/WiFi/MAVLink"},
    {"name": "5800MHz_FPV",  "center": 5800.00e6, "label": "5.8 GHz",  "protocol": "FPV Video"},
]

# RTL-SDR hardware constraints
RTL_SDR_MAX_FREQ_HZ = 2.5e9
RTL_SDR_HARD_MAX_HZ = 5.0e9

SAMPLE_RATE     = 2.048e6
FFT_SIZE        = 1024
SAMPLES_TO_READ = FFT_SIZE * 4
DWELL_TIME_S    = 0.05
NOISE_FLOOR_AVG = 20
DETECTION_THRESHOLD_DB = 12.0

BAND_SCAN_CONFIG = {
    "2437MHz_WiFi": {
        "sample_rate":  1.024e6,
        "gain":         49.6,
        "dwell_s":      0.12,
        "samples":      FFT_SIZE * 4,
    },
}


@dataclass
class BandReading:
    """Processed result for a single band dwell."""
    band_name:      str
    center_hz:      float
    label:          str
    protocol:       str
    peak_power_db:  float
    noise_floor_db: float
    snr_db:         float
    peak_freq_hz:   float
    bandwidth_hz:   float
    is_detection:   bool
    timestamp:      float = field(default_factory=time.time)
    simulated:      bool  = False


@dataclass
class ScanCycle:
    """One complete sweep across all configured bands."""
    bands:        List[BandReading]
    cycle_time_s: float
    timestamp:    float = field(default_factory=time.time)
    simulated:    bool  = False


class SDRScanner:
    """
    Band-hopping RF scanner using a single RTL-SDR dongle.

    Usage:
        scanner = SDRScanner()
        scanner.start()
        while True:
            result = scanner.get_latest_scan()
            ...
        scanner.stop()
    """

    def __init__(self, device_index: int = 0, sim_fallback: bool = True,
                 sim_seed: Optional[int] = None):
        self._device_index  = device_index
        self._sim_fallback  = sim_fallback
        self._sdr           = None
        self._running       = False
        self._thread: Optional[threading.Thread] = None
        self._latest_scan: Optional[ScanCycle] = None
        self._lock          = threading.Lock()
        self._noise_history: Dict[str, deque] = {
            b["name"]: deque(maxlen=NOISE_FLOOR_AVG) for b in SCAN_BANDS
        }
        self._hardware_ok   = False
        # Optional fixed seed for reproducible sim runs (demos / testing)
        self._rng = np.random.default_rng(sim_seed)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info("SDRScanner started.")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        self._release_sdr()
        logger.info("SDRScanner stopped.")

    def get_latest_scan(self) -> Optional['ScanCycle']:
        with self._lock:
            return self._latest_scan

    @property
    def hardware_ok(self) -> bool:
        return self._hardware_ok

    # ------------------------------------------------------------------
    # Internal: hardware init / release
    # ------------------------------------------------------------------

    def _init_sdr(self) -> bool:
        try:
            from rtlsdr import RtlSdr
            self._sdr = RtlSdr(self._device_index)
            self._sdr.sample_rate = SAMPLE_RATE
            self._sdr.gain = 'auto'
            try:
                self._sdr.set_direct_sampling(0)
                logger.info("Direct sampling disabled (VHF/UHF mode active).")
            except Exception:
                pass
            self._hardware_ok = True
            logger.info(f"RTL-SDR opened: device {self._device_index}, "
                        f"sample_rate={SAMPLE_RATE/1e6:.3f} MSPS")
            return True
        except Exception as e:
            logger.warning(f"RTL-SDR init failed: {e}")
            self._hardware_ok = False
            return False

    def _release_sdr(self):
        if self._sdr is not None:
            try:
                self._sdr.close()
            except Exception:
                pass
            self._sdr = None

    # ------------------------------------------------------------------
    # Internal: scan loop
    # ------------------------------------------------------------------

    def _scan_loop(self):
        hw_available = self._init_sdr()

        if not hw_available and not self._sim_fallback:
            logger.error("No RTL-SDR hardware and simulation fallback disabled. Stopping.")
            return

        if not hw_available:
            logger.warning("RTL-SDR unavailable — running in SIMULATION mode.")

        while self._running:
            cycle_start = time.time()
            band_results = []

            for band in SCAN_BANDS:
                if not self._running:
                    break
                reading = self._read_band_hw(band) if hw_available else self._read_band_sim(band)
                band_results.append(reading)

            cycle_time = time.time() - cycle_start
            scan = ScanCycle(
                bands=band_results,
                cycle_time_s=cycle_time,
                simulated=not hw_available,
            )
            with self._lock:
                self._latest_scan = scan

    # ------------------------------------------------------------------
    # Internal: real hardware band reading
    # ------------------------------------------------------------------

    def _read_band_hw(self, band: dict) -> BandReading:
        center_hz = band["center"]

        if center_hz > RTL_SDR_HARD_MAX_HZ:
            r = self._read_band_sim(band)
            r.simulated = True
            return r

        cfg         = BAND_SCAN_CONFIG.get(band["name"], {})
        sample_rate = cfg.get("sample_rate", SAMPLE_RATE)
        gain        = cfg.get("gain", None)
        dwell_s     = cfg.get("dwell_s", DWELL_TIME_S)
        num_samples = cfg.get("samples", SAMPLES_TO_READ)

        try:
            if sample_rate != self._sdr.sample_rate:
                self._sdr.sample_rate = sample_rate
            if gain is not None:
                self._sdr.gain = gain

            self._sdr.center_freq = center_hz
            time.sleep(dwell_s)

            samples = self._sdr.read_samples(num_samples)

            if sample_rate != SAMPLE_RATE:
                try:
                    self._sdr.sample_rate = SAMPLE_RATE
                    self._sdr.gain = 'auto'
                except Exception:
                    pass

            return self._process_samples(samples, band, sample_rate=sample_rate)

        except Exception as e:
            logger.warning(f"SDR read failed on {band['name']} at {center_hz/1e6:.0f} MHz: {e} "
                           f"— falling back to simulation for this band.")
            try:
                self._sdr.sample_rate = SAMPLE_RATE
                self._sdr.gain = 'auto'
            except Exception:
                pass
            r = self._read_band_sim(band)
            r.simulated = True
            return r

    def _process_samples(
        self,
        samples: np.ndarray,
        band: dict,
        sample_rate: float = SAMPLE_RATE,
    ) -> BandReading:
        samples = np.array(samples, dtype=np.complex64)
        n = len(samples)

        window    = np.hanning(FFT_SIZE)
        num_frames = max(1, n // FFT_SIZE)
        psd_accum = np.zeros(FFT_SIZE)

        for i in range(num_frames):
            frame = samples[i * FFT_SIZE:(i + 1) * FFT_SIZE]
            if len(frame) < FFT_SIZE:
                break
            fft_out = np.fft.fftshift(np.fft.fft(frame * window))
            psd_accum += np.abs(fft_out) ** 2

        psd    = psd_accum / num_frames
        psd_db = 10.0 * np.log10(psd + 1e-12)

        freqs    = np.fft.fftshift(np.fft.fftfreq(FFT_SIZE, d=1.0 / sample_rate))
        freqs_hz = freqs + band["center"]

        noise_floor_db = float(np.median(psd_db))
        self._noise_history[band["name"]].append(noise_floor_db)
        avg_noise_db = float(np.mean(self._noise_history[band["name"]]))

        peak_idx      = int(np.argmax(psd_db))
        peak_power_db = float(psd_db[peak_idx])
        peak_freq_hz  = float(freqs_hz[peak_idx])
        snr_db        = peak_power_db - avg_noise_db

        threshold_db = peak_power_db - 3.0
        above        = psd_db >= threshold_db
        bw_bins      = int(np.sum(above))
        bandwidth_hz = bw_bins * (SAMPLE_RATE / FFT_SIZE)

        is_detection = snr_db >= DETECTION_THRESHOLD_DB

        return BandReading(
            band_name=band["name"],
            center_hz=band["center"],
            label=band["label"],
            protocol=band["protocol"],
            peak_power_db=round(peak_power_db, 2),
            noise_floor_db=round(avg_noise_db, 2),
            snr_db=round(snr_db, 2),
            peak_freq_hz=round(peak_freq_hz, 0),
            bandwidth_hz=round(bandwidth_hz, 0),
            is_detection=is_detection,
            simulated=False,
        )

    # ------------------------------------------------------------------
    # Internal: simulation fallback
    # ------------------------------------------------------------------

    def _read_band_sim(self, band: dict) -> BandReading:
        noise_map = {
            "433MHz_ISM":   -88.0,
            "868MHz_ISM":   -90.0,
            "915MHz_ISM":   -89.0,
            "1090MHz_ADSB": -85.0,
            "2437MHz_WiFi": -75.0,
            "5800MHz_FPV":  -80.0,
        }
        noise_floor = noise_map.get(band["name"], -88.0) + self._rng.normal(0, 1.5)

        if self._rng.random() < 0.20:
            snr_db        = float(self._rng.uniform(DETECTION_THRESHOLD_DB,
                                                     DETECTION_THRESHOLD_DB + 20))
            peak_power_db = noise_floor + snr_db
            is_detection  = True
            offset_hz     = float(self._rng.uniform(-0.5e6, 0.5e6))
            peak_freq_hz  = band["center"] + offset_hz
            bandwidth_hz  = float(self._rng.uniform(50e3, 500e3))
        else:
            snr_db        = float(self._rng.uniform(0, DETECTION_THRESHOLD_DB - 1))
            peak_power_db = noise_floor + snr_db
            is_detection  = False
            peak_freq_hz  = band["center"]
            bandwidth_hz  = float(self._rng.uniform(1e6, 2e6))

        return BandReading(
            band_name=band["name"],
            center_hz=band["center"],
            label=band["label"],
            protocol=band["protocol"],
            peak_power_db=round(float(peak_power_db), 2),
            noise_floor_db=round(float(noise_floor), 2),
            snr_db=round(float(snr_db), 2),
            peak_freq_hz=round(float(peak_freq_hz), 0),
            bandwidth_hz=round(float(bandwidth_hz), 0),
            is_detection=is_detection,
            simulated=True,
        )
