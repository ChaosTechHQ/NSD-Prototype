# psd_scanner.py — PROTOTYPE, not production
# ChaosTech Defense NSD — RF pipeline Layer 1

import numpy as np
from rtlsdr import RtlSdr
import time
import json

def acquire_iq(num_samples, center_freq_hz, sample_rate_hz=2_048_000, gain='auto'):
    sdr = RtlSdr()
    sdr.sample_rate = sample_rate_hz
    sdr.center_freq = center_freq_hz
    sdr.gain = gain
    
    try:
        # Discard first buffer — lets AGC settle
        _ = sdr.read_samples(1024)
        iq = sdr.read_samples(num_samples)
        return np.array(iq, dtype=np.complex64)
    finally:
        sdr.close()  # CRITICAL: always close immediately

def compute_psd_fft(iq, sample_rate_hz):
    """
    Simple FFT-based PSD estimator.
    Uses at most 262144 samples to avoid huge arrays on 32-bit Python.
    """
    iq = np.asarray(iq).ravel()
    n = iq.size

    if n < 2048:
        raise ValueError(f"Not enough samples for PSD: got {n}")

    # Hard cap to keep array sizes safe on 32-bit
    max_n = 262144
    if n > max_n:
        iq = iq[:max_n]
        n = max_n

    # Hann window to reduce spectral leakage
    window = np.hanning(n).astype(np.float32)
    x = iq * window

    # FFT and frequency axis
    X = np.fft.fftshift(np.fft.fft(x))
    freqs = np.fft.fftshift(np.fft.fftfreq(n, d=1.0 / sample_rate_hz))

    # PSD estimate (power per bin, arbitrary units)
    psd = (np.abs(X) ** 2) / (np.sum(window ** 2))
    psd_db = 10.0 * np.log10(psd + 1e-12)

    return freqs, psd_db

def scan_band(center_freq_hz, span_hz=2_000_000, dwell_s=0.5,
              sample_rate_hz=2_048_000):
    num_samples = int(sample_rate_hz * dwell_s)
    iq = acquire_iq(num_samples, center_freq_hz, sample_rate_hz)
    print(f"[NSD] Got {iq.size} IQ samples at {center_freq_hz/1e6:.3f} MHz")
    freqs, psd_db = compute_psd_fft(iq, sample_rate_hz)
    freqs_abs = freqs + center_freq_hz
    return freqs_abs, psd_db

def detect_peaks(freqs_hz, psd_db,
                 threshold_db=10.0,
                 min_separation_hz=50_000):
    median = np.median(psd_db)
    thr = median + threshold_db

    candidates = [
        (float(f), float(p))
        for f, p in zip(freqs_hz, psd_db)
        if p > thr
    ]

    # Sort strongest-first
    candidates.sort(key=lambda x: x[1], reverse=True)

    # Enforce minimum frequency separation between reported peaks
    peaks = []
    for f, p in candidates:
        if all(abs(f - pf["freq_hz"]) >= min_separation_hz for pf in peaks):
            peaks.append({"freq_hz": f, "power_db": p})
        if len(peaks) >= 50:  # cap number of reported peaks
            break

    return {
        "noise_floor_db": float(median),
        "peaks": peaks,
    }

def scan_to_json(center_freq_mhz, span_mhz, outfile):
    center_hz = center_freq_mhz * 1e6
    freqs, psd_db = scan_band(center_hz, span_hz=span_mhz * 1e6)
    detection = detect_peaks(freqs, psd_db)

    points = [
        {"freq_hz": float(f), "power_db": float(p)}
        for f, p in zip(freqs, psd_db)
    ]

    output = {
        "center_freq_hz": center_hz,
        "timestamp": time.time(),
        "noise_floor_db": detection["noise_floor_db"],
        "points": points,
        "peaks": detection["peaks"],
    }

    with open(outfile, "w") as f:
        json.dump(output, f)

    print(f"[NSD] Scan complete.")
    print(f"[NSD] Noise floor : {detection['noise_floor_db']:.1f} dB")
    print(f"[NSD] Peaks found : {len(detection['peaks'])}")
    for pk in detection["peaks"][:10]:
        print(f"      {pk['freq_hz']/1e6:.3f} MHz  @ {pk['power_db']:.1f} dB")
    print(f"[NSD] Output saved: {outfile}")


if __name__ == "__main__":
    # NESDR Nano 2 / R820T max ~1766 MHz
    # Using 1090 MHz (ADS-B) for pipeline validation
    scan_to_json(
        center_freq_mhz=1090,
        span_mhz=2,
        outfile="psd_1090mhz.json"
    )
