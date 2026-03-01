import numpy as np
from rtlsdr import RtlSdr
import time

def scan_band(center_freq_hz, sample_rate_hz=2.4e6, num_samples=65536, gain='auto'):
    """Returns (freqs_hz, psd_db, fft_out) — 3-tuple, fft_out for phase extraction."""
    sdr = None
    try:
        sdr = RtlSdr()
        sdr.direct_sampling = 0
        sdr.sample_rate     = sample_rate_hz
        sdr.center_freq     = center_freq_hz
        sdr.gain            = gain
        time.sleep(0.15)
        _  = sdr.read_samples(1024)
        iq = sdr.read_samples(num_samples)
        sdr.close()
    except Exception as e:
        if sdr:
            try: sdr.close()
            except: pass
        raise RuntimeError(f"SDR read failed at {center_freq_hz/1e6:.1f} MHz: {e}")
    iq        = np.array(iq, dtype=np.complex64)
    n         = len(iq)
    window    = np.hanning(n)
    fft_out   = np.fft.fftshift(np.fft.fft(iq * window))
    psd_db    = 10 * np.log10(np.abs(fft_out) ** 2 + 1e-12)
    freq_bins = np.fft.fftshift(np.fft.fftfreq(n, d=1.0 / sample_rate_hz))
    freqs_hz  = center_freq_hz + freq_bins
    return freqs_hz, psd_db, fft_out

def detect_peaks(freqs_hz, psd_db, fft_out=None, threshold_db=20.0):
    noise_floor = float(np.median(psd_db))
    above       = psd_db - noise_floor
    peak_idx    = np.where(above > threshold_db)[0]
    peaks = []
    if len(peak_idx) > 0:
        clusters = np.split(peak_idx, np.where(np.diff(peak_idx) > 10)[0] + 1)
        for cluster in clusters:
            best  = cluster[np.argmax(psd_db[cluster])]
            phase = float(np.angle(fft_out[best])) if fft_out is not None else 0.0
            peaks.append({
                "freq_hz":        float(freqs_hz[best]),
                "power_db":       round(float(psd_db[best]), 2),
                "above_noise_db": round(float(above[best]), 2),
                "phase_rad":      phase,
            })
    peaks.sort(key=lambda x: x["power_db"], reverse=True)
    peaks = peaks[:25]
    return {"peaks": peaks, "noise_floor_db": round(noise_floor, 2), "peak_count": len(peaks)}
