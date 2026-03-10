
import numpy as np
from rtlsdr import RtlSdr
import time, json, os

def scan_spectrum():
    sdr = RtlSdr()
    sdr.sample_rate = 2.4e6
    sdr.center_freq = 433.92e6
    sdr.gain = "auto"
    _ = sdr.read_samples(2048)
    print("SDR FFT Scanner Started: Monitoring 433.92 MHz")
    while True:
        try:
            samples = sdr.read_samples(1024)
            psd = np.abs(np.fft.fft(samples))**2 / (1024 * sdr.sample_rate)
            psd_log = 10.0 * np.log10(psd + 1e-12)
            psd_shifted = np.fft.fftshift(psd_log)
            ui_spectrum = psd_shifted[::4].tolist()
            with open("/dev/shm/nsd_psd.json", "w") as f:
                json.dump({"timestamp": time.time(), "center_freq_mhz": 433.92, "span_mhz": 2.4, "data_points": len(ui_spectrum), "spectrum_db": ui_spectrum}, f)
            time.sleep(0.1)
        except Exception as e:
            print(f"SDR error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    scan_spectrum()
