from psd_scanner import scan_band, detect_peaks
iq = scan_band(433e6)
freqs, psd, peaks, noise = detect_peaks(iq, 433e6)
print(f"Peaks found: {len(peaks)}")
print(f"Noise floor: {noise:.1f} dB")
if peaks:
    print("Strongest:", peaks[0])
