import numpy as np
import cv2

class DeepfakeDetector:
    def analyze(self, gray):
        fft = np.fft.fft2(gray)
        fft_shift = np.fft.fftshift(fft)
        spectrum = np.log(np.abs(fft_shift) + 1)

        high_freq_energy = np.mean(spectrum)

        gan_probability = min(1.0, high_freq_energy / 12.0)

        return {
            "deepfake_probability": round(gan_probability, 3),
            "likely_gan_generated": gan_probability > 0.65
        }
