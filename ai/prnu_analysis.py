import cv2
import numpy as np

class PRNUAnalyzer:

    def analyze(self, gray_image):
        denoised = cv2.GaussianBlur(gray_image, (5,5), 0)
        noise = gray_image.astype(np.float32) - denoised.astype(np.float32)

        std = np.std(noise)
        spatial_var = np.var(noise, axis=0).mean()

        inconsistent = spatial_var > std * 1.5

        return {
            "prnu_inconsistency_detected": inconsistent,
            "confidence": round(min(1.0, spatial_var / (std + 1e-5)), 2),
            "reason": "Noise pattern inconsistency across image"
        }
