import cv2
import numpy as np

class LightingAnalyzer:

    def analyze(self, gray_image):
        sobelx = cv2.Sobel(gray_image, cv2.CV_64F, 1, 0)
        sobely = cv2.Sobel(gray_image, cv2.CV_64F, 0, 1)

        angles = np.arctan2(sobely, sobelx)
        angle_std = np.std(angles)

        inconsistent = angle_std > 1.2

        return {
            "lighting_inconsistency_detected": inconsistent,
            "confidence": round(min(1.0, angle_std / 2.0), 2),
            "reason": "Multiple dominant lighting directions"
        }
