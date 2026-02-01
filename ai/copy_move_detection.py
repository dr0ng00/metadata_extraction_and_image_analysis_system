import cv2
import numpy as np


class CopyMoveDetector:
    """
    Detects copy-move forgery using ORB self-matching.
    Designed for forensic explainability and speed.
    """

    def __init__(self, nfeatures: int = 5000):
        # ✅ Correct OpenCV API (Pylance-safe)
        self.orb = cv2.ORB.create(nfeatures=nfeatures)

        # Forensic thresholds
        self.min_features = 20
        self.index_gap_threshold = 50
        self.distance_threshold = 32
        self.suspicion_ratio_threshold = 0.15

    def analyze(self, gray_image: np.ndarray) -> dict:
        if gray_image is None:
            return self._result(False, 0.0, "Invalid image input")

        if len(gray_image.shape) != 2:
            return self._result(False, 0.0, "Image must be grayscale")

        keypoints, descriptors = self.orb.detectAndCompute(gray_image, None)

        if descriptors is None or len(descriptors) < self.min_features:
            return self._result(False, 0.0, "Insufficient features")

        matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = matcher.match(descriptors, descriptors)

        suspicious = [
            m for m in matches
            if abs(m.queryIdx - m.trainIdx) > self.index_gap_threshold
            and m.distance < self.distance_threshold
        ]

        ratio = len(suspicious) / max(len(matches), 1)
        detected = ratio > self.suspicion_ratio_threshold

        return self._result(
            detected,
            min(1.0, ratio),
            "High internal feature duplication"
            if detected else "Normal self-similarity"
        )

    def _result(self, detected, confidence, reason):
        return {
            "copy_move_detected": detected,
            "confidence": round(confidence, 2),
            "reason": reason
        }
