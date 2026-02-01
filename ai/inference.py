"""
inference.py

Central AI inference engine.

Responsibilities:
1. Understand user intent
2. Call ONLY required forensic modules
3. Aggregate results
4. Return DIRECT, REQUESTED output
5. NO storage, NO logging to disk
"""

import cv2

# Import forensic AI modules
from ai.copy_move_detection import CopyMoveDetector
from ai.prnu_analysis import PRNUAnalyzer
from ai.exif_timeline import ExIFTimelineAnalyzer
from ai.lighting_consistency import LightingAnalyzer
from ai.priority_scoring import PriorityScorer
from ai.explainability import ExplainableAI


class ForensicInferenceEngine:
    """
    Stateless AI inference engine for image forensics
    """

    def __init__(self):
        self.copy_move = CopyMoveDetector()
        self.prnu = PRNUAnalyzer()
        self.timeline = ExIFTimelineAnalyzer()
        self.lighting = LightingAnalyzer()
        self.priority = PriorityScorer()
        self.explainer = ExplainableAI()

    # --------------------------------------------------
    # Core Inference Entry Point (UPDATED SIGNATURE)
    # --------------------------------------------------

    def run(
        self,
        image,                 # ✅ NumPy image array (NOT path)
        metadata: dict,
        user_request: str
    ) -> dict:
        """
        Run AI inference based on user intent.

        Args:
            image: OpenCV image (numpy array)
            metadata: Extracted EXIF metadata
            user_request: User question / intent

        Returns:
            dict: AI response (ONLY requested info)
        """

        # Normalize user request
        request = user_request.lower()

        # Validate image
        if image is None:
            return {"error": "Invalid image input"}

        # Convert to grayscale once
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        results = {}

        # --------------------------------------------------
        # INTENT ROUTING (STRICT & CLEAN)
        # --------------------------------------------------

        # 1️⃣ Location only
        if self._asks_location(request):
            return self._location_response(metadata)

        # 2️⃣ Humans / Animals (stub for now)
        if self._asks_humans_animals(request):
            return self._object_detection_stub()

        # 3️⃣ EXIF timeline
        if self._asks_timeline(request):
            return self.timeline.analyze(metadata)

        # 4️⃣ Editing / manipulation checks
        if self._asks_editing(request):
            results.update(self.copy_move.analyze(gray))
            results.update(self.prnu.analyze(gray))
            results.update(self.lighting.analyze(gray))

        # 5️⃣ Authenticity check (broader)
        if self._asks_authenticity(request):
            results.update(self.copy_move.analyze(gray))
            results.update(self.prnu.analyze(gray))
            results.update(self.lighting.analyze(gray))
            results.update(self.timeline.analyze(metadata))

        # --------------------------------------------------
        # FINAL AI DECISION (ONLY IF ASKED)
        # --------------------------------------------------

        if self._asks_final_verdict(request):
            verdict = self.priority.calculate(results)
            explanation = self.explainer.generate_explanation(results)

            return {
                "verdict": verdict,
                "explanation": explanation
            }

        # --------------------------------------------------
        # Default: return analysis + explanation
        # --------------------------------------------------

        explanation = self.explainer.generate_explanation(results)

        return {
            "analysis_results": results,
            "explanation": explanation
        }

    # --------------------------------------------------
    # Intent Detection Helpers
    # --------------------------------------------------

    def _asks_location(self, text):
        return any(k in text for k in ["location", "where", "gps", "place"])

    def _asks_editing(self, text):
        return any(k in text for k in ["edited", "manipulated", "tampered", "fake"])

    def _asks_authenticity(self, text):
        return any(k in text for k in ["authentic", "real", "original"])

    def _asks_timeline(self, text):
        return any(k in text for k in ["timeline", "time", "history", "when"])

    def _asks_final_verdict(self, text):
        return any(k in text for k in ["final", "verdict", "conclusion", "summary"])

    def _asks_humans_animals(self, text):
        return any(k in text for k in [
            "human", "person", "people",
            "animal", "dog", "cat", "cow", "bird"
        ])

    # --------------------------------------------------
    # Response Builders
    # --------------------------------------------------

    def _location_response(self, metadata):
        gps = metadata.get("GPSInfo", {})
        if not gps:
            return {"location": "No GPS data found"}

        return {
            "latitude": gps.get("Latitude"),
            "longitude": gps.get("Longitude"),
            "altitude": gps.get("Altitude")
        }

    def _object_detection_stub(self):
        """
        Placeholder for YOLO / DL model
        (Will be replaced with real detection)
        """
        return {
            "humans_detected": "AI model not enabled yet",
            "animals_detected": "AI model not enabled yet"
        }
