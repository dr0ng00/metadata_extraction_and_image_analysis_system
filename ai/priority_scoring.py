class PriorityScorer:

    WEIGHTS = {
        "copy_move_detected": 30,
        "prnu_inconsistency_detected": 25,
        "lighting_inconsistency_detected": 20,
        "social_media_reupload_detected": 15,
        "timeline_anomalies": 10
    }

    def calculate(self, analysis_results):
        score = 0
        reasons = []

        for key, weight in self.WEIGHTS.items():
            if analysis_results.get(key):
                score += weight
                reasons.append(key)

        level = (
            "CRITICAL" if score >= 70 else
            "HIGH" if score >= 40 else
            "MEDIUM" if score >= 20 else
            "LOW"
        )

        return {
            "priority_score": score,
            "priority_level": level,
            "triggered_factors": reasons
        }
