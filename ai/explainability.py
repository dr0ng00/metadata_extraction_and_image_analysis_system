class ExplainableAI:

    def generate_explanation(self, results):
        explanations = []

        for key, value in results.items():
            if isinstance(value, dict) and value.get("confidence", 0) > 0.5:
                explanations.append(
                    f"{key}: {value.get('reason')} (confidence {value['confidence']})"
                )

        return {
            "explanations": explanations,
            "explainability_level": "HIGH" if explanations else "LOW"
        }
