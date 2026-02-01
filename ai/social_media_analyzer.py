class SocialMediaAnalyzer:

    PLATFORMS = {
        "instagram": {"quality": (80, 88), "max_size": 1080},
        "facebook": {"quality": (78, 85), "max_size": 2048},
        "twitter": {"quality": (75, 82), "max_size": 1200},
        "whatsapp": {"quality": (70, 80), "max_size": 1600}
    }

    def detect(self, image_features):
        quality = image_features.get("estimated_quality", 100)
        width = image_features.get("image_width", 0)
        height = image_features.get("image_height", 0)

        candidates = []

        for platform, rules in self.PLATFORMS.items():
            if rules["quality"][0] <= quality <= rules["quality"][1]:
                if max(width, height) <= rules["max_size"]:
                    candidates.append(platform)

        return {
            "suspected_platforms": candidates or ["Unknown"],
            "possible_reupload": len(candidates) > 1
        }
