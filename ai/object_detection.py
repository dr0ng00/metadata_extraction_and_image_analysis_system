import cv2
from typing import Dict, Any

# Pylance-safe import (runtime correct)
from ultralytics import YOLO  # type: ignore


class ObjectDetector:
    """
    Human & Animal detection using YOLOv8.
    """

    def __init__(self, model_path: str = "yolov8n.pt"):
        self.model = YOLO(model_path)

        self.allowed_classes = {
            "person": "human",
            "dog": "animal",
            "cat": "animal",
            "horse": "animal",
            "cow": "animal",
            "bird": "animal"
        }

    def detect(self, image) -> Dict[str, Any]:
        if image is None:
            return {
                "humans_detected": 0,
                "animals_detected": {},
                "total_animals": 0,
                "error": "Invalid image input"
            }

        results = self.model(image, verbose=False)[0]

        humans = 0
        animals: Dict[str, int] = {}

        for box in results.boxes:
            cls_name = results.names[int(box.cls)]

            if cls_name not in self.allowed_classes:
                continue

            category = self.allowed_classes[cls_name]

            if category == "human":
                humans += 1
            else:
                animals[cls_name] = animals.get(cls_name, 0) + 1

        return {
            "humans_detected": humans,
            "animals_detected": animals,
            "total_animals": sum(animals.values())
        }
