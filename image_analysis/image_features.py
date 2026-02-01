"""
image_features.py

Safe and error-free pixel-level image forensic analysis module.

Dependencies:
- OpenCV (cv2)
- NumPy

No SciPy required.
"""

import cv2
import numpy as np
import os


# --------------------------------------------------
# Image Loader
# --------------------------------------------------

def load_image(image_path, max_dim=2000):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("Failed to load image")

    h, w = image.shape[:2]
    scale = min(1.0, max_dim / max(h, w))

    if scale < 1.0:
        image = cv2.resize(image, (int(w * scale), int(h * scale)))

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)

    return {
        "bgr": image,
        "gray": gray,
        "hsv": hsv,
        "height": gray.shape[0],
        "width": gray.shape[1],
        "aspect_ratio": gray.shape[1] / gray.shape[0],
        "file_size": os.path.getsize(image_path)
    }


# --------------------------------------------------
# Blur Detection
# --------------------------------------------------

def detect_blur(gray):
    lap = cv2.Laplacian(gray, cv2.CV_64F)
    variance = lap.var()

    is_blurry = 1 if variance < 100 else 0

    return {
        "blur_laplacian_variance": float(variance),
        "is_blurry": is_blurry
    }


# --------------------------------------------------
# Noise Analysis
# --------------------------------------------------

def analyze_noise(gray):
    noise_std = float(np.std(gray))

    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    noise_map = gray.astype(np.float32) - blurred.astype(np.float32)

    noise_energy = float(np.mean(np.abs(noise_map)))

    return {
        "noise_std": noise_std,
        "noise_energy": noise_energy
    }


# --------------------------------------------------
# Edge Analysis
# --------------------------------------------------

def analyze_edges(gray):
    edges = cv2.Canny(gray, 100, 200)
    edge_density = np.sum(edges > 0) / edges.size

    return {
        "edge_density": float(edge_density)
    }


# --------------------------------------------------
# Brightness & Contrast
# --------------------------------------------------

def analyze_brightness(gray):
    return {
        "brightness_mean": float(np.mean(gray)),
        "contrast_std": float(np.std(gray))
    }


# --------------------------------------------------
# Color Analysis
# --------------------------------------------------

def analyze_color(hsv):
    saturation = hsv[:, :, 1]
    hue = hsv[:, :, 0]

    sat_mean = float(np.mean(saturation))
    hue_std = float(np.std(hue))

    return {
        "saturation_mean": sat_mean,
        "hue_variance": hue_std
    }


# --------------------------------------------------
# Compression Artifact Detection (Safe)
# --------------------------------------------------

def analyze_compression(gray):
    h, w = gray.shape
    block = 8

    diffs = []

    for i in range(block, h - block, block):
        diff = np.mean(np.abs(gray[i] - gray[i - 1]))
        diffs.append(diff)

    blocking_score = float(np.mean(diffs)) if diffs else 0.0

    return {
        "compression_blocking_score": blocking_score
    }


# --------------------------------------------------
# MAIN FEATURE EXTRACTION
# --------------------------------------------------

def extract_image_features(image_path):
    features = {}

    try:
        data = load_image(image_path)

        gray = data["gray"]
        hsv = data["hsv"]

        features["image_height"] = float(data["height"])
        features["image_width"] = float(data["width"])
        features["image_aspect_ratio"] = float(data["aspect_ratio"])
        features["image_file_size"] = float(data["file_size"])

        features.update(detect_blur(gray))
        features.update(analyze_noise(gray))
        features.update(analyze_edges(gray))
        features.update(analyze_brightness(gray))
        features.update(analyze_color(hsv))
        features.update(analyze_compression(gray))

        # ----------------------------
        # Image Quality Score
        # ----------------------------

        quality = 100.0

        if features["is_blurry"]:
            quality -= 30

        if features["noise_std"] > 40:
            quality -= 20

        if features["contrast_std"] < 20:
            quality -= 15

        if features["compression_blocking_score"] > 20:
            quality -= 15

        features["image_quality_score"] = float(max(0.0, quality))

        # Forgery suspicion heuristic
        forgery = 0.0
        if features["is_blurry"]:
            forgery += 20
        if features["compression_blocking_score"] > 25:
            forgery += 30
        if features["noise_std"] > 50:
            forgery += 20

        features["forgery_suspicion_score"] = float(min(100.0, forgery))

        features["_processing_success"] = True

    except Exception as e:
        features = {
            "_processing_success": False,
            "_error": str(e),
            "image_quality_score": 0.0,
            "forgery_suspicion_score": 0.0
        }

    return features


# --------------------------------------------------
# Batch Processing
# --------------------------------------------------

def batch_image_feature_extraction(image_paths):
    results = []

    for idx, path in enumerate(image_paths):
        feats = extract_image_features(path)
        feats["_image_id"] = idx
        feats["_image_path"] = path
        results.append(feats)

    return results


# --------------------------------------------------
# Test Run
# --------------------------------------------------

def example_usage():
    test_image = "test.jpg"

    if not os.path.exists(test_image):
        img = np.random.randint(0, 255, (512, 512, 3), dtype=np.uint8)
        cv2.imwrite(test_image, img)

    feats = extract_image_features(test_image)

    print("\nImage Forensic Features:")
    for k, v in feats.items():
        print(f"{k:35}: {v}")

    os.remove(test_image)


if __name__ == "__main__":
    example_usage()
