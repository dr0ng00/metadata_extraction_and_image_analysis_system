import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.main import MetaForensicAI


def analyze_ai_evidence(image_path: str) -> None:
    print("--- MetaForensicAI: AI Origin Identification ---")
    system = MetaForensicAI()
    results = system.analyze_image(image_path)

    origin = results.get("origin_detection", {})
    print("\n[!] IDENTIFICATION RESULT:")
    print(
        "    Status: "
        + (
            "SYNTHETIC (AI-GENERATED)"
            if origin.get("is_synthetic")
            else "AUTHENTIC / UNKNOWN"
        )
    )
    print(f"    Confidence: {origin.get('confidence', 0) * 100:.1f}%")
    print(f"    Detection Details: {origin.get('details')}")

    print("\n[+] Extracting Metadata (ExifTool-Style High-Fidelity Extraction)...")
    reports = system.generate_reports(formats=["txt"])
    txt_path = reports.get("txt")
    if txt_path:
        with open(txt_path, "r") as file_handle:
            print("\n--- BEGIN FORENSIC METADATA REPORT ---")
            print(file_handle.read())
            print("--- END FORENSIC METADATA REPORT ---")


if __name__ == "__main__":
    analyze_ai_evidence("ai_generated_evidence.jpg")
