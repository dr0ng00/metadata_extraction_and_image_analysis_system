import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.main import MetaForensicAI


def verify_14_point_pipeline() -> None:
    print("--- 14-Point Forensic Pipeline Verification ---")
    system = MetaForensicAI()
    image_path = PROJECT_ROOT / "venv" / "Lib" / "site-packages" / "sklearn" / "datasets" / "images" / "china.jpg"

    print(f"[*] Analyzing image: {image_path}")
    results = system.analyze_image(str(image_path))

    artifact_analysis = results.get("artifact_analysis", {})
    print("\n[Artifact Analysis Findings]")
    print(f"ELA Intensity: {artifact_analysis.get('ela_results', {}).get('ela_intensity')}")
    print(
        "Q-Table Signature: "
        f"{artifact_analysis.get('qtable_audit', {}).get('signature_match')}"
    )
    print(f"Advanced Flags: {artifact_analysis.get('advanced_flags', [])}")

    explanations = results.get("explanations", [])
    print("\n[Forensic Narratives Generated]")
    advanced_narratives = [
        item
        for item in explanations
        if "Analysis (ELA)" in item["title"] or "Quantization" in item["title"]
    ]

    if advanced_narratives:
        for explanation in advanced_narratives:
            print(f"Title: {explanation['title']}")
            print(f"Observation: {explanation['observation']}")
            print("-" * 20)
    else:
        print("[-] No advanced narratives generated. (Expected if criteria not met)")

    output_dir = PROJECT_ROOT / "forensic_results"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "china_14_point_audit.json"
    with open(output_path, "w") as file_handle:
        json.dump(results, file_handle, indent=4)
    print(f"\n[+] Full audit result saved to: {output_path}")


if __name__ == "__main__":
    verify_14_point_pipeline()
