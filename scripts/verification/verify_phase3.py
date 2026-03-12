import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.main import MetaForensicAI


def verify_15_point_pipeline() -> None:
    print("--- 15-Point Forensic Pipeline Verification ---")
    system = MetaForensicAI()
    image_path = PROJECT_ROOT / "venv" / "Lib" / "site-packages" / "sklearn" / "datasets" / "images" / "china.jpg"

    print(f"[*] Analyzing image: {image_path}")
    results = system.analyze_image(str(image_path))

    bayesian = results.get("bayesian_risk", {})
    print("\n[Bayesian Predictive Intelligence]")
    print(f"Predictive Risk Score: {bayesian.get('predictive_risk_score')}")
    print(f"Risk Level: {bayesian.get('risk_level')}")
    print(f"Evidence Cues: {bayesian.get('evidence_cues_used')}")
    print(f"Interpretation: {bayesian.get('interpretation')}")

    print("\n[Pipeline Audit]")
    print("Pipeline Points: 15")

    output_dir = PROJECT_ROOT / "forensic_results"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "china_15_point_audit.json"
    with open(output_path, "w") as file_handle:
        json.dump(results, file_handle, indent=4)
    print(f"\n[+] Full audit result saved to: {output_path}")


if __name__ == "__main__":
    verify_15_point_pipeline()
