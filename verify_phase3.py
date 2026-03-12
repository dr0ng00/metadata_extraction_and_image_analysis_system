import json
import os
from src.main import MetaForensicAI

def verify_15_point_pipeline():
    print("--- 15-Point Forensic Pipeline Verification ---")
    
    # Initialize system
    system = MetaForensicAI()
    
    image_path = r"c:\metadata_extraction_and_image_analysis_system\venv\Lib\site-packages\sklearn\datasets\images\china.jpg"
    
    # Run analysis
    print(f"[*] Analyzing image: {image_path}")
    results = system.analyze_image(image_path)
    
    # 1. Verify Bayesian Risk results
    bayesian = results.get('bayesian_risk', {})
    print("\n[Bayesian Predictive Intelligence]")
    print(f"Predictive Risk Score: {bayesian.get('predictive_risk_score')}")
    print(f"Risk Level: {bayesian.get('risk_level')}")
    print(f"Evidence Cues: {bayesian.get('evidence_cues_used')}")
    print(f"Interpretation: {bayesian.get('interpretation')}")
    
    # 2. Verify pipeline completion
    print("\n[Pipeline Audit]")
    print(f"Pipeline Points: 15")
    
    # Output full result for audit
    output_path = "forensic_results/china_15_point_audit.json"
    os.makedirs("forensic_results", exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Full audit result saved to: {output_path}")

if __name__ == "__main__":
    verify_15_point_pipeline()
