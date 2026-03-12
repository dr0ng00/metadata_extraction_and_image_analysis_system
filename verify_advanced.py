import json
import os
from src.main import MetaForensicAI

def verify_14_point_pipeline():
    print("--- 14-Point Forensic Pipeline Verification ---")
    
    # Initialize system
    system = MetaForensicAI()
    
    image_path = r"c:\metadata_extraction_and_image_analysis_system\venv\Lib\site-packages\sklearn\datasets\images\china.jpg"
    
    # Run analysis
    print(f"[*] Analyzing image: {image_path}")
    results = system.analyze_image(image_path)
    
    # 1. Verify Artifact Analysis results
    artifact_analysis = results.get('artifact_analysis', {})
    print("\n[Artifact Analysis Findings]")
    print(f"ELA Intensity: {artifact_analysis.get('ela_results', {}).get('ela_intensity')}")
    print(f"Q-Table Signature: {artifact_analysis.get('qtable_audit', {}).get('signature_match')}")
    print(f"Advanced Flags: {artifact_analysis.get('advanced_flags', [])}")
    
    # 2. Verify Explanations
    explanations = results.get('explanations', [])
    print("\n[Forensic Narratives Generated]")
    advanced_narratives = [e for e in explanations if 'Analysis (ELA)' in e['title'] or 'Quantization' in e['title']]
    
    if advanced_narratives:
        for exp in advanced_narratives:
            print(f"Title: {exp['title']}")
            print(f"Observation: {exp['observation']}")
            print("-" * 20)
    else:
        print("[-] No advanced narratives generated. (Expected if criteria not met)")

    # Output full result for audit
    output_path = "forensic_results/china_14_point_audit.json"
    os.makedirs("forensic_results", exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Full audit result saved to: {output_path}")

if __name__ == "__main__":
    verify_14_point_pipeline()
