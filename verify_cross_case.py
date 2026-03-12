import json
import os
import shutil
from src.core.batch_processor import ForensicBatchProcessor

def verify_cross_case_intelligence():
    print("--- 16-Point Cross-Case Intelligence Verification ---")
    
    # Clean state
    if os.path.exists("forensic_intelligence.db"):
        os.remove("forensic_intelligence.db")
    
    processor = ForensicBatchProcessor(max_workers=2)
    
    # Evidence Paths
    path_a = r"c:\metadata_extraction_and_image_analysis_system\venv\Lib\site-packages\sklearn\datasets\images\china.jpg"
    path_b = r"c:\metadata_extraction_and_image_analysis_system\venv\Lib\site-packages\sklearn\datasets\images\flower.jpg"
    
    # 1. Process Case A
    print(f"[*] Processing Case A: {os.path.basename(path_a)}")
    results_a = processor.process_batch([path_a], case_info={"case_id": "CASE_ALPHA"})[0]
    
    # 2. Process Case B
    print(f"[*] Processing Case B: {os.path.basename(path_b)}")
    results_b = processor.process_batch([path_b], case_info={"case_id": "CASE_BETA"})[0]
    
    # 3. Verify Links in Case B
    cross_links = results_b.get('cross_case_analysis', {})
    print("\n[Cross-Case Evidence Summary]")
    print(f"Has Cross Links: {cross_links.get('has_cross_links')}")
    print(f"Summary: {cross_links.get('summary')}")
    
    if cross_links.get('has_cross_links'):
        for link in cross_links.get('evidentiary_links', []):
            print(f"  -> Link to {link['linked_case']} ({link['relationship']})")
    else:
        print("[-] Error: No links found (expected correlation between generic images).")

    # 4. Verify Bayesian Risk in Case B
    bayesian = results_b.get('bayesian_risk', {})
    print(f"\n[Bayesian Risk]: {bayesian.get('predictive_risk_score')} ({bayesian.get('risk_level')})")

    # Output full result for audit
    output_path = "forensic_results/phase3_enterprise_audit.json"
    os.makedirs("forensic_results", exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results_b, f, indent=4)
    print(f"\n[+] Final Phase 3 audit result saved to: {output_path}")

if __name__ == "__main__":
    verify_cross_case_intelligence()
