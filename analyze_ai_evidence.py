from src.main import MetaForensicAI
import sys

def analyze_ai_evidence(image_path):
    print(f"--- MetaForensicAI: AI Origin Identification ---")
    system = MetaForensicAI()
    
    # Run 16-point analysis
    results = system.analyze_image(image_path)
    
    # Get Origin Result
    origin = results.get('origin_detection', {})
    print(f"\n[!] IDENTIFICATION RESULT:")
    print(f"    Status: {'SYNTHETIC (AI-GENERATED)' if origin.get('is_synthetic') else 'AUTHENTIC / UNKNOWN'}")
    print(f"    Confidence: {origin.get('confidence', 0)*100:.1f}%")
    print(f"    Detection Details: {origin.get('details')}")
    
    # Generate ExifTool-style report
    print(f"\n[+] Extracting Metadata (ExifTool-Style High-Fidelity Extraction)...")
    reports = system.generate_reports(formats=['txt'])
    
    txt_path = reports.get('txt')
    if txt_path:
        with open(txt_path, 'r') as f:
            print("\n--- BEGIN FORENSIC METADATA REPORT ---")
            print(f.read())
            print("--- END FORENSIC METADATA REPORT ---")

if __name__ == "__main__":
    analyze_ai_evidence("ai_generated_evidence.jpg")
