def create_ai_sample(input_path, output_path):
    print(f"[*] Simulating AI-generated image: {output_path}")
    with open(input_path, 'rb') as f:
        content = f.read()
    
    # Inject C2PA/JUMB signature + GPT-4o agent name
    # We append it to the end or insert it into a comment segment
    # For our simple detector, having it in the first 500KB is enough
    signature = b'\x00\x00\x00\x1cc2pa\x00\x00\x00\x00JUMBF\x00\x00Actions Software Agent Name: GPT-4o'
    
    # We'll just prepend it to a copy for this simulation 
    # (A real file would have it in a JUMB box, but our detector scans the binary)
    with open(output_path, 'wb') as f:
        f.write(signature)
        f.write(content)
    
    print("[+] Synthetic AI image created with C2PA signature.")

if __name__ == "__main__":
    create_ai_sample("ai_generated_sample.jpg", "ai_generated_evidence.jpg")
