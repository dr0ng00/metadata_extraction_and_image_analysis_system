import time
import multiprocessing
import os
import importlib
from importlib.util import find_spec
from src.interface.forensic_api import app

def run_server():
    uvicorn = find_spec("uvicorn")
    if uvicorn is None:
        print("[-] Missing dependency: uvicorn")
        print("    Install with: pip install uvicorn")
        return
    uvicorn_mod = importlib.import_module("uvicorn")
    uvicorn_mod.run(app, host="127.0.0.1", port=8001, log_level="info")

def test_api():
    print("--- FastAPI Enterprise Backend Verification ---")
    requests_spec = find_spec("requests")
    if requests_spec is None:
        print("[-] Missing dependency: requests")
        print("    Install with: pip install requests")
        return
    requests_mod = importlib.import_module("requests")
    
    # Start server in a separate process
    server_process = multiprocessing.Process(target=run_server)
    server_process.start()
    
    # Give it a few seconds to start
    time.sleep(5)
    
    try:
        # 1. Test Root
        print("[*] Testing Root Endpoint...")
        response = requests_mod.get("http://127.0.0.1:8001/")
        print(f"Status: {response.status_code}")
        print(f"Content: {json.dumps(response.json(), indent=2)}")
        
        # 2. Test Health
        print("\n[*] Testing Health Endpoint...")
        response = requests_mod.get("http://127.0.0.1:8001/health")
        print(f"Status: {response.status_code}")
        print(f"System Version: {response.json().get('system', {}).get('package_version')}")
        
        if response.status_code == 200:
            print("\n[+] API Service is OPERATIONAL")
        else:
            print("\n[-] API Service Error")
            
    except Exception as e:
        print(f"\n[-] API Test Failed: {str(e)}")
    finally:
        # Shutdown server
        print("\n[*] Shutting down server...")
        server_process.terminate()
        server_process.join()

if __name__ == "__main__":
    import json
    test_api()
