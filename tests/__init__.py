"""
Test suite for MetaForensicAI.

This package contains unit tests, integration tests, and validation
tests for the forensic analysis system.
"""

import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

__all__ = []

# Test configuration
TEST_CONFIG = {
    'test_data_dir': os.path.join(os.path.dirname(__file__), 'test_data'),
    'validation_dir': os.path.join(os.path.dirname(__file__), 'test_validation'),
    'temp_dir': os.path.join(os.path.dirname(__file__), 'temp'),
    'max_test_files': 10,
    'cleanup_temp_files': True
}

def setup_test_environment():
    """Setup test environment with required directories."""
    for dir_path in TEST_CONFIG.values():
        if isinstance(dir_path, str) and dir_path.endswith('_dir'):
            os.makedirs(dir_path, exist_ok=True)
    
    print("Test environment setup complete.")

def cleanup_test_environment():
    """Clean up test files and directories."""
    import shutil
    if TEST_CONFIG['cleanup_temp_files']:
        temp_dir = TEST_CONFIG['temp_dir']
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"Cleaned up: {temp_dir}")

# Import test modules when needed
def import_all_tests():
    """Import all test modules."""
    from . import test_evidence_handler
    from . import test_metadata_analyzer
    from . import test_origin_detector
    from . import test_risk_scorer
    from . import test_integration
    
    return [
        test_evidence_handler,
        test_metadata_analyzer,
        test_origin_detector,
        test_risk_scorer,
        test_integration
    ]