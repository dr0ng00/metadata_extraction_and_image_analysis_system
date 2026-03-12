#!/usr/bin/env python3
"""
MetaForensicAI - Execution Wrapper
Primary launcher for running the CLI as:
    python forensicai.py
"""

import sys
from pathlib import Path

# Ensure root directory is in python path
root_dir = str(Path(__file__).parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from src.main import main
except ImportError:
    # Importing src.main requires package context for relative imports.
    raise


if __name__ == "__main__":
    main()
