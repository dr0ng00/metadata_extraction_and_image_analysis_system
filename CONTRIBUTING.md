# Contributing to MetaForensicAI

Thank you for your interest in contributing to MetaForensicAI! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- ExifTool (for full functionality)

### Development Setup
```bash
# 1. Fork and clone the repository
git clone https://github.com/dr0ng00/metadata_extraction_and_image_analysis_system.git
cd MetaForensicAI

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install development dependencies
pip install -e ".[dev]"

# 4. Install pre-commit hooks
pre-commit install