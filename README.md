# MetaForensicAI

AI-assisted digital image forensics focused on metadata extraction, provenance analysis, origin classification, explainable risk scoring, and report generation.

## Overview

MetaForensicAI analyzes image evidence using a multi-stage forensic pipeline built around:

- evidence integrity checks and hashing
- EXIF/XMP/IPTC and file metadata extraction
- origin detection for camera, screenshot, social-media redistribution, and synthetic/AI-like signals
- structural analysis such as compression and artifact inspection
- contextual and timestamp consistency checks
- explainable risk scoring and report generation

The project exposes the same core engine through:

- a CLI entrypoint via [`forensicai.py`](/c:/metadata_extraction_and_image_analysis_system/forensicai.py)
- the main package in [`src`](/c:/metadata_extraction_and_image_analysis_system/src)
- a FastAPI backend in [`src/interface/forensic_api.py`](/c:/metadata_extraction_and_image_analysis_system/src/interface/forensic_api.py)

## Features

- forensic-style image intake with integrity metadata
- metadata extraction with Python fallback and ExifTool support
- origin and redistribution detection
- artifact and compression analysis
- Bayesian and rule-based risk assessment
- explainability output for analyst review
- PDF, HTML, JSON, and text report generation
- batch processing support
- API integration for uploaded evidence workflows

## Repository Layout

```text
.
|-- forensicai.py              # main CLI launcher
|-- src/                       # application package
|   |-- analysis/              # scoring, artifact, contextual, and correlation logic
|   |-- core/                  # extraction, evidence handling, origin detection
|   |-- explanation/           # explainability layer
|   |-- interface/             # CLI assistant and FastAPI backend
|   |-- reporting/             # report generation
|   `-- utils/                 # support utilities
|-- config/                    # default config and forensic rules
|-- scripts/
|   |-- analysis/              # focused helper scripts
|   |-- dataset/               # dataset prep/statistics utilities
|   |-- experiments/           # one-off generators and debugging helpers
|   `-- verification/          # manual verification scripts
|-- tests/                     # automated test suite
|   `-- manual/                # manual checks excluded from default pytest discovery
`-- results/                   # generated reports and exports
```

## Requirements

- Python 3.8+
- Windows, Linux, or macOS
- ExifTool recommended for full metadata extraction

Core Python dependencies are listed in [`requirements.txt`](/c:/metadata_extraction_and_image_analysis_system/requirements.txt).

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/dr0ng00/metadata_extraction_and_image_analysis_system.git
cd metadata_extraction_and_image_analysis_system
```

### 2. Create a virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

On PowerShell, if needed:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. ExifTool

The project can fall back to Python-based extraction, but ExifTool is preferred for higher-fidelity metadata access.

- On Windows, the project may attempt to prepare ExifTool automatically when native extraction is first needed.
- If ExifTool is already available in `PATH`, it will be used directly.

## Quick Start

Analyze a single image:

```bash
python forensicai.py --image path/to/evidence.jpg --report all
```

Analyze a directory:

```bash
python forensicai.py --batch path/to/folder --report json
```

Compare multiple images:

```bash
python forensicai.py --compare image1.jpg image2.jpg --compare-type metadata
```

Interactive assistant:

```bash
python forensicai.py --image path/to/evidence.jpg --interactive
```

Explain mode:

```bash
python forensicai.py --image path/to/evidence.jpg --ai-mode explain --report html
```

## CLI Notes

The main CLI supports:

- single-image analysis with `--image`
- batch analysis with `--batch`
- comparison mode with `--compare`
- multiple report formats via `--report`
- explainability and analyst-assist modes via `--ai-mode`

The main implementation lives in [`src/main.py`](/c:/metadata_extraction_and_image_analysis_system/src/main.py).

## API Usage

Run the API server module directly:

```bash
python -m src.interface.forensic_api
```

Default behavior:

- listens on `0.0.0.0:8000`
- exposes `/`, `/analyze`, `/cases/{case_id}`, and `/health`

Example health check:

```bash
curl http://127.0.0.1:8000/health
```

## Verification and Support Scripts

Manual verification scripts are grouped by purpose:

- [`scripts/verification`](/c:/metadata_extraction_and_image_analysis_system/scripts/verification)
- [`scripts/experiments`](/c:/metadata_extraction_and_image_analysis_system/scripts/experiments)
- [`scripts/analysis`](/c:/metadata_extraction_and_image_analysis_system/scripts/analysis)
- [`scripts/dataset`](/c:/metadata_extraction_and_image_analysis_system/scripts/dataset)

Examples:

```bash
python scripts/verification/verify_api.py
python scripts/verification/verify_phase3.py
python scripts/experiments/create_gps_test_image.py
```

## Testing

Run the default automated test suite:

```bash
pytest
```

Manual checks under [`tests/manual`](/c:/metadata_extraction_and_image_analysis_system/tests/manual) are intentionally excluded from default test discovery.

## Output

Generated artifacts typically land under [`results`](/c:/metadata_extraction_and_image_analysis_system/results) and related report folders, depending on the CLI options used.

Common output formats:

- JSON
- HTML
- PDF
- TXT

## Configuration

Primary configuration files:

- [`config/default_config.yaml`](/c:/metadata_extraction_and_image_analysis_system/config/default_config.yaml)
- [`config/forensic_rules.json`](/c:/metadata_extraction_and_image_analysis_system/config/forensic_rules.json)

You can pass a custom config file to the CLI with:

```bash
python forensicai.py --config path/to/config.yaml --image path/to/evidence.jpg
```

## Development Notes

- package metadata is defined in [`pyproject.toml`](/c:/metadata_extraction_and_image_analysis_system/pyproject.toml)
- the project currently contains some in-progress source changes outside this README
- the top-level launcher remains [`forensicai.py`](/c:/metadata_extraction_and_image_analysis_system/forensicai.py)

## License

This repository includes an MIT [`LICENSE`](/c:/metadata_extraction_and_image_analysis_system/LICENSE) file.
