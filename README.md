# MetaForensicAI 🕵️‍♂️
**Comprehensive AI-Assisted Digital Image Forensics System**

MetaForensicAI is a state-of-the-art forensic tool designed for deep analysis of digital images. It combines traditional metadata investigation with AI-assisted origin detection and explainable risk scoring to provide a holistic view of image authenticity.

## 🛡 13-Point Forensic Pipeline
The system implements a professional 13-point analysis workflow:

1.  **Evidence Input**: Read-only intake with cryptographic verification.
2.  **Metadata Extraction**: Deep audit of EXIF, XMP, IPTC, and MakerNotes.
3.  **Structured JSON**: Normalization of diverse metadata formats.
4.  **Feature Generation**: Conversion of raw data into forensic feature vectors.
5.  **ML Classification**: Predictive origin detection (Camera vs. AI vs. Platform).
6.  **Rule Application**: Hard-logic consistency checks for hardware/firmware.
7.  **Anomaly Detection**: Statistical deviation analysis of compression/noise.
8.  **Supporting Systems**: Specialized domain modules (Canon, Nikon, RAW, GPS).
9.  **Evidence Correlation**: Unified interpretation of multi-source findings.
10. **Confidence Scoring**: Weighted risk assessment (XAI-integrated).
11. **Interactive Assistant**: Natural language forensic querying.
12. **NLP Responses**: Context-aware evidentiary justifications.
13. **Professional Reporting**: PDF/JSON/HTML multi-format evidence output.

## 🚀 Getting Started

### Installation
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/MetaForensicAI.git
    cd MetaForensicAI
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Usage
Analyze an image and generate a professional forensic report:
```bash
python forensicai.py --image path/to/evidence.jpg --report pdf --output ./reports
```

Interact with the Forensic CLI Assistant:
```bash
python forensicai.py --interactive
```

## 📂 Project Architecture
- `src/core`: Extraction and authenticity logic.
- `src/analysis`: Specialized engines for risk, context, and origin.
- `src/explanation`: XAI engine for human-readable justifications.
- `src/reporting`: Professional PDF and JSON report generation.
- `src/interface`: NLP-powered CLI assistant.

## 📄 License
Forensic-grade implementation. All rights reserved.

---

# MetaForensic AI Chat Assistant

MetaForensic AI provides an interactive forensic analysis interface that allows investigators to query metadata, inspect evidence signals, and evaluate image origin using structured forensic reasoning.

---

## Table of Contents

* Chat Commands
* Direct Metadata Queries
* Forensic Question Examples
* Response Format
* Forensic Guardrails
* Clarification Flow
* Confidence Interpretation
* Recommended Investigation Workflow

---

## Chat Commands

### Core Commands

`help`
Display quick forensic query examples.

`help-all`
Open the full generated forensic query library containing **200,000+ investigation examples**.

`tags`
List all available metadata tags detected in the image.

`software`
Show detected editing software indicators.

`origin`
Display image origin classification with supporting forensic evidence.

`timestamps`
Show all timestamp-related metadata fields.

`ai-check`
Analyze potential AI or synthetic image indicators.

`compression`
Show recompression signals and compression artifacts.

---

## Direct Metadata Queries

Investigators can request specific metadata fields directly.

Examples:

`show DateTimeOriginal`
`show Software`
`show GPSLatitude`
`show Model`
`show ImageWidth`
`show ImageHeight`

If a tag does not exist, MetaForensic AI returns:

Not available

---

## Forensic Question Examples

Investigators can ask natural language questions such as:

Was this image edited after capture
Is there evidence of WhatsApp or Instagram recompression
Do the timestamps appear internally consistent
Is this image AI generated or synthetic artwork
Show all camera-related metadata fields
Compare DateTimeOriginal vs FileModifyDate

---

## Response Format

MetaForensic AI responses follow a structured forensic reporting format.

Answer
Reasoning
Evidence Used
Confidence

This ensures results remain **transparent, traceable, and investigation-ready**.

---

## Forensic Guardrails

MetaForensic AI follows strict forensic analysis principles.

No evidence fabrication
Absence of AI indicators does not imply camera origin
Missing metadata defaults to **Unknown Origin** unless strong non-metadata evidence exists

---

## Clarification Flow

If a question can belong to multiple forensic domains, MetaForensic AI asks the investigator to clarify.

Example:

Your question could match multiple forensic domains.

1. Structural or recompression analysis
2. Synthetic or AI detection

Please select the appropriate option.

---

## Confidence Interpretation

Confidence scores indicate the strength of supporting forensic signals.

High — Strong evidence from multiple signals
Moderate — Partial evidence available
Low — Limited or inconclusive signals

---

## Recommended Investigation Workflow

1. Run `tags` to view all metadata fields.
2. Check `timestamps` and `origin` for initial triage.
3. Inspect `software` and `compression` for editing indicators.
4. Run `ai-check` to evaluate synthetic signals.
5. Perform targeted tag queries such as:

show DateTimeOriginal
show Software
compare DateTimeOriginal vs FileModifyDate

### Prompt Reference

For a full strict court-style assistant policy, see:
`METAFORENSIC_AI_SYSTEM_PROMPT.md`
