# MetaForensicAI Forensic Image Dataset

## Overview
This dataset contains curated images for training and evaluating forensic image analysis algorithms. The dataset is organized into four main categories with ground truth labels for various forensic tasks.

## Dataset Structure

### Ground Truth Categories

1. **original_camera/**
   - Original, unmodified images from various camera models
   - Organized by camera brand and model
   - Includes EXIF metadata and camera fingerprints
   - Purpose: Camera model identification and baseline analysis

2. **social_media/**
   - Images downloaded from social media platforms
   - Includes Facebook, Instagram, Twitter/X, TikTok
   - Shows platform-specific compression and processing
   - Purpose: Platform detection and re-upload analysis

3. **edited_images/**
   - Legitimately edited images
   - Created using professional (Photoshop, Lightroom) and mobile apps
   - Includes edit logs where available
   - Purpose: Distinguishing legitimate edits from manipulations

4. **manipulated/**
   - Artificially manipulated images
   - Includes splicing, cloning, and AI-generated content
   - Provides ground truth masks for manipulation localization
   - Purpose: Manipulation detection and localization training

### Validation Sets
- Blind test sets for unbiased evaluation
- Competition datasets (MICC-F220, CASIA v2, CoVERAGE)
- Real-world forensic challenges
- Controlled experiments

## Dataset Statistics

| Category | Images | Avg Size | Formats | Metadata |
|----------|--------|----------|---------|----------|
| Original Camera | 5,000 | 4032x3024 | JPEG, RAW | Full EXIF |
| Social Media | 2,800 | 1080x1080 | JPEG, WebP | Platform-specific |
| Edited Images | 3,500 | Varies | JPEG, PNG | Edit logs |
| Manipulated | 4,200 | Varies | JPEG, PNG | Ground truth masks |

## Usage Guidelines

### 1. Dataset Loading
```python
from forensic_dataset import load_forensic_dataset

dataset = load_forensic_dataset(
    base_path="datasets/",
    categories=["original_camera", "manipulated"],
    include_metadata=True
)