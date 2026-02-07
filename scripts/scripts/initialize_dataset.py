#!/usr/bin/env python3
"""
Initialize the MetaForensicAI dataset structure
"""

import os
import sys
import yaml
from pathlib import Path
import shutil

class DatasetInitializer:
    def __init__(self, base_path="datasets"):
        self.base_path = Path(base_path)
        self.config = self.load_config()
        
    def load_config(self):
        """Load dataset configuration"""
        config_path = self.base_path / "dataset_config.yaml"
        if config_path.exists():
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self.get_default_config()
    
    def get_default_config(self):
        """Return default configuration"""
        return {
            'dataset': {
                'name': 'MetaForensicAI Forensic Dataset',
                'version': '1.0.0'
            }
        }
    
    def create_structure(self):
        """Create complete dataset directory structure"""
        print("Creating dataset structure...")
        
        # Create main directories
        directories = [
            self.base_path,
            self.base_path / "ground_truth",
            self.base_path / "ground_truth" / "original_camera",
            self.base_path / "ground_truth" / "social_media",
            self.base_path / "ground_truth" / "edited_images",
            self.base_path / "ground_truth" / "manipulated",
            self.base_path / "validation_sets",
            
            # Camera subdirectories
            self.base_path / "ground_truth" / "original_camera" / "canon",
            self.base_path / "ground_truth" / "original_camera" / "nikon",
            self.base_path / "ground_truth" / "original_camera" / "sony",
            self.base_path / "ground_truth" / "original_camera" / "iphone",
            
            # Social media subdirectories
            self.base_path / "ground_truth" / "social_media" / "facebook",
            self.base_path / "ground_truth" / "social_media" / "instagram",
            self.base_path / "ground_truth" / "social_media" / "twitter",
            self.base_path / "ground_truth" / "social_media" / "tiktok",
            
            # Edited images subdirectories
            self.base_path / "ground_truth" / "edited_images" / "photoshop",
            self.base_path / "ground_truth" / "edited_images" / "lightroom",
            self.base_path / "ground_truth" / "edited_images" / "mobile_apps",
            
            # Manipulated subdirectories
            self.base_path / "ground_truth" / "manipulated" / "splicing",
            self.base_path / "ground_truth" / "manipulated" / "cloning",
            self.base_path / "ground_truth" / "manipulated" / "generative",
            self.base_path / "ground_truth" / "manipulated" / "ground_truth_masks",
            
            # Validation sets
            self.base_path / "validation_sets" / "blind_test_set_a",
            self.base_path / "validation_sets" / "blind_test_set_b",
            self.base_path / "validation_sets" / "competition_sets",
            self.base_path / "validation_sets" / "forensic_challenges",
            self.base_path / "validation_sets" / "real_world_cases",
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"  Created: {directory}")
        
        # Create placeholder README files
        self.create_readme_files()
        
        # Save configuration
        self.save_config()
        
        print(f"\nDataset structure created at: {self.base_path}")
        
    def create_readme_files(self):
        """Create README files for each directory"""
        readme_content = """# {directory_name}

## Description
{description}

## Contents
- Images: {count}
- Format: JPEG/PNG
- Metadata: Included
- Ground Truth: Provided

## Usage
This dataset is part of MetaForensicAI for {purpose}.

## Citation
If you use this dataset, please cite:
MetaForensicAI Dataset v1.0
"""

        directories_info = [
            {
                'path': self.base_path / "ground_truth" / "original_camera",
                'name': "Original Camera Images",
                'desc': "Original, unmodified images from various camera models",
                'purpose': "camera model fingerprinting and baseline analysis"
            },
            {
                'path': self.base_path / "ground_truth" / "social_media",
                'name': "Social Media Images",
                'desc': "Images downloaded from social media platforms",
                'purpose': "platform compression and re-upload detection"
            },
            {
                'path': self.base_path / "ground_truth" / "edited_images",
                'name': "Legitimately Edited Images",
                'desc': "Images with legitimate edits (color correction, cropping, etc.)",
                'purpose': "distinguishing between legitimate and malicious edits"
            },
            {
                'path': self.base_path / "ground_truth" / "manipulated",
                'name': "Manipulated Images",
                'desc': "Images with malicious manipulations (splicing, cloning, etc.)",
                'purpose': "manipulation detection training and testing"
            },
            {
                'path': self.base_path / "validation_sets",
                'name': "Validation Sets",
                'desc': "Blind test sets for model validation",
                'purpose': "unbiased model evaluation and benchmarking"
            }
        ]
        
        for info in directories_info:
            readme_path = info['path'] / "README.md"
            content = readme_content.format(
                directory_name=info['name'],
                description=info['desc'],
                count="Variable",
                purpose=info['purpose']
            )
            readme_path.write_text(content)
            print(f"  Created README: {readme_path}")
    
    def save_config(self):
        """Save configuration to YAML file"""
        config_path = self.base_path / "dataset_config.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        print(f"  Saved configuration: {config_path}")

if __name__ == "__main__":
    initializer = DatasetInitializer()
    initializer.create_structure()