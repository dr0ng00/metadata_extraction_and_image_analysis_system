#!/usr/bin/env python3
"""
Split dataset into train/validation/test sets
"""

import os
import random
import shutil
import json
from pathlib import Path
from sklearn.model_selection import train_test_split
import pandas as pd
import yaml

class DatasetSplitter:
    def __init__(self, dataset_path="datasets", output_path="split_datasets"):
        self.dataset_path = Path(dataset_path)
        self.output_path = Path(output_path)
        self.config = self.load_config()
        
    def load_config(self):
        """Load split configuration"""
        config_file = self.dataset_path / "dataset_config.yaml"
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('distribution', {
                    'split': {'train': 70, 'val': 15, 'test': 15},
                    'seed': 42,
                    'shuffle': True
                })
        return {'split': {'train': 70, 'val': 15, 'test': 15}, 'seed': 42, 'shuffle': True}
    
    def create_split(self, categories=None):
        """Create train/val/test split"""
        if categories is None:
            categories = ["original_camera", "social_media", "edited_images", "manipulated"]
        
        # Create output directory
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        split_info = {}
        
        for category in categories:
            category_path = self.dataset_path / "ground_truth" / category
            if not category_path.exists():
                print(f"Warning: {category_path} does not exist")
                continue
            
            print(f"\nProcessing category: {category}")
            
            # Collect all images
            image_files = self.collect_images(category_path)
            print(f"  Found {len(image_files)} images")
            
            if not image_files:
                continue
            
            # Create splits
            train_ratio = self.config['split']['train'] / 100.0
            val_ratio = self.config['split']['val'] / 100.0
            test_ratio = self.config['split']['test'] / 100.0
            
            # First split: train vs (val+test)
            train_files, temp_files = train_test_split(
                image_files,
                test_size=(val_ratio + test_ratio),
                random_state=self.config['seed'],
                shuffle=self.config['shuffle']
            )
            
            # Second split: val vs test
            val_test_ratio = val_ratio / (val_ratio + test_ratio)
            val_files, test_files = train_test_split(
                temp_files,
                test_size=(1 - val_test_ratio),
                random_state=self.config['seed'],
                shuffle=self.config['shuffle']
            )
            
            split_info[category] = {
                'train': len(train_files),
                'val': len(val_files),
                'test': len(test_files),
                'total': len(image_files)
            }
            
            # Copy files to split directories
            self.copy_split_files(category, 'train', train_files)
            self.copy_split_files(category, 'val', val_files)
            self.copy_split_files(category, 'test', test_files)
        
        # Save split information
        self.save_split_info(split_info)
        
        return split_info
    
    def collect_images(self, directory):
        """Collect all image files from directory"""
        image_extensions = {'.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.webp'}
        image_files = []
        
        for ext in image_extensions:
            image_files.extend(directory.rglob(f"*{ext}"))
            image_files.extend(directory.rglob(f"*{ext.upper()}"))
        
        # Convert to strings for sklearn compatibility
        return [str(f) for f in image_files]
    
    def copy_split_files(self, category, split_name, file_list):
        """Copy files to split directory"""
        split_dir = self.output_path / split_name / category
        split_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"  Copying {len(file_list)} files to {split_name}")
        
        for src_path in file_list:
            src_path = Path(src_path)
            # Preserve subdirectory structure
            rel_path = src_path.relative_to(self.dataset_path / "ground_truth" / category)
            dst_path = split_dir / rel_path
            
            # Create parent directories if needed
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file
            shutil.copy2(src_path, dst_path)
    
    def save_split_info(self, split_info):
        """Save split information to JSON"""
        info_file = self.output_path / "split_information.json"
        
        summary = {
            'total_images': 0,
            'train': 0,
            'val': 0,
            'test': 0,
            'categories': split_info,
            'config': self.config
        }
        
        for category_info in split_info.values():
            summary['total_images'] += category_info['total']
            summary['train'] += category_info['train']
            summary['val'] += category_info['val']
            summary['test'] += category_info['test']
        
        with open(info_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\nSplit information saved to: {info_file}")
        
        # Also create CSV summary
        self.create_csv_summary(summary)
    
    def create_csv_summary(self, summary):
        """Create CSV summary of splits"""
        rows = []
        for category, info in summary['categories'].items():
            rows.append({
                'category': category,
                'total': info['total'],
                'train': info['train'],
                'val': info['val'],
                'test': info['test'],
                'train_pct': info['train'] / info['total'] * 100,
                'val_pct': info['val'] / info['total'] * 100,
                'test_pct': info['test'] / info['total'] * 100
            })
        
        df = pd.DataFrame(rows)
        csv_file = self.output_path / "split_summary.csv"
        df.to_csv(csv_file, index=False)
        
        print(f"CSV summary saved to: {csv_file}")
        
        # Print summary
        print("\n=== Split Summary ===")
        print(df.to_string())
        print(f"\nTotal images: {summary['total_images']}")
        print(f"Train: {summary['train']} ({summary['train']/summary['total_images']*100:.1f}%)")
        print(f"Validation: {summary['val']} ({summary['val']/summary['total_images']*100:.1f}%)")
        print(f"Test: {summary['test']} ({summary['test']/summary['total_images']*100:.1f}%)")

if __name__ == "__main__":
    splitter = DatasetSplitter()
    split_info = splitter.create_split()