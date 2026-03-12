#!/usr/bin/env python3
"""
Analyze dataset statistics and generate reports
"""

import os
import json
import pandas as pd
import numpy as np
from pathlib import Path
from PIL import Image, ImageStat
import exifread
import hashlib
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm

class DatasetStatistics:
    def __init__(self, dataset_path="datasets"):
        self.dataset_path = Path(dataset_path)
        self.statistics = {}
        
    def analyze_all(self):
        """Analyze complete dataset"""
        print("Analyzing dataset statistics...")
        
        # Analyze ground truth categories
        ground_truth_path = self.dataset_path / "ground_truth"
        if ground_truth_path.exists():
            categories = ["original_camera", "social_media", "edited_images", "manipulated"]
            for category in categories:
                category_path = ground_truth_path / category
                if category_path.exists():
                    self.statistics[category] = self.analyze_category(category_path, category)
        
        # Analyze validation sets
        validation_path = self.dataset_path / "validation_sets"
        if validation_path.exists():
            self.statistics["validation_sets"] = self.analyze_category(validation_path, "validation_sets")
        
        # Generate summary
        self.generate_summary()
        
        return self.statistics
    
    def analyze_category(self, category_path, category_name):
        """Analyze specific category"""
        print(f"\nAnalyzing {category_name}...")
        
        stats = {
            'total_images': 0,
            'subcategories': {},
            'image_properties': {
                'sizes': [],
                'formats': Counter(),
                'modes': Counter(),
                'file_sizes': [],
                'hashes': set()
            },
            'metadata_stats': {
                'has_exif': 0,
                'has_gps': 0,
                'cameras': Counter(),
                'software': Counter()
            }
        }
        
        # Walk through directory tree
        image_extensions = {'.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.webp'}
        image_files = []
        
        for ext in image_extensions:
            image_files.extend(category_path.rglob(f"*{ext}"))
            image_files.extend(category_path.rglob(f"*{ext.upper()}"))
        
        stats['total_images'] = len(image_files)
        
        # Analyze each image
        for img_path in tqdm(image_files, desc=f"Processing {category_name}"):
            try:
                # Get subcategory
                rel_path = img_path.relative_to(category_path)
                subcategory = str(rel_path.parent).replace('\\', '/')
                stats['subcategories'][subcategory] = stats['subcategories'].get(subcategory, 0) + 1
                
                # Get file properties
                file_size = img_path.stat().st_size
                stats['image_properties']['file_sizes'].append(file_size)
                
                # Get hash (for duplicate detection)
                file_hash = self.calculate_hash(img_path)
                stats['image_properties']['hashes'].add(file_hash)
                
                # Open image
                with Image.open(img_path) as img:
                    # Size
                    stats['image_properties']['sizes'].append(img.size)
                    
                    # Format
                    stats['image_properties']['formats'][img.format or 'unknown'] += 1
                    
                    # Mode
                    stats['image_properties']['modes'][img.mode] += 1
                
                # Extract metadata
                self.extract_metadata(img_path, stats['metadata_stats'])
                
            except Exception as e:
                print(f"Error processing {img_path}: {e}")
                continue
        
        # Calculate derived statistics
        self.calculate_derived_stats(stats)
        
        return stats
    
    def calculate_hash(self, file_path):
        """Calculate file hash"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def extract_metadata(self, image_path, metadata_stats):
        """Extract metadata from image"""
        try:
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
                
                if tags:
                    metadata_stats['has_exif'] += 1
                    
                    # Camera make/model
                    if 'Image Make' in tags and 'Image Model' in tags:
                        camera = f"{tags['Image Make']} {tags['Image Model']}"
                        metadata_stats['cameras'][str(camera)] += 1
                    
                    # Software
                    if 'Image Software' in tags:
                        software = str(tags['Image Software'])
                        metadata_stats['software'][software] += 1
                    
                    # GPS
                    if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
                        metadata_stats['has_gps'] += 1
                        
        except Exception as e:
            pass  # Skip if no metadata
    
    def calculate_derived_stats(self, stats):
        """Calculate derived statistics"""
        if stats['image_properties']['sizes']:
            sizes = np.array(stats['image_properties']['sizes'])
            stats['image_properties']['size_stats'] = {
                'min_width': int(sizes[:, 0].min()),
                'max_width': int(sizes[:, 0].max()),
                'avg_width': float(sizes[:, 0].mean()),
                'min_height': int(sizes[:, 1].min()),
                'max_height': int(sizes[:, 1].max()),
                'avg_height': float(sizes[:, 1].mean()),
                'common_sizes': Counter([tuple(size) for size in sizes]).most_common(10)
            }
        
        if stats['image_properties']['file_sizes']:
            file_sizes = np.array(stats['image_properties']['file_sizes'])
            stats['image_properties']['file_size_stats'] = {
                'min': int(file_sizes.min()),
                'max': int(file_sizes.max()),
                'avg': float(file_sizes.mean()),
                'total': int(file_sizes.sum())
            }
        
        # Duplicate detection
        total_images = stats['total_images']
        unique_images = len(stats['image_properties']['hashes'])
        stats['image_properties']['duplicates'] = total_images - unique_images
        stats['image_properties']['duplicate_percentage'] = \
            ((total_images - unique_images) / total_images * 100) if total_images > 0 else 0
    
    def generate_summary(self):
        """Generate summary statistics"""
        summary = {
            'total_images': 0,
            'categories': {},
            'overall_stats': {
                'unique_images': 0,
                'duplicate_percentage': 0,
                'common_formats': [],
                'average_size': (0, 0)
            }
        }
        
        total_unique = 0
        all_hashes = set()
        
        for category, stats in self.statistics.items():
            summary['categories'][category] = {
                'total': stats['total_images'],
                'unique': len(stats['image_properties']['hashes']),
                'duplicates': stats['image_properties'].get('duplicates', 0),
                'avg_file_size': stats['image_properties'].get('file_size_stats', {}).get('avg', 0)
            }
            
            summary['total_images'] += stats['total_images']
            all_hashes.update(stats['image_properties']['hashes'])
            total_unique += len(stats['image_properties']['hashes'])
        
        summary['overall_stats']['unique_images'] = len(all_hashes)
        summary['overall_stats']['duplicate_percentage'] = \
            (summary['total_images'] - len(all_hashes)) / summary['total_images'] * 100
        
        self.statistics['summary'] = summary
        return summary
    
    def generate_report(self, output_path="dataset_report.json"):
        """Generate JSON report"""
        report = {
            'dataset_path': str(self.dataset_path),
            'analysis_date': pd.Timestamp.now().isoformat(),
            'statistics': self.statistics
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\nReport saved to: {output_path}")
        return report
    
    def visualize_statistics(self, output_dir="reports"):
        """Generate visualization plots"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        fig, axes = plt.subplots(3, 2, figsize=(15, 18))
        
        # 1. Category distribution
        categories = list(self.statistics.get('summary', {}).get('categories', {}).keys())
        category_counts = [c['total'] for c in self.statistics.get('summary', {}).get('categories', {}).values()]
        
        axes[0, 0].bar(categories, category_counts)
        axes[0, 0].set_title('Image Distribution by Category')
        axes[0, 0].set_ylabel('Number of Images')
        axes[0, 0].tick_params(axis='x', rotation=45)
        
        # 2. File format distribution
        all_formats = Counter()
        for cat_stats in self.statistics.values():
            if 'image_properties' in cat_stats:
                all_formats.update(cat_stats['image_properties']['formats'])
        
        if all_formats:
            formats = list(all_formats.keys())
            counts = list(all_formats.values())
            axes[0, 1].pie(counts, labels=formats, autopct='%1.1f%%')
            axes[0, 1].set_title('File Format Distribution')
        
        # 3. Image size scatter plot
        all_sizes = []
        for cat_stats in self.statistics.values():
            if 'image_properties' in cat_stats and 'sizes' in cat_stats['image_properties']:
                all_sizes.extend(cat_stats['image_properties']['sizes'])
        
        if all_sizes:
            widths, heights = zip(*all_sizes)
            axes[1, 0].scatter(widths, heights, alpha=0.5, s=1)
            axes[1, 0].set_xlabel('Width (pixels)')
            axes[1, 0].set_ylabel('Height (pixels)')
            axes[1, 0].set_title('Image Size Distribution')
            axes[1, 0].grid(True, alpha=0.3)
        
        # 4. File size histogram
        all_file_sizes = []
        for cat_stats in self.statistics.values():
            if 'image_properties' in cat_stats and 'file_sizes' in cat_stats['image_properties']:
                all_file_sizes.extend(cat_stats['image_properties']['file_sizes'])
        
        if all_file_sizes:
            axes[1, 1].hist(all_file_sizes, bins=50, alpha=0.7)
            axes[1, 1].set_xlabel('File Size (bytes)')
            axes[1, 1].set_ylabel('Frequency')
            axes[1, 1].set_title('File Size Distribution')
            axes[1, 1].grid(True, alpha=0.3)
        
        # 5. Camera distribution (if available)
        camera_counts = Counter()
        for cat_stats in self.statistics.values():
            if 'metadata_stats' in cat_stats and 'cameras' in cat_stats['metadata_stats']:
                camera_counts.update(cat_stats['metadata_stats']['cameras'])
        
        if camera_counts:
            top_cameras = camera_counts.most_common(10)
            cameras, counts = zip(*top_cameras)
            axes[2, 0].barh(range(len(cameras)), counts)
            axes[2, 0].set_yticks(range(len(cameras)))
            axes[2, 0].set_yticklabels(cameras)
            axes[2, 0].set_xlabel('Count')
            axes[2, 0].set_title('Top 10 Camera Models')
        
        # 6. Software distribution (if available)
        software_counts = Counter()
        for cat_stats in self.statistics.values():
            if 'metadata_stats' in cat_stats and 'software' in cat_stats['metadata_stats']:
                software_counts.update(cat_stats['metadata_stats']['software'])
        
        if software_counts:
            top_software = software_counts.most_common(10)
            software, counts = zip(*top_software)
            axes[2, 1].barh(range(len(software)), counts)
            axes[2, 1].set_yticks(range(len(software)))
            axes[2, 1].set_yticklabels(software, fontsize=8)
            axes[2, 1].set_xlabel('Count')
            axes[2, 1].set_title('Top 10 Software Used')
        
        plt.tight_layout()
        plt.savefig(output_dir / 'dataset_statistics.png', dpi=150, bbox_inches='tight')
        plt.show()
        
        print(f"Visualizations saved to: {output_dir}/")

if __name__ == "__main__":
    analyzer = DatasetStatistics("datasets")
    stats = analyzer.analyze_all()
    report = analyzer.generate_report("dataset_analysis_report.json")
    analyzer.visualize_statistics()