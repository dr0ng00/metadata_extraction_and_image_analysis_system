#!/usr/bin/env python3
"""
Generate Sample Test Data
Create sample images for testing MetaForensicAI system.
"""

import os
import sys
import json
import random
from pathlib import Path
from datetime import datetime, timedelta
from PIL import Image, ImageDraw, ImageFont
import hashlib
import shutil

class SampleDataGenerator:
    """Generate sample test data for forensic analysis."""
    
    def __init__(self, output_dir=None):
        """Initialize sample data generator."""
        self.output_dir = Path(output_dir or './test_data')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Categories and their characteristics
        self.categories = {
            'original': {
                'count': 10,
                'description': 'Original camera images with complete metadata',
                'characteristics': ['complete_metadata', 'consistent_timestamps', 'no_compression']
            },
            'whatsapp': {
                'count': 5,
                'description': 'WhatsApp compressed images',
                'characteristics': ['stripped_metadata', 'compressed_1280', 'whatsapp_pattern']
            },
            'instagram': {
                'count': 5,
                'description': 'Instagram processed images',
                'characteristics': ['square_crop', 'compressed_1080', 'instagram_pattern']
            },
            'screenshot': {
                'count': 5,
                'description': 'Mobile and desktop screenshots',
                'characteristics': ['no_camera_metadata', 'screen_resolution', 'ui_elements']
            },
            'edited': {
                'count': 5,
                'description': 'Photoshop/Lightroom edited images',
                'characteristics': ['software_signatures', 'timestamp_inconsistencies', 'edited_metadata']
            },
            'manipulated': {
                'count': 5,
                'description': 'Deliberately manipulated images',
                'characteristics': ['tampered_metadata', 'inconsistent_patterns', 'high_risk_indicators']
            }
        }
        
        # Camera models for simulation
        self.camera_models = [
            {'make': 'Canon', 'model': 'EOS 5D Mark IV', 'year': 2016},
            {'make': 'Nikon', 'model': 'D850', 'year': 2017},
            {'make': 'Sony', 'model': 'ILCE-7RM4', 'year': 2019},
            {'make': 'Apple', 'model': 'iPhone 14 Pro', 'year': 2022},
            {'make': 'Samsung', 'model': 'Galaxy S23 Ultra', 'year': 2023}
        ]
        
        # Software signatures
        self.software_signatures = [
            'Adobe Photoshop 24.0',
            'Adobe Lightroom Classic 12.0',
            'GIMP 2.10',
            'Canon Digital Photo Professional 4.0',
            'Nikon Capture NX-D'
        ]
    
    def generate_all_samples(self):
        """Generate all sample data categories."""
        print("\n" + "="*70)
        print("SAMPLE DATA GENERATION".center(70))
        print("="*70 + "\n")
        
        all_samples = {}
        total_count = 0
        
        for category, config in self.categories.items():
            print(f"Generating {category} samples...")
            category_samples = self._generate_category_samples(category, config)
            all_samples[category] = category_samples
            total_count += len(category_samples)
            
            print(f"  ✅ Generated {len(category_samples)} {category} samples")
        
        # Generate metadata file
        metadata_file = self._generate_metadata_file(all_samples)
        
        print(f"\n📊 Summary:")
        print(f"   • Total samples: {total_count}")
        print(f"   • Categories: {len(self.categories)}")
        print(f"   • Output directory: {self.output_dir}")
        print(f"   • Metadata file: {metadata_file}")
        
        return all_samples
    
    def _generate_category_samples(self, category: str, config: dict) -> list:
        """Generate samples for a specific category."""
        samples = []
        category_dir = self.output_dir / category
        category_dir.mkdir(exist_ok=True)
        
        for i in range(config['count']):
            # Generate unique sample
            sample_data = self._generate_single_sample(category, i, config)
            
            # Create image
            img_path = self._create_sample_image(category_dir, sample_data)
            
            # Update sample data with file info
            sample_data['file_path'] = str(img_path)
            sample_data['file_size'] = img_path.stat().st_size
            sample_data['file_hash'] = self._calculate_file_hash(img_path)
            
            samples.append(sample_data)
        
        return samples
    
    def _generate_single_sample(self, category: str, index: int, config: dict) -> dict:
        """Generate metadata for a single sample."""
        # Base metadata
        sample_id = f"{category}_{index:03d}"
        
        # Timestamps
        base_time = datetime.now() - timedelta(days=random.randint(1, 365))
        datetime_original = base_time
        create_date = base_time + timedelta(seconds=random.randint(0, 10))
        modify_date = create_date
        
        # Adjust timestamps based on category
        if category == 'edited':
            modify_date = create_date + timedelta(hours=random.randint(1, 24))
        elif category == 'manipulated':
            datetime_original = base_time - timedelta(days=random.randint(1, 30))
        
        # Camera/device info
        if category in ['original', 'edited']:
            camera = random.choice(self.camera_models)
        elif category in ['whatsapp', 'instagram']:
            camera = {'make': 'Apple', 'model': 'iPhone', 'year': 2022}
        elif category == 'screenshot':
            camera = {'make': 'System', 'model': 'Screenshot', 'year': 2023}
        else:
            camera = None
        
        # Software info
        software = None
        if category == 'edited':
            software = random.choice(self.software_signatures)
        elif category == 'manipulated':
            software = 'Unknown Editor'
        
        # GPS coordinates (sometimes)
        gps_data = None
        if random.random() > 0.5 and category in ['original', 'edited']:
            gps_data = {
                'latitude': round(random.uniform(-90, 90), 6),
                'longitude': round(random.uniform(-180, 180), 6),
                'altitude': round(random.uniform(0, 1000), 1)
            }
        
        # Compression/quality
        if category == 'whatsapp':
            quality = random.randint(72, 82)
            dimensions = (1280, 960) if random.random() > 0.5 else (1024, 768)
        elif category == 'instagram':
            quality = random.randint(80, 90)
            dimensions = (1080, 1080)  # Square
        elif category == 'screenshot':
            quality = 95
            dimensions = random.choice([(1920, 1080), (1440, 2560), (2560, 1440)])
        else:
            quality = random.randint(90, 98)
            dimensions = (random.randint(2000, 6000), random.randint(1500, 4000))
        
        return {
            'sample_id': sample_id,
            'category': category,
            'description': config['description'],
            'characteristics': config['characteristics'],
            'timestamps': {
                'datetime_original': datetime_original.isoformat(),
                'create_date': create_date.isoformat(),
                'modify_date': modify_date.isoformat()
            },
            'camera_info': camera,
            'software': software,
            'gps_data': gps_data,
            'image_info': {
                'dimensions': dimensions,
                'quality': quality,
                'format': 'JPEG',
                'color_space': 'sRGB'
            },
            'forensic_indicators': self._get_forensic_indicators(category),
            'expected_risk_score': self._get_expected_risk_score(category)
        }
    
    def _get_forensic_indicators(self, category: str) -> list:
        """Get expected forensic indicators for category."""
        indicators_map = {
            'original': [
                'complete_metadata',
                'consistent_timestamps',
                'camera_signature_present',
                'single_compression_cycle'
            ],
            'whatsapp': [
                'metadata_stripped',
                'platform_compression',
                'specific_dimensions',
                'reduced_quality'
            ],
            'instagram': [
                'square_aspect_ratio',
                'max_dimension_1080',
                'color_profile_srgb',
                'metadata_pattern'
            ],
            'screenshot': [
                'no_camera_metadata',
                'screen_resolution',
                'system_generated',
                'contains_ui_elements'
            ],
            'edited': [
                'software_signature',
                'timestamp_inconsistency',
                'edited_metadata',
                'possible_tampering'
            ],
            'manipulated': [
                'high_risk_tampering',
                'metadata_anomalies',
                'multiple_compression',
                'forgery_indicators'
            ]
        }
        
        return indicators_map.get(category, [])
    
    def _get_expected_risk_score(self, category: str) -> dict:
        """Get expected risk score range for category."""
        score_ranges = {
            'original': {'min': 0, 'max': 20, 'expected': 'VERY_LOW'},
            'whatsapp': {'min': 30, 'max': 50, 'expected': 'LOW'},
            'instagram': {'min': 30, 'max': 50, 'expected': 'LOW'},
            'screenshot': {'min': 40, 'max': 60, 'expected': 'MODERATE'},
            'edited': {'min': 50, 'max': 80, 'expected': 'HIGH'},
            'manipulated': {'min': 70, 'max': 100, 'expected': 'VERY_HIGH'}
        }
        
        return score_ranges.get(category, {'min': 0, 'max': 100, 'expected': 'UNKNOWN'})
    
    def _create_sample_image(self, output_dir: Path, sample_data: dict) -> Path:
        """Create a sample image file with appropriate characteristics."""
        dimensions = sample_data['image_info']['dimensions']
        quality = sample_data['image_info']['quality']
        
        # Create image
        img = Image.new('RGB', dimensions, color=self._get_random_color())
        draw = ImageDraw.Draw(img)
        
        # Add some content based on category
        category = sample_data['category']
        
        if category == 'screenshot':
            # Simulate screenshot with UI elements
            self._add_screenshot_elements(draw, dimensions)
        elif category in ['whatsapp', 'instagram']:
            # Social media style
            self._add_social_media_elements(draw, dimensions, category)
        else:
            # Camera photo style
            self._add_photo_elements(draw, dimensions)
        
        # Add text overlay with sample info
        self._add_sample_info(draw, dimensions, sample_data)
        
        # Save image
        filename = f"{sample_data['sample_id']}.jpg"
        filepath = output_dir / filename
        
        img.save(filepath, 'JPEG', quality=quality)
        
        return filepath
    
    def _get_random_color(self):
        """Get random color tuple."""
        return (
            random.randint(50, 255),
            random.randint(50, 255),
            random.randint(50, 255)
        )
    
    def _add_screenshot_elements(self, draw, dimensions):
        """Add screenshot-like elements to image."""
        width, height = dimensions
        
        # Status bar (top)
        draw.rectangle([0, 0, width, 50], fill=(240, 240, 240))
        draw.text((10, 10), "9:41", fill=(0, 0, 0))
        draw.text((width - 100, 10), "4G", fill=(0, 0, 0))
        
        # App header
        draw.rectangle([0, 50, width, 120], fill=(0, 122, 255))
        draw.text((20, 70), "Settings", fill=(255, 255, 255), font_size=24)
        
        # List items
        for i in range(5):
            y = 130 + i * 60
            draw.rectangle([20, y, width - 20, y + 50], fill=(245, 245, 245))
            draw.text((40, y + 10), f"Option {i+1}", fill=(0, 0, 0))
            draw.rectangle([width - 40, y + 20, width - 30, y + 30], fill=(200, 200, 200))
    
    def _add_social_media_elements(self, draw, dimensions, platform):
        """Add social media style elements."""
        width, height = dimensions
        
        # Platform-specific background
        if platform == 'instagram':
            # Instagram gradient
            for y in range(height):
                color = (
                    int(255 * (y / height)),
                    int(100 * (y / height)),
                    int(200 * (y / height))
                )
                draw.line([0, y, width, y], fill=color, width=1)
        else:
            # WhatsApp green
            draw.rectangle([0, 0, width, height], fill=(37, 211, 102))
        
        # Add platform logo/text
        if platform == 'instagram':
            # Instagram camera
            center_x, center_y = width // 2, height // 2
            radius = min(width, height) // 4
            draw.ellipse(
                [center_x - radius, center_y - radius, center_x + radius, center_y + radius],
                outline=(255, 255, 255),
                width=10
            )
            draw.ellipse(
                [center_x - radius//2, center_y - radius//2, center_x + radius//2, center_y + radius//2],
                outline=(255, 255, 255),
                width=10
            )
        else:
            # WhatsApp phone
            draw.text(
                (width // 2 - 50, height // 2 - 20),
                "WhatsApp",
                fill=(255, 255, 255),
                font_size=40
            )
    
    def _add_photo_elements(self, draw, dimensions):
        """Add photo-like elements."""
        width, height = dimensions
        
        # Gradient sky
        for y in range(height // 2):
            blue = int(135 + (120 * y / (height // 2)))
            draw.line([0, y, width, y], fill=(135, 206, blue), width=1)
        
        # Ground
        draw.rectangle([0, height // 2, width, height], fill=(34, 139, 34))
        
        # Sun
        sun_radius = min(width, height) // 10
        draw.ellipse(
            [width - sun_radius - 50, 50, width - 50, 50 + sun_radius * 2],
            fill=(255, 255, 0)
        )
        
        # Trees
        for i in range(3):
            x = width // 4 * (i + 1)
            # Trunk
            draw.rectangle([x - 10, height // 2, x + 10, height // 2 + 100], fill=(139, 69, 19))
            # Leaves
            draw.ellipse([x - 50, height // 2 - 100, x + 50, height // 2], fill=(0, 100, 0))
    
    def _add_sample_info(self, draw, dimensions, sample_data):
        """Add sample information text overlay."""
        width, height = dimensions
        
        # Info box background
        info_height = 80
        draw.rectangle(
            [10, height - info_height - 10, width - 10, height - 10],
            fill=(0, 0, 0, 128)  # Semi-transparent black
        )
        
        # Sample info text
        info_lines = [
            f"ID: {sample_data['sample_id']}",
            f"Category: {sample_data['category']}",
            f"Dimensions: {dimensions[0]}x{dimensions[1]}"
        ]
        
        for i, line in enumerate(info_lines):
            draw.text(
                (20, height - info_height + 10 + i * 20),
                line,
                fill=(255, 255, 255)
            )
    
    def _calculate_file_hash(self, filepath: Path) -> str:
        """Calculate SHA-256 hash of file."""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _generate_metadata_file(self, all_samples: dict) -> Path:
        """Generate comprehensive metadata file."""
        metadata = {
            'generated': datetime.now().isoformat(),
            'total_samples': sum(len(samples) for samples in all_samples.values()),
            'categories': {},
            'samples': {}
        }
        
        # Organize by category
        for category, samples in all_samples.items():
            metadata['categories'][category] = {
                'count': len(samples),
                'description': self.categories[category]['description'],
                'characteristics': self.categories[category]['characteristics']
            }
            
            for sample in samples:
                metadata['samples'][sample['sample_id']] = {
                    'category': sample['category'],
                    'file_path': sample['file_path'],
                    'file_size': sample['file_size'],
                    'file_hash': sample['file_hash'],
                    'timestamps': sample['timestamps'],
                    'camera_info': sample['camera_info'],
                    'software': sample['software'],
                    'gps_data': sample['gps_data'],
                    'image_info': sample['image_info'],
                    'forensic_indicators': sample['forensic_indicators'],
                    'expected_risk_score': sample['expected_risk_score']
                }
        
        # Save metadata
        metadata_file = self.output_dir / 'sample_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Also create CSV version
        csv_file = self.output_dir / 'sample_metadata.csv'
        self._create_csv_metadata(metadata, csv_file)
        
        return metadata_file
    
    def _create_csv_metadata(self, metadata: dict, csv_file: Path):
        """Create CSV version of metadata."""
        import csv
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'sample_id', 'category', 'file_path', 'file_size',
                'datetime_original', 'camera_make', 'camera_model',
                'software', 'dimensions', 'quality', 'expected_risk_min',
                'expected_risk_max', 'expected_risk_level'
            ])
            
            # Write data rows
            for sample_id, sample in metadata['samples'].items():
                writer.writerow([
                    sample_id,
                    sample['category'],
                    sample['file_path'],
                    sample['file_size'],
                    sample['timestamps']['datetime_original'],
                    sample['camera_info']['make'] if sample['camera_info'] else '',
                    sample['camera_info']['model'] if sample['camera_info'] else '',
                    sample['software'] or '',
                    f"{sample['image_info']['dimensions'][0]}x{sample['image_info']['dimensions'][1]}",
                    sample['image_info']['quality'],
                    sample['expected_risk_score']['min'],
                    sample['expected_risk_score']['max'],
                    sample['expected_risk_score']['expected']
                ])


def main():
    """Main entry point for sample data generation."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate sample test data for MetaForensicAI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --output test_data/
  %(prog)s --category original --count 20
  %(prog)s --quick --all-categories
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        default='./test_data',
        help='Output directory for sample data'
    )
    
    parser.add_argument(
        '--category',
        choices=['original', 'whatsapp', 'instagram', 'screenshot', 'edited', 'manipulated', 'all'],
        default='all',
        help='Category of samples to generate'
    )
    
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=5,
        help='Number of samples per category'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick generation (smaller images)'
    )
    
    parser.add_argument(
        '--metadata-only',
        action='store_true',
        help='Generate metadata only (skip image creation)'
    )
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("SAMPLE DATA GENERATION".center(70))
    print("="*70 + "\n")
    
    try:
        # Initialize generator
        generator = SampleDataGenerator(output_dir=args.output)
        
        # Adjust counts if quick mode
        if args.quick:
            for category in generator.categories:
                generator.categories[category]['count'] = min(2, generator.categories[category]['count'])
        
        # Adjust specific category count
        if args.category != 'all':
            for category in generator.categories:
                if category != args.category:
                    generator.categories[category]['count'] = 0
                else:
                    generator.categories[category]['count'] = args.count
        
        # Generate samples
        results = generator.generate_all_samples()
        
        print(f"\n✅ Sample data generation complete!")
        print(f"\nNext steps:")
        print(f"1. Test with MetaForensicAI:")
        print(f"   python -m src.main --image {args.output}/original/original_000.jpg")
        print(f"2. Run batch analysis:")
        print(f"   python scripts/batch_analyzer.py --input {args.output}")
        print(f"3. Use for validation:")
        print(f"   python scripts/validation_runner.py")
        
    except Exception as e:
        print(f"\n❌ Sample data generation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()