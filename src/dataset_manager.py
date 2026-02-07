"""
Comprehensive dataset management system for MetaForensicAI
"""

import os
import sys
import json
import yaml
import hashlib
import shutil
import random
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Union
import pandas as pd
import numpy as np
from PIL import Image, ImageFile
import exifread
from tqdm import tqdm
from dataclasses import dataclass, asdict, field
from enum import Enum
import warnings

# Enable loading of truncated images
ImageFile.LOAD_TRUNCATED_IMAGES = True

class DatasetCategory(Enum):
    """Dataset category enumeration"""
    ORIGINAL_CAMERA = "original_camera"
    SOCIAL_MEDIA = "social_media"
    EDITED_IMAGES = "edited_images"
    MANIPULATED = "manipulated"

class ImageFormat(Enum):
    """Supported image formats"""
    JPEG = "jpg"
    PNG = "png"
    WEBP = "webp"
    HEIC = "heic"
    TIFF = "tiff"
    BMP = "bmp"

@dataclass
class ImageMetadata:
    """Image metadata container"""
    path: str
    filename: str
    category: str
    subcategory: str
    source: str
    format: str
    size_bytes: int
    dimensions: Tuple[int, int]
    hash_md5: str
    hash_sha256: str
    exif_data: Dict = field(default_factory=dict)
    xmp_data: Dict = field(default_factory=dict)
    iptc_data: Dict = field(default_factory=dict)
    platform_metadata: Dict = field(default_factory=dict)
    creation_date: Optional[datetime] = None
    modification_date: Optional[datetime] = None
    camera_info: Dict = field(default_factory=dict)
    software_info: Dict = field(default_factory=dict)
    compression_info: Dict = field(default_factory=dict)
    quality_score: float = 0.0
    validation_status: str = "pending"
    notes: str = ""

@dataclass
class DatasetStatistics:
    """Dataset statistics container"""
    total_images: int = 0
    total_size_gb: float = 0.0
    categories: Dict[str, int] = field(default_factory=dict)
    formats: Dict[str, int] = field(default_factory=dict)
    resolutions: Dict[str, int] = field(default_factory=dict)
    sources: Dict[str, int] = field(default_factory=dict)
    date_range: Tuple[datetime, datetime] = (datetime.max, datetime.min)
    quality_distribution: Dict[str, int] = field(default_factory=dict)
    metadata_completeness: Dict[str, float] = field(default_factory=dict)

class ForensicDatasetManager:
    """
    Comprehensive forensic dataset manager for MetaForensicAI
    """
    
    def __init__(self, base_path: str = "datasets", config_path: Optional[str] = None):
        """
        Initialize dataset manager
        
        Args:
            base_path: Path to datasets directory
            config_path: Path to configuration file
        """
        self.base_path = Path(base_path)
        self.config_path = Path(config_path) if config_path else self.base_path / "dataset_config.yaml"
        self.config = self._load_config()
        
        # Initialize directories
        self._init_directories()
        
        # Load metadata index if exists
        self.metadata_index = self._load_metadata_index()
        
        # Statistics
        self.statistics = DatasetStatistics()
        
    def _load_config(self) -> Dict:
        """Load configuration file"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'dataset': {
                'name': 'MetaForensicAI Dataset',
                'version': '1.0.0'
            }
        }
    
    def _init_directories(self):
        """Initialize directory structure"""
        directories = [
            self.base_path,
            self.base_path / "ground_truth",
            self.base_path / "ground_truth" / "original_camera",
            self.base_path / "ground_truth" / "social_media",
            self.base_path / "ground_truth" / "edited_images",
            self.base_path / "ground_truth" / "manipulated",
            self.base_path / "validation_sets",
            
            # Original camera subdirectories
            self.base_path / "ground_truth" / "original_camera" / "canon",
            self.base_path / "ground_truth" / "original_camera" / "nikon",
            self.base_path / "ground_truth" / "original_camera" / "sony",
            self.base_path / "ground_truth" / "original_camera" / "iphone",
            self.base_path / "ground_truth" / "original_camera" / "samsung",
            self.base_path / "ground_truth" / "original_camera" / "google",
            
            # Social media subdirectories
            self.base_path / "ground_truth" / "social_media" / "facebook",
            self.base_path / "ground_truth" / "social_media" / "instagram",
            self.base_path / "ground_truth" / "social_media" / "twitter",
            self.base_path / "ground_truth" / "social_media" / "tiktok",
            self.base_path / "ground_truth" / "social_media" / "whatsapp",
            self.base_path / "ground_truth" / "social_media" / "linkedin",
            
            # Edited images subdirectories
            self.base_path / "ground_truth" / "edited_images" / "photoshop",
            self.base_path / "ground_truth" / "edited_images" / "lightroom",
            self.base_path / "ground_truth" / "edited_images" / "gimp",
            self.base_path / "ground_truth" / "edited_images" / "mobile_apps",
            
            # Manipulated subdirectories
            self.base_path / "ground_truth" / "manipulated" / "splicing",
            self.base_path / "ground_truth" / "manipulated" / "cloning",
            self.base_path / "ground_truth" / "manipulated" / "generative",
            self.base_path / "ground_truth" / "manipulated" / "removal",
            self.base_path / "ground_truth" / "manipulated" / "addition",
            self.base_path / "ground_truth" / "manipulated" / "ground_truth_masks",
            
            # Validation sets
            self.base_path / "validation_sets" / "blind_test_set_a",
            self.base_path / "validation_sets" / "blind_test_set_b",
            self.base_path / "validation_sets" / "competition_sets",
            self.base_path / "validation_sets" / "forensic_challenges",
            self.base_path / "validation_sets" / "real_world_cases",
            
            # Metadata and indices
            self.base_path / "metadata",
            self.base_path / "indices",
            self.base_path / "logs",
            self.base_path / "reports",
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _load_metadata_index(self) -> pd.DataFrame:
        """Load metadata index if exists"""
        index_path = self.base_path / "indices" / "metadata_index.parquet"
        if index_path.exists():
            return pd.read_parquet(index_path)
        else:
            return pd.DataFrame()
    
    def add_image(self, 
                  image_path: Union[str, Path],
                  category: Union[str, DatasetCategory],
                  subcategory: str,
                  source: str,
                  metadata: Optional[Dict] = None,
                  copy_file: bool = True,
                  validate: bool = True) -> Optional[ImageMetadata]:
        """
        Add an image to the dataset
        
        Args:
            image_path: Path to source image
            category: Dataset category
            subcategory: Subcategory within category
            source: Source description
            metadata: Additional metadata
            copy_file: Whether to copy the file
            validate: Whether to validate the image
            
        Returns:
            ImageMetadata object or None if failed
        """
        try:
            image_path = Path(image_path)
            if not image_path.exists():
                raise FileNotFoundError(f"Image not found: {image_path}")
            
            # Determine target path
            if isinstance(category, DatasetCategory):
                category = category.value
            
            target_dir = self.base_path / "ground_truth" / category / subcategory
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_hash = self._calculate_file_hash(image_path)
            extension = image_path.suffix.lower()
            
            target_filename = f"{category}_{subcategory}_{timestamp}_{file_hash[:8]}{extension}"
            target_path = target_dir / target_filename
            
            # Copy or move file
            if copy_file:
                shutil.copy2(image_path, target_path)
            else:
                shutil.move(str(image_path), target_path)
            
            # Extract metadata
            image_metadata = self._extract_image_metadata(target_path, category, subcategory, source)
            
            # Add additional metadata
            if metadata:
                for key, value in metadata.items():
                    if hasattr(image_metadata, key):
                        setattr(image_metadata, key, value)
            
            # Validate if requested
            if validate:
                validation_result = self._validate_image(target_path)
                image_metadata.validation_status = validation_result["status"]
                image_metadata.notes = validation_result.get("notes", "")
            
            # Update index
            self._update_metadata_index(image_metadata)
            
            print(f"Added image: {target_filename}")
            return image_metadata
            
        except Exception as e:
            print(f"Error adding image {image_path}: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate file hash"""
        hash_func = hashlib.sha256() if algorithm == "sha256" else hashlib.md5()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _extract_image_metadata(self, 
                                image_path: Path,
                                category: str,
                                subcategory: str,
                                source: str) -> ImageMetadata:
        """Extract comprehensive image metadata"""
        
        # Basic file info
        stat = image_path.stat()
        file_size = stat.st_size
        
        # Open image
        with Image.open(image_path) as img:
            dimensions = img.size
            image_format = img.format or "unknown"
            
            # Extract EXIF if available (using modern Pillow approach)
            exif_data = {}
            try:
                if hasattr(img, 'getexif'):
                    exif_dict = img.getexif()
                    if exif_dict:
                        exif_data = self._parse_exif_data(dict(exif_dict))
            except Exception:
                pass  # If EXIF extraction fails, continue with exifread data
        
        # Extract EXIF using exifread for more details
        exifread_data = {}
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            exifread_data = {str(tag): str(value) for tag, value in tags.items()}
        
        # Calculate hashes
        md5_hash = self._calculate_file_hash(image_path, "md5")
        sha256_hash = self._calculate_file_hash(image_path, "sha256")
        
        # Extract camera and software info
        camera_info = self._extract_camera_info(exifread_data)
        software_info = self._extract_software_info(exifread_data)
        
        # Create metadata object
        metadata = ImageMetadata(
            path=str(image_path),
            filename=image_path.name,
            category=category,
            subcategory=subcategory,
            source=source,
            format=image_format.lower(),
            size_bytes=file_size,
            dimensions=dimensions,
            hash_md5=md5_hash,
            hash_sha256=sha256_hash,
            exif_data=exifread_data,
            camera_info=camera_info,
            software_info=software_info,
            creation_date=datetime.fromtimestamp(stat.st_ctime),
            modification_date=datetime.fromtimestamp(stat.st_mtime),
            compression_info=self._extract_compression_info(image_path),
            quality_score=self._calculate_quality_score(image_path)
        )
        
        return metadata
    
    def _parse_exif_data(self, exif_dict: Dict) -> Dict:
        """Parse EXIF data"""
        parsed = {}
        
        # Map EXIF tags to human-readable names
        exif_tags = {
            271: 'Make',
            272: 'Model',
            274: 'Orientation',
            282: 'XResolution',
            283: 'YResolution',
            296: 'ResolutionUnit',
            306: 'DateTime',
            33432: 'Copyright',
            36867: 'DateTimeOriginal',
            36868: 'DateTimeDigitized',
            37377: 'ShutterSpeedValue',
            37378: 'ApertureValue',
            37379: 'BrightnessValue',
            37380: 'ExposureBiasValue',
            37381: 'MaxApertureValue',
            37382: 'SubjectDistance',
            37383: 'MeteringMode',
            37384: 'LightSource',
            37385: 'Flash',
            37386: 'FocalLength',
            37396: 'SubjectArea',
            37500: 'MakerNote',
            41985: 'WhiteBalance',
            41986: 'DigitalZoomRatio',
            41987: 'FocalLengthIn35mmFilm',
            41990: 'SceneCaptureType',
            41992: 'Contrast',
            41993: 'Saturation',
            41994: 'Sharpness',
        }
        
        for tag_id, value in exif_dict.items():
            tag_name = exif_tags.get(tag_id, f'Unknown_{tag_id}')
            parsed[tag_name] = value
        
        return parsed
    
    def _extract_camera_info(self, exif_data: Dict) -> Dict:
        """Extract camera information from EXIF"""
        camera_info = {
            'make': exif_data.get('Image Make', 'Unknown'),
            'model': exif_data.get('Image Model', 'Unknown'),
            'lens': exif_data.get('EXIF LensModel', 'Unknown'),
            'serial_number': exif_data.get('EXIF BodySerialNumber', 'Unknown'),
            'firmware': exif_data.get('EXIF FirmwareVersion', 'Unknown')
        }
        return camera_info
    
    def _extract_software_info(self, exif_data: Dict) -> Dict:
        """Extract software information"""
        software_info = {
            'software': exif_data.get('Image Software', 'Unknown'),
            'processing_software': exif_data.get('EXIF ProcessingSoftware', 'Unknown'),
            'history': exif_data.get('EXIF History', '')
        }
        return software_info
    
    def _extract_compression_info(self, image_path: Path) -> Dict:
        """Extract compression information"""
        compression_info = {
            'type': 'unknown',
            'quality': 0,
            'subsampling': 'unknown'
        }
        
        try:
            with Image.open(image_path) as img:
                if img.format == 'JPEG':
                    compression_info['type'] = 'JPEG'
                    # Try to get quantization tables
                    try:
                        # This is a simplified approach
                        # In practice, you'd need to parse the JPEG structure
                        compression_info['quality'] = self._estimate_jpeg_quality(image_path)
                    except:
                        pass
        except:
            pass
        
        return compression_info
    
    def _estimate_jpeg_quality(self, image_path: Path) -> int:
        """Estimate JPEG quality (simplified)"""
        # This is a placeholder - implement actual quality estimation
        return 85
    
    def _calculate_quality_score(self, image_path: Path) -> float:
        """Calculate image quality score"""
        try:
            with Image.open(image_path) as img:
                # Simple quality metrics
                width, height = img.size
                total_pixels = width * height
                
                # Check for compression artifacts
                # This is a simplified version
                score = 0.8  # Base score
                
                # Adjust based on resolution
                if total_pixels > 8000000:  # > 8MP
                    score += 0.1
                elif total_pixels < 1000000:  # < 1MP
                    score -= 0.2
                
                return min(max(score, 0), 1)
        except:
            return 0.5
    
    def _validate_image(self, image_path: Path) -> Dict:
        """Validate image file"""
        validation = {
            'status': 'passed',
            'errors': [],
            'warnings': [],
            'notes': ''
        }
        
        try:
            # Check file exists
            if not image_path.exists():
                validation['status'] = 'failed'
                validation['errors'].append('File does not exist')
                return validation
            
            # Check file size
            file_size = image_path.stat().st_size
            if file_size == 0:
                validation['status'] = 'failed'
                validation['errors'].append('File is empty')
            
            # Try to open with PIL
            try:
                with Image.open(image_path) as img:
                    img.verify()  # Verify file integrity
                    
                    # Check dimensions
                    width, height = img.size
                    if width < 100 or height < 100:
                        validation['warnings'].append('Image dimensions are very small')
                    
                    # Check format
                    if img.format not in ['JPEG', 'PNG', 'TIFF', 'BMP', 'WEBP']:
                        validation['warnings'].append(f'Unusual format: {img.format}')
                    
            except Exception as e:
                validation['status'] = 'failed'
                validation['errors'].append(f'Cannot open image: {str(e)}')
            
            # Check for corruption
            try:
                with open(image_path, 'rb') as f:
                    # Read entire file to check for read errors
                    f.read()
            except Exception as e:
                validation['status'] = 'failed'
                validation['errors'].append(f'File read error: {str(e)}')
            
        except Exception as e:
            validation['status'] = 'error'
            validation['errors'].append(f'Validation error: {str(e)}')
        
        # Update status based on findings
        if validation['errors']:
            validation['status'] = 'failed'
        elif validation['warnings']:
            validation['status'] = 'warning'
        
        validation['notes'] = '; '.join(validation['errors'] + validation['warnings'])
        
        return validation
    
    def _update_metadata_index(self, metadata: ImageMetadata):
        """Update metadata index with new image"""
        metadata_dict = asdict(metadata)
        
        # Convert to DataFrame row
        new_row = pd.DataFrame([metadata_dict])
        
        if self.metadata_index.empty:
            self.metadata_index = new_row
        else:
            self.metadata_index = pd.concat([self.metadata_index, new_row], ignore_index=True)
        
        # Save index
        self._save_metadata_index()
    
    def _save_metadata_index(self):
        """Save metadata index to disk"""
        index_path = self.base_path / "indices" / "metadata_index.parquet"
        self.metadata_index.to_parquet(index_path, index=False)
    
    def analyze_dataset(self, update_statistics: bool = True) -> DatasetStatistics:
        """
        Analyze the complete dataset
        
        Args:
            update_statistics: Whether to update statistics
            
        Returns:
            DatasetStatistics object
        """
        print("Analyzing dataset...")
        
        # Reset statistics
        self.statistics = DatasetStatistics()
        
        # Walk through dataset
        for category in DatasetCategory:
            category_path = self.base_path / "ground_truth" / category.value
            
            if not category_path.exists():
                continue
            
            # Count images in category
            image_files = list(category_path.rglob("*.jpg")) + \
                         list(category_path.rglob("*.jpeg")) + \
                         list(category_path.rglob("*.png")) + \
                         list(category_path.rglob("*.webp")) + \
                         list(category_path.rglob("*.tiff")) + \
                         list(category_path.rglob("*.bmp"))
            
            category_count = len(image_files)
            self.statistics.categories[category.value] = category_count
            self.statistics.total_images += category_count
            
            # Analyze each image
            for image_path in tqdm(image_files, desc=f"Analyzing {category.value}"):
                try:
                    # Update format statistics
                    extension = image_path.suffix.lower()
                    self.statistics.formats[extension] = self.statistics.formats.get(extension, 0) + 1
                    
                    # Update size
                    file_size = image_path.stat().st_size
                    self.statistics.total_size_gb += file_size / (1024**3)
                    
                    # Update resolution statistics
                    with Image.open(image_path) as img:
                        resolution = f"{img.size[0]}x{img.size[1]}"
                        self.statistics.resolutions[resolution] = \
                            self.statistics.resolutions.get(resolution, 0) + 1
                    
                    # Extract source from path
                    parts = image_path.relative_to(category_path).parts
                    if parts:
                        source = parts[0]
                        self.statistics.sources[source] = \
                            self.statistics.sources.get(source, 0) + 1
                    
                except Exception as e:
                    print(f"Error analyzing {image_path}: {e}")
        
        # Calculate derived statistics
        self._calculate_derived_statistics()
        
        # Save statistics
        if update_statistics:
            self._save_statistics()
        
        return self.statistics
    
    def _calculate_derived_statistics(self):
        """Calculate derived statistics"""
        # Calculate date range from metadata index
        if not self.metadata_index.empty and 'creation_date' in self.metadata_index.columns:
            dates = pd.to_datetime(self.metadata_index['creation_date'])
            if not dates.empty:
                self.statistics.date_range = (dates.min(), dates.max())
        
        # Calculate metadata completeness
        if not self.metadata_index.empty:
            total_rows = len(self.metadata_index)
            for column in ['exif_data', 'camera_info', 'software_info']:
                if column in self.metadata_index.columns:
                    non_null = self.metadata_index[column].notna().sum()
                    completeness = non_null / total_rows if total_rows > 0 else 0
                    self.statistics.metadata_completeness[column] = completeness
        
        # Calculate quality distribution
        if not self.metadata_index.empty and 'quality_score' in self.metadata_index.columns:
            scores = self.metadata_index['quality_score']
            bins = [0, 0.3, 0.6, 0.8, 1.0]
            labels = ['poor', 'fair', 'good', 'excellent']
            
            if not scores.empty:
                binned = pd.cut(scores, bins=bins, labels=labels, include_lowest=True)
                self.statistics.quality_distribution = binned.value_counts().to_dict()
    
    def _save_statistics(self):
        """Save statistics to disk"""
        stats_path = self.base_path / "reports" / "dataset_statistics.json"
        
        # Convert statistics to dict
        stats_dict = asdict(self.statistics)
        
        # Convert datetime objects to strings
        for key, value in stats_dict.items():
            if isinstance(value, datetime):
                stats_dict[key] = value.isoformat()
            elif isinstance(value, tuple) and len(value) == 2:
                if isinstance(value[0], datetime) and isinstance(value[1], datetime):
                    stats_dict[key] = (value[0].isoformat(), value[1].isoformat())
        
        with open(stats_path, 'w') as f:
            json.dump(stats_dict, f, indent=2, default=str)
    
    def generate_report(self, 
                       output_format: str = "html",
                       include_visualizations: bool = True) -> str:
        """
        Generate dataset report
        
        Args:
            output_format: Report format (html, pdf, json)
            include_visualizations: Whether to include charts
        
        Returns:
            Path to generated report
        """
        report_dir = self.base_path / "reports"
        report_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format == "html":
            report_path = report_dir / f"dataset_report_{timestamp}.html"
            self._generate_html_report(report_path, include_visualizations)
        elif output_format == "json":
            report_path = report_dir / f"dataset_report_{timestamp}.json"
            self._generate_json_report(report_path)
        elif output_format == "pdf":
            report_path = report_dir / f"dataset_report_{timestamp}.pdf"
            self._generate_pdf_report(report_path, include_visualizations)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
        
        print(f"Report generated: {report_path}")
        return str(report_path)
    
    def _generate_html_report(self, report_path: Path, include_visualizations: bool = True):
        """Generate HTML report"""
        # Ensure statistics are up-to-date
        if self.statistics.total_images == 0:
            self.analyze_dataset()
        
        # Create visualizations if requested
        visualizations = ""
        if include_visualizations:
            visualizations = self._create_visualizations()
        
        # HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MetaForensicAI Dataset Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                .stat {{ display: inline-block; margin: 10px 20px 10px 0; padding: 10px; background: #f8f9fa; border-radius: 3px; }}
                .stat-value {{ font-size: 1.5em; font-weight: bold; color: #2980b9; }}
                .stat-label {{ font-size: 0.9em; color: #7f8c8d; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .visualization {{ margin: 20px 0; text-align: center; }}
                img {{ max-width: 100%; height: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>MetaForensicAI Dataset Report</h1>
                <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p>Dataset Version: {self.config.get('dataset', {}).get('version', '1.0.0')}</p>
            </div>
            
            <div class="section">
                <h2>Overview</h2>
                <div class="stat">
                    <div class="stat-value">{self.statistics.total_images:,}</div>
                    <div class="stat-label">Total Images</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{self.statistics.total_size_gb:.2f} GB</div>
                    <div class="stat-label">Total Size</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{len(self.statistics.categories)}</div>
                    <div class="stat-label">Categories</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{len(self.statistics.formats)}</div>
                    <div class="stat-label">File Formats</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Category Distribution</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join([
                            f'<tr><td>{cat}</td><td>{count:,}</td><td>{count/self.statistics.total_images*100:.1f}%</td></tr>'
                            for cat, count in self.statistics.categories.items()
                        ])}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>File Format Distribution</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Format</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join([
                            f'<tr><td>{fmt}</td><td>{count:,}</td><td>{count/self.statistics.total_images*100:.1f}%</td></tr>'
                            for fmt, count in self.statistics.formats.items()
                        ])}
                    </tbody>
                </table>
            </div>
            
            {visualizations}
            
            <div class="section">
                <h2>Metadata Completeness</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Metadata Type</th>
                            <th>Completeness</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join([
                            f'<tr><td>{metadata_type}</td><td>{completeness*100:.1f}%</td></tr>'
                            for metadata_type, completeness in self.statistics.metadata_completeness.items()
                        ])}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Quality Distribution</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Quality Level</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join([
                            f'<tr><td>{level}</td><td>{count:,}</td><td>{count/self.statistics.total_images*100:.1f}%</td></tr>'
                            for level, count in self.statistics.quality_distribution.items()
                        ])}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Date Range</h2>
                <p>Earliest: {self.statistics.date_range[0].strftime('%Y-%m-%d') if isinstance(self.statistics.date_range[0], datetime) else 'N/A'}</p>
                <p>Latest: {self.statistics.date_range[1].strftime('%Y-%m-%d') if isinstance(self.statistics.date_range[1], datetime) else 'N/A'}</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_template)
    
    def _create_visualizations(self) -> str:
        """Create visualization charts and return HTML"""
        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            viz_dir = self.base_path / "reports" / "visualizations"
            viz_dir.mkdir(exist_ok=True)
            
            visualizations_html = "<div class='section'><h2>Visualizations</h2>"
            
            # 1. Category distribution pie chart
            if self.statistics.categories:
                plt.figure(figsize=(10, 6))
                categories = list(self.statistics.categories.keys())
                counts = list(self.statistics.categories.values())
                
                plt.pie(counts, labels=categories, autopct='%1.1f%%', startangle=90)
                plt.axis('equal')
                plt.title('Category Distribution')
                
                pie_chart_path = viz_dir / "category_distribution.png"
                plt.savefig(pie_chart_path, dpi=150, bbox_inches='tight')
                plt.close()
                
                visualizations_html += f"""
                <div class="visualization">
                    <h3>Category Distribution</h3>
                    <img src="{pie_chart_path.relative_to(self.base_path)}" alt="Category Distribution">
                </div>
                """
            
            # 2. Format distribution bar chart
            if self.statistics.formats:
                plt.figure(figsize=(10, 6))
                formats = list(self.statistics.formats.keys())
                counts = list(self.statistics.formats.values())
                
                bars = plt.bar(formats, counts)
                plt.xlabel('File Format')
                plt.ylabel('Count')
                plt.title('File Format Distribution')
                plt.xticks(rotation=45)
                
                # Add value labels on bars
                for bar in bars:
                    height = bar.get_height()
                    plt.text(bar.get_x() + bar.get_width()/2., height,
                            f'{int(height):,}', ha='center', va='bottom')
                
                format_chart_path = viz_dir / "format_distribution.png"
                plt.savefig(format_chart_path, dpi=150, bbox_inches='tight')
                plt.close()
                
                visualizations_html += f"""
                <div class="visualization">
                    <h3>File Format Distribution</h3>
                    <img src="{format_chart_path.relative_to(self.base_path)}" alt="Format Distribution">
                </div>
                """
            
            # 3. Quality distribution bar chart
            if self.statistics.quality_distribution:
                plt.figure(figsize=(10, 6))
                quality_levels = list(self.statistics.quality_distribution.keys())
                counts = list(self.statistics.quality_distribution.values())
                
                bars = plt.bar(quality_levels, counts, color=['#e74c3c', '#f39c12', '#2ecc71', '#27ae60'])
                plt.xlabel('Quality Level')
                plt.ylabel('Count')
                plt.title('Image Quality Distribution')
                
                for bar in bars:
                    height = bar.get_height()
                    plt.text(bar.get_x() + bar.get_width()/2., height,
                            f'{int(height):,}', ha='center', va='bottom')
                
                quality_chart_path = viz_dir / "quality_distribution.png"
                plt.savefig(quality_chart_path, dpi=150, bbox_inches='tight')
                plt.close()
                
                visualizations_html += f"""
                <div class="visualization">
                    <h3>Quality Distribution</h3>
                    <img src="{quality_chart_path.relative_to(self.base_path)}" alt="Quality Distribution">
                </div>
                """
            
            visualizations_html += "</div>"
            return visualizations_html
            
        except ImportError:
            return "<div class='section'><p>Visualizations require matplotlib and seaborn. Install with: pip install matplotlib seaborn</p></div>"
    
    def _generate_json_report(self, report_path: Path):
        """Generate JSON report"""
        # Ensure statistics are up-to-date
        if self.statistics.total_images == 0:
            self.analyze_dataset()
        
        report_data = {
            'report_date': datetime.now().isoformat(),
            'dataset_info': self.config.get('dataset', {}),
            'statistics': asdict(self.statistics),
            'config': self.config
        }
        
        # Convert datetime objects
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, tuple) and len(obj) == 2:
                if isinstance(obj[0], datetime) and isinstance(obj[1], datetime):
                    return (obj[0].isoformat(), obj[1].isoformat())
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=convert_datetime)
    
    def _generate_pdf_report(self, report_path: Path, include_visualizations: bool = True):
        """Generate PDF report"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            
            # Ensure statistics are up-to-date
            if self.statistics.total_images == 0:
                self.analyze_dataset()
            
            # Create document
            doc = SimpleDocTemplate(str(report_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = styles['Heading1']
            title_style.alignment = 1  # Center
            story.append(Paragraph("MetaForensicAI Dataset Report", title_style))
            story.append(Spacer(1, 0.25*inch))
            
            # Date and version
            normal_style = styles['Normal']
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
            story.append(Paragraph(f"Dataset Version: {self.config.get('dataset', {}).get('version', '1.0.0')}", normal_style))
            story.append(Spacer(1, 0.5*inch))
            
            # Overview section
            story.append(Paragraph("Overview", styles['Heading2']))
            
            overview_data = [
                ["Metric", "Value"],
                ["Total Images", f"{self.statistics.total_images:,}"],
                ["Total Size", f"{self.statistics.total_size_gb:.2f} GB"],
                ["Categories", f"{len(self.statistics.categories)}"],
                ["File Formats", f"{len(self.statistics.formats)}"],
            ]
            
            overview_table = Table(overview_data, colWidths=[2*inch, 2*inch])
            overview_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(overview_table)
            story.append(Spacer(1, 0.5*inch))
            
            # Category distribution
            story.append(Paragraph("Category Distribution", styles['Heading2']))
            
            category_data = [["Category", "Count", "Percentage"]]
            for cat, count in self.statistics.categories.items():
                percentage = count / self.statistics.total_images * 100
                category_data.append([cat, f"{count:,}", f"{percentage:.1f}%"])
            
            category_table = Table(category_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            category_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(category_table)
            
            doc.build(story)
            
        except ImportError:
            print("PDF report generation requires reportlab. Install with: pip install reportlab")
            # Fall back to HTML report
            html_path = report_path.with_suffix('.html')
            self._generate_html_report(html_path, include_visualizations)
    
    def create_train_val_split(self,
                              train_ratio: float = 0.7,
                              val_ratio: float = 0.15,
                              test_ratio: float = 0.15,
                              output_dir: str = "split_datasets",
                              random_seed: int = 42) -> Dict:
        """
        Create train/validation/test split
        
        Args:
            train_ratio: Training set ratio
            val_ratio: Validation set ratio
            test_ratio: Test set ratio
            output_dir: Output directory for splits
            random_seed: Random seed for reproducibility
        
        Returns:
            Dictionary with split information
        """
        from sklearn.model_selection import train_test_split
        
        # Validate ratios
        total = train_ratio + val_ratio + test_ratio
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Ratios must sum to 1.0, got {total}")
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        split_info = {
            'total_images': 0,
            'train': 0,
            'val': 0,
            'test': 0,
            'categories': {},
            'config': {
                'train_ratio': train_ratio,
                'val_ratio': val_ratio,
                'test_ratio': test_ratio,
                'random_seed': random_seed
            }
        }
        
        # Process each category
        for category in DatasetCategory:
            category_path = self.base_path / "ground_truth" / category.value
            
            if not category_path.exists():
                continue
            
            # Collect all images in category
            image_files = []
            for ext in ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.tiff', '*.bmp']:
                image_files.extend(category_path.rglob(ext))
                image_files.extend(category_path.rglob(ext.upper()))
            
            if not image_files:
                continue
            
            # Convert to strings for sklearn
            image_paths = [str(f) for f in image_files]
            
            # Create splits
            # First split: train vs (val+test)
            train_paths, temp_paths = train_test_split(
                image_paths,
                test_size=(val_ratio + test_ratio),
                random_state=random_seed,
                shuffle=True,
                stratify=None  # Could implement stratification if needed
            )
            
            # Second split: val vs test
            val_test_ratio = val_ratio / (val_ratio + test_ratio)
            val_paths, test_paths = train_test_split(
                temp_paths,
                test_size=(1 - val_test_ratio),
                random_state=random_seed,
                shuffle=True
            )
            
            # Copy files to split directories
            category_split_info = {
                'total': len(image_paths),
                'train': len(train_paths),
                'val': len(val_paths),
                'test': len(test_paths)
            }
            
            split_info['categories'][category.value] = category_split_info
            split_info['total_images'] += len(image_paths)
            split_info['train'] += len(train_paths)
            split_info['val'] += len(val_paths)
            split_info['test'] += len(test_paths)
            
            # Copy files
            for split_name, paths in [('train', train_paths), ('val', val_paths), ('test', test_paths)]:
                split_category_dir = output_path / split_name / category.value
                split_category_dir.mkdir(parents=True, exist_ok=True)
                
                for src_path in paths:
                    src_path = Path(src_path)
                    dst_path = split_category_dir / src_path.name
                    
                    # Handle duplicates by adding hash
                    counter = 1
                    while dst_path.exists():
                        stem = src_path.stem
                        suffix = src_path.suffix
                        dst_path = split_category_dir / f"{stem}_{counter}{suffix}"
                        counter += 1
                    
                    shutil.copy2(src_path, dst_path)
        
        # Save split information
        split_info_path = output_path / "split_information.json"
        with open(split_info_path, 'w') as f:
            json.dump(split_info, f, indent=2, default=str)
        
        # Create CSV summary
        self._create_split_summary_csv(split_info, output_path)
        
        print(f"Split created in: {output_path}")
        print(f"Train: {split_info['train']} images")
        print(f"Validation: {split_info['val']} images")
        print(f"Test: {split_info['test']} images")
        
        return split_info
    
    def _create_split_summary_csv(self, split_info: Dict, output_path: Path):
        """Create CSV summary of splits"""
        import pandas as pd
        
        rows = []
        for category, info in split_info['categories'].items():
            rows.append({
                'category': category,
                'total': info['total'],
                'train': info['train'],
                'train_pct': info['train'] / info['total'] * 100,
                'val': info['val'],
                'val_pct': info['val'] / info['total'] * 100,
                'test': info['test'],
                'test_pct': info['test'] / info['total'] * 100
            })
        
        df = pd.DataFrame(rows)
        csv_path = output_path / "split_summary.csv"
        df.to_csv(csv_path, index=False)
        
        # Also save as markdown for easy reading
        md_path = output_path / "split_summary.md"
        with open(md_path, 'w') as f:
            f.write("# Dataset Split Summary\n\n")
            f.write(df.to_markdown(index=False))
    
    def export_dataset_info(self, 
                           export_format: str = "json",
                           include_samples: bool = False,
                           sample_count: int = 10) -> str:
        """
        Export dataset information
        
        Args:
            export_format: Export format (json, csv, yaml)
            include_samples: Whether to include sample image info
            sample_count: Number of samples to include
        
        Returns:
            Path to exported file
        """
        export_dir = self.base_path / "exports"
        export_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Prepare export data
        export_data = {
            'export_date': datetime.now().isoformat(),
            'dataset_info': self.config.get('dataset', {}),
            'statistics': asdict(self.statistics) if self.statistics.total_images > 0 else {},
            'categories': list(self.statistics.categories.keys()),
            'file_formats': list(self.statistics.formats.keys())
        }
        
        # Add samples if requested
        if include_samples and not self.metadata_index.empty:
            samples = self.metadata_index.sample(min(sample_count, len(self.metadata_index)))
            export_data['samples'] = samples.to_dict('records')
        
        # Export in requested format
        if export_format == "json":
            export_path = export_dir / f"dataset_export_{timestamp}.json"
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        elif export_format == "csv":
            export_path = export_dir / f"dataset_export_{timestamp}.csv"
            
            # Flatten data for CSV
            flat_data = []
            for category, count in self.statistics.categories.items():
                flat_data.append({
                    'type': 'category',
                    'name': category,
                    'count': count
                })
            
            for fmt, count in self.statistics.formats.items():
                flat_data.append({
                    'type': 'format',
                    'name': fmt,
                    'count': count
                })
            
            df = pd.DataFrame(flat_data)
            df.to_csv(export_path, index=False)
        
        elif export_format == "yaml":
            export_path = export_dir / f"dataset_export_{timestamp}.yaml"
            with open(export_path, 'w') as f:
                yaml.dump(export_data, f, default_flow_style=False)
        
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        print(f"Dataset exported to: {export_path}")
        return str(export_path)
    
    def validate_dataset(self, fix_issues: bool = False) -> Dict:
        """
        Validate the entire dataset
        
        Args:
            fix_issues: Whether to attempt to fix issues
        
        Returns:
            Validation results
        """
        validation_results = {
            'timestamp': datetime.now().isoformat(),
            'total_checked': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'issues': [],
            'summary': {}
        }
        
        print("Validating dataset...")
        
        # Walk through all images
        image_extensions = ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.tiff', '*.bmp']
        
        for category in DatasetCategory:
            category_path = self.base_path / "ground_truth" / category.value
            
            if not category_path.exists():
                continue
            
            category_results = {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0,
                'issues': []
            }
            
            # Collect all images
            image_files = []
            for ext in image_extensions:
                image_files.extend(category_path.rglob(ext))
                image_files.extend(category_path.rglob(ext.upper()))
            
            for image_path in tqdm(image_files, desc=f"Validating {category.value}"):
                validation_results['total_checked'] += 1
                category_results['total'] += 1
                
                # Validate image
                validation = self._validate_image(image_path)
                
                if validation['status'] == 'passed':
                    validation_results['passed'] += 1
                    category_results['passed'] += 1
                elif validation['status'] == 'failed':
                    validation_results['failed'] += 1
                    category_results['failed'] += 1
                    
                    # Record issue
                    issue = {
                        'path': str(image_path),
                        'category': category.value,
                        'errors': validation['errors'],
                        'warnings': validation['warnings']
                    }
                    validation_results['issues'].append(issue)
                    category_results['issues'].append(issue)
                    
                    # Attempt to fix if requested
                    if fix_issues:
                        self._attempt_fix(image_path, validation)
                elif validation['status'] == 'warning':
                    validation_results['warnings'] += 1
                    category_results['warnings'] += 1
            
            validation_results['summary'][category.value] = category_results
        
        # Calculate percentages
        if validation_results['total_checked'] > 0:
            validation_results['pass_rate'] = validation_results['passed'] / validation_results['total_checked'] * 100
            validation_results['fail_rate'] = validation_results['failed'] / validation_results['total_checked'] * 100
            validation_results['warning_rate'] = validation_results['warnings'] / validation_results['total_checked'] * 100
        
        # Save validation results
        validation_path = self.base_path / "reports" / "validation_results.json"
        with open(validation_path, 'w') as f:
            json.dump(validation_results, f, indent=2, default=str)
        
        # Print summary
        print(f"\nValidation Complete:")
        print(f"  Total checked: {validation_results['total_checked']}")
        print(f"  Passed: {validation_results['passed']} ({validation_results.get('pass_rate', 0):.1f}%)")
        print(f"  Failed: {validation_results['failed']} ({validation_results.get('fail_rate', 0):.1f}%)")
        print(f"  Warnings: {validation_results['warnings']} ({validation_results.get('warning_rate', 0):.1f}%)")
        
        if validation_results['issues']:
            print(f"\nIssues found: {len(validation_results['issues'])}")
            for issue in validation_results['issues'][:10]:  # Show first 10
                print(f"  - {issue['path']}: {', '.join(issue['errors'])}")
        
        return validation_results
    
    def _attempt_fix(self, image_path: Path, validation: Dict):
        """Attempt to fix image issues"""
        # This is a basic implementation - can be extended based on specific issues
        try:
            if 'File is empty' in validation['errors']:
                # Cannot fix empty file
                return False
            
            # Try to re-save the image if it's corrupted
            with Image.open(image_path) as img:
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                
                # Save with optimal settings
                temp_path = image_path.with_suffix('.fixed' + image_path.suffix)
                img.save(temp_path, quality=95, optimize=True)
                
                # Replace original if new file is valid
                temp_validation = self._validate_image(temp_path)
                if temp_validation['status'] == 'passed':
                    shutil.move(temp_path, image_path)
                    print(f"  Fixed: {image_path.name}")
                    return True
                else:
                    temp_path.unlink()  # Delete temp file
                    return False
                    
        except Exception as e:
            print(f"  Failed to fix {image_path}: {e}")
            return False
    
    def cleanup_dataset(self, 
                       remove_corrupted: bool = False,
                       remove_duplicates: bool = False,
                       backup: bool = True) -> Dict:
        """
        Clean up the dataset
        
        Args:
            remove_corrupted: Whether to remove corrupted images
            remove_duplicates: Whether to remove duplicate images
            backup: Whether to create backup before cleanup
        
        Returns:
            Cleanup results
        """
        cleanup_results = {
            'timestamp': datetime.now().isoformat(),
            'backup_created': False,
            'corrupted_removed': 0,
            'duplicates_removed': 0,
            'total_space_freed': 0,
            'removed_files': []
        }
        
        # Create backup if requested
        if backup:
            backup_path = self._create_backup()
            if backup_path:
                cleanup_results['backup_created'] = True
                cleanup_results['backup_path'] = str(backup_path)
        
        # Remove corrupted images
        if remove_corrupted:
            corrupted_files = self._find_corrupted_images()
            for file_path in corrupted_files:
                file_size = file_path.stat().st_size
                file_path.unlink()
                cleanup_results['corrupted_removed'] += 1
                cleanup_results['total_space_freed'] += file_size
                cleanup_results['removed_files'].append(str(file_path))
        
        # Remove duplicates
        if remove_duplicates:
            duplicate_groups = self._find_duplicate_images()
            for group in duplicate_groups:
                # Keep first file, remove others
                for file_path in group[1:]:
                    file_size = file_path.stat().st_size
                    file_path.unlink()
                    cleanup_results['duplicates_removed'] += 1
                    cleanup_results['total_space_freed'] += file_size
                    cleanup_results['removed_files'].append(str(file_path))
        
        # Update metadata index
        self._rebuild_metadata_index()
        
        # Convert bytes to GB
        cleanup_results['total_space_freed_gb'] = \
            cleanup_results['total_space_freed'] / (1024**3)
        
        # Save cleanup results
        cleanup_path = self.base_path / "reports" / "cleanup_results.json"
        with open(cleanup_path, 'w') as f:
            json.dump(cleanup_results, f, indent=2)
        
        print(f"\nCleanup Complete:")
        print(f"  Corrupted removed: {cleanup_results['corrupted_removed']}")
        print(f"  Duplicates removed: {cleanup_results['duplicates_removed']}")
        print(f"  Space freed: {cleanup_results['total_space_freed_gb']:.2f} GB")
        
        return cleanup_results
    
    def _create_backup(self) -> Optional[Path]:
        """Create backup of dataset"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(f"datasets_backup_{timestamp}.zip")
            
            import zipfile
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in self.base_path.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(self.base_path.parent)
                        zipf.write(file_path, arcname)
            
            print(f"Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            print(f"Failed to create backup: {e}")
            return None
    
    def _find_corrupted_images(self) -> List[Path]:
        """Find corrupted images"""
        corrupted = []
        
        image_extensions = ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.tiff', '*.bmp']
        
        for ext in image_extensions:
            for image_path in self.base_path.rglob(ext):
                validation = self._validate_image(image_path)
                if validation['status'] == 'failed':
                    corrupted.append(image_path)
        
        return corrupted
    
    def _find_duplicate_images(self) -> List[List[Path]]:
        """Find duplicate images using perceptual hashing"""
        try:
            import imagehash
            
            hash_dict = {}
            
            # Collect all images and their hashes
            image_extensions = ['*.jpg', '*.jpeg', '*.png', '*.webp']
            
            for ext in image_extensions:
                for image_path in tqdm(self.base_path.rglob(ext), desc="Hashing images"):
                    try:
                        with Image.open(image_path) as img:
                            # Use average hash for speed
                            img_hash = imagehash.average_hash(img)
                            hash_str = str(img_hash)
                            
                            if hash_str not in hash_dict:
                                hash_dict[hash_str] = []
                            hash_dict[hash_str].append(image_path)
                    except:
                        continue
            
            # Find groups with more than one image
            duplicate_groups = [group for group in hash_dict.values() if len(group) > 1]
            
            return duplicate_groups
            
        except ImportError:
            print("Duplicate detection requires imagehash. Install with: pip install imagehash")
            return []
    
    def _rebuild_metadata_index(self):
        """Rebuild metadata index from scratch"""
        print("Rebuilding metadata index...")
        
        # Clear existing index
        self.metadata_index = pd.DataFrame()
        
        # Walk through all images and extract metadata
        image_extensions = ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.tiff', '*.bmp']
        
        for ext in image_extensions:
            for image_path in tqdm(self.base_path.rglob(ext), desc="Processing images"):
                try:
                    # Determine category and subcategory from path
                    rel_path = image_path.relative_to(self.base_path)
                    parts = rel_path.parts
                    
                    if len(parts) >= 3 and parts[0] == "ground_truth":
                        category = parts[1]
                        subcategory = parts[2] if len(parts) > 2 else ""
                        source = parts[3] if len(parts) > 3 else ""
                        
                        # Extract metadata
                        metadata = self._extract_image_metadata(
                            image_path, category, subcategory, source
                        )
                        
                        # Update index
                        self._update_metadata_index(metadata)
                except:
                    continue
        
        print(f"Metadata index rebuilt with {len(self.metadata_index)} entries")
    
    def get_dataset_info(self) -> Dict:
        """
        Get comprehensive dataset information
        
        Returns:
            Dataset information dictionary
        """
        # Ensure statistics are up-to-date
        if self.statistics.total_images == 0:
            self.analyze_dataset()
        
        info = {
            'dataset': self.config.get('dataset', {}),
            'statistics': asdict(self.statistics),
            'categories': {
                cat: {
                    'count': count,
                    'percentage': count / self.statistics.total_images * 100
                }
                for cat, count in self.statistics.categories.items()
            },
            'metadata_index_size': len(self.metadata_index),
            'config_path': str(self.config_path),
            'base_path': str(self.base_path)
        }
        
        return info
    
    def print_summary(self):
        """Print dataset summary"""
        info = self.get_dataset_info()
        
        print("\n" + "="*60)
        print("META FORENSIC AI DATASET SUMMARY")
        print("="*60)
        
        print(f"\nDataset: {info['dataset'].get('name', 'Unknown')}")
        print(f"Version: {info['dataset'].get('version', 'Unknown')}")
        print(f"Location: {info['base_path']}")
        
        print(f"\n📊 Statistics:")
        print(f"  Total Images: {info['statistics']['total_images']:,}")
        print(f"  Total Size: {info['statistics']['total_size_gb']:.2f} GB")
        print(f"  Categories: {len(info['statistics']['categories'])}")
        print(f"  File Formats: {len(info['statistics']['formats'])}")
        
        print(f"\n📁 Categories:")
        for category, stats in info['categories'].items():
            print(f"  {category}: {stats['count']:,} ({stats['percentage']:.1f}%)")
        
        print(f"\n📄 File Formats:")
        for fmt, count in info['statistics']['formats'].items():
            percentage = count / info['statistics']['total_images'] * 100
            print(f"  {fmt}: {count:,} ({percentage:.1f}%)")
        
        print(f"\n📈 Metadata:")
        print(f"  Index Size: {info['metadata_index_size']:,} entries")
        for metadata_type, completeness in info['statistics']['metadata_completeness'].items():
            print(f"  {metadata_type}: {completeness*100:.1f}% complete")
        
        print(f"\n📅 Date Range:")
        date_range = info['statistics']['date_range']
        if isinstance(date_range[0], str) and isinstance(date_range[1], str):
            print(f"  From: {date_range[0]}")
            print(f"  To: {date_range[1]}")
        
        print("\n" + "="*60)


# Command-line interface
def main():
    """Command-line interface for dataset management"""
    import argparse
    
    parser = argparse.ArgumentParser(description="MetaForensicAI Dataset Manager")
    parser.add_argument("--base-path", default="datasets", help="Dataset base path")
    parser.add_argument("--config", help="Configuration file path")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Initialize command
    init_parser = subparsers.add_parser("init", help="Initialize dataset structure")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze dataset")
    analyze_parser.add_argument("--update", action="store_true", help="Update statistics")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate dataset report")
    report_parser.add_argument("--format", choices=["html", "json", "pdf"], default="html")
    report_parser.add_argument("--no-vis", action="store_true", help="Skip visualizations")
    
    # Split command
    split_parser = subparsers.add_parser("split", help="Create train/val/test split")
    split_parser.add_argument("--train", type=float, default=0.7, help="Training ratio")
    split_parser.add_argument("--val", type=float, default=0.15, help="Validation ratio")
    split_parser.add_argument("--test", type=float, default=0.15, help="Test ratio")
    split_parser.add_argument("--output", default="split_datasets", help="Output directory")
    split_parser.add_argument("--seed", type=int, default=42, help="Random seed")
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate dataset")
    validate_parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up dataset")
    cleanup_parser.add_argument("--corrupted", action="store_true", help="Remove corrupted images")
    cleanup_parser.add_argument("--duplicates", action="store_true", help="Remove duplicates")
    cleanup_parser.add_argument("--no-backup", action="store_true", help="Skip backup")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export dataset info")
    export_parser.add_argument("--format", choices=["json", "csv", "yaml"], default="json")
    export_parser.add_argument("--samples", type=int, default=0, help="Include sample images")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show dataset information")
    
    # Add image command
    add_parser = subparsers.add_parser("add", help="Add image to dataset")
    add_parser.add_argument("image", help="Path to image file")
    add_parser.add_argument("--category", required=True, help="Category (original_camera, social_media, etc.)")
    add_parser.add_argument("--subcategory", required=True, help="Subcategory")
    add_parser.add_argument("--source", required=True, help="Source description")
    add_parser.add_argument("--move", action="store_true", help="Move instead of copy")
    add_parser.add_argument("--no-validate", action="store_true", help="Skip validation")
    
    args = parser.parse_args()
    
    # Initialize dataset manager
    manager = ForensicDatasetManager(base_path=args.base_path, config_path=args.config)
    
    if args.command == "init":
        print("Dataset structure initialized.")
        
    elif args.command == "analyze":
        stats = manager.analyze_dataset(update_statistics=args.update)
        print(f"Analysis complete. Total images: {stats.total_images:,}")
        
    elif args.command == "report":
        report_path = manager.generate_report(
            output_format=args.format,
            include_visualizations=not args.no_vis
        )
        print(f"Report generated: {report_path}")
        
    elif args.command == "split":
        split_info = manager.create_train_val_split(
            train_ratio=args.train,
            val_ratio=args.val,
            test_ratio=args.test,
            output_dir=args.output,
            random_seed=args.seed
        )
        print(f"Split created with {split_info['total_images']:,} images")
        
    elif args.command == "validate":
        results = manager.validate_dataset(fix_issues=args.fix)
        print(f"Validation complete. Pass rate: {results.get('pass_rate', 0):.1f}%")
        
    elif args.command == "cleanup":
        results = manager.cleanup_dataset(
            remove_corrupted=args.corrupted,
            remove_duplicates=args.duplicates,
            backup=not args.no_backup
        )
        print(f"Cleanup complete. Space freed: {results['total_space_freed_gb']:.2f} GB")
        
    elif args.command == "export":
        export_path = manager.export_dataset_info(
            export_format=args.format,
            include_samples=args.samples > 0,
            sample_count=args.samples
        )
        print(f"Export complete: {export_path}")
        
    elif args.command == "info":
        manager.print_summary()
        
    elif args.command == "add":
        metadata = manager.add_image(
            image_path=args.image,
            category=args.category,
            subcategory=args.subcategory,
            source=args.source,
            copy_file=not args.move,
            validate=not args.no_validate
        )
        if metadata:
            print(f"Image added: {metadata.filename}")
        else:
            print("Failed to add image")
            
    else:
        parser.print_help()


if __name__ == "__main__":
    main()