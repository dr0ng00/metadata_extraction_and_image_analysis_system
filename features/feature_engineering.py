"""
feature_engineering.py

Enhanced module for converting forensic analysis results into
numerical features for machine learning and statistical analysis.

This module:
1. Extracts comprehensive feature sets from forensic analysis
2. Normalizes features for ML model compatibility
3. Provides feature importance indicators
4. Supports multiple feature extraction strategies

This module DOES NOT perform detection.
It only REPRESENTS results numerically.
"""

import numpy as np
from datetime import datetime
import re
from collections import Counter


# --------------------------------------------------
# Feature Engineering Core Function
# --------------------------------------------------

def extract_features_from_analysis(analysis_result, feature_set='full'):
    """
    Convert forensic analysis output into a numeric feature set.
    
    Args:
        analysis_result (dict): Output from forensic analysis pipeline
        feature_set (str): Feature extraction strategy:
            - 'minimal': Core suspicion features only
            - 'standard': Most commonly used features (default)
            - 'full': All available features including advanced metrics
            - 'research': Extended features for research purposes
    
    Returns:
        dict: Numeric feature vector with normalized values
    """
    
    features = {}
    
    # --------------------------------------------------
    # 1. BASIC SUSPICION METRICS
    # --------------------------------------------------
    
    suspicion_score = analysis_result.get("suspicion_score", 0)
    features["suspicion_score"] = float(suspicion_score)
    
    # Enhanced suspicion level encoding
    suspicion_level = analysis_result.get("suspicion_level", "Low").lower()
    level_mapping = {
        'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4
    }
    features["suspicion_level_numeric"] = level_mapping.get(suspicion_level, 1)
    
    # Suspicion confidence (if available)
    suspicion_confidence = analysis_result.get("suspicion_confidence", 0.5)
    features["suspicion_confidence"] = float(suspicion_confidence)
    
    # --------------------------------------------------
    # 2. FORENSIC FLAGS QUANTIFICATION
    # --------------------------------------------------
    
    flags = analysis_result.get("forensic_flags", [])
    features["num_forensic_flags"] = len(flags)
    
    # Initialize detailed flag categories
    flag_categories = {
        "software_edit": 0,
        "timestamp": 0,
        "gps": 0,
        "compression": 0,
        "camera": 0,
        "metadata": 0,
        "compression_cycle": 0,
        "noise_pattern": 0,
        "ela": 0,
        "format": 0,
        "signature": 0,
        "unknown": 0
    }
    
    # Flag confidence scores
    flag_confidence_sum = 0
    flag_high_confidence = 0
    
    # Enhanced flag categorization with confidence
    for flag in flags:
        flag_text = ""
        confidence = 0.5  # Default confidence
        
        if isinstance(flag, dict):
            flag_text = (str(flag.get('type', '')) + ' ' + 
                        str(flag.get('description', ''))).lower()
            confidence = float(flag.get('confidence', 0.5))
        else:
            flag_text = str(flag).lower()
        
        # Update confidence metrics
        flag_confidence_sum += confidence
        if confidence > 0.7:
            flag_high_confidence += 1
        
        # Categorize flags
        categorized = False
        
        # Software editing flags
        if any(keyword in flag_text for keyword in 
               ['software', 'editor', 'photoshop', 'gimp', 'lightroom', 'edited']):
            flag_categories["software_edit"] += 1
            categorized = True
        
        # Timestamp flags
        if any(keyword in flag_text for keyword in 
               ['timestamp', 'chrono', 'time', 'date', 'datetime', 'inconsistent']):
            flag_categories["timestamp"] += 1
            categorized = True
        
        # GPS flags
        if any(keyword in flag_text for keyword in 
               ['gps', 'location', 'geotag', 'coordinates', 'geolocation']):
            flag_categories["gps"] += 1
            categorized = True
        
        # Compression flags
        if any(keyword in flag_text for keyword in 
               ['compression', 'jpeg', 'quality', 'quantization', 'double compress']):
            flag_categories["compression"] += 1
            categorized = True
        
        # Camera flags
        if any(keyword in flag_text for keyword in 
               ['camera', 'resolution', 'sensor', 'lens', 'make', 'model']):
            flag_categories["camera"] += 1
            categorized = True
        
        # Metadata flags
        if any(keyword in flag_text for keyword in 
               ['metadata', 'exif', 'header', 'iptc', 'xmp']):
            flag_categories["metadata"] += 1
            categorized = True
        
        # Compression cycle flags
        if any(keyword in flag_text for keyword in 
               ['cycle', 'multiple compress', 'recompress']):
            flag_categories["compression_cycle"] += 1
            categorized = True
        
        # Noise pattern flags
        if any(keyword in flag_text for keyword in 
               ['noise', 'pattern', 'smooth', 'uniform']):
            flag_categories["noise_pattern"] += 1
            categorized = True
        
        # ELA flags
        if 'ela' in flag_text or 'error level' in flag_text:
            flag_categories["ela"] += 1
            categorized = True
        
        # Format flags
        if any(keyword in flag_text for keyword in 
               ['format', 'extension', 'mime', 'file type']):
            flag_categories["format"] += 1
            categorized = True
        
        # Signature flags
        if any(keyword in flag_text for keyword in 
               ['signature', 'hash', 'fingerprint', 'digital signature']):
            flag_categories["signature"] += 1
            categorized = True
        
        if not categorized:
            flag_categories["unknown"] += 1
    
    # Add flag category features
    for category, count in flag_categories.items():
        features[f"flags_{category}"] = count
    
    # Add flag confidence features
    if flags:
        features["avg_flag_confidence"] = flag_confidence_sum / len(flags)
        features["high_confidence_flags_ratio"] = flag_high_confidence / len(flags)
    else:
        features["avg_flag_confidence"] = 0.0
        features["high_confidence_flags_ratio"] = 0.0
    
    # --------------------------------------------------
    # 3. METADATA COMPREHENSIVE ANALYSIS
    # --------------------------------------------------
    
    meta = analysis_result.get("normalized_metadata", {})
    
    # Basic metadata presence indicators
    metadata_presence = {
        "has_gps": 1 if meta.get("GPSInfo") else 0,
        "has_software": 1 if meta.get("Software") else 0,
        "has_camera_make": 1 if meta.get("Make") else 0,
        "has_camera_model": 1 if meta.get("Model") else 0,
        "has_lens_info": 1 if meta.get("LensModel") else 0,
        "has_exposure_info": 1 if any(k in meta for k in ['ExposureTime', 'FNumber', 'ISOSpeedRatings']) else 0,
        "has_flash_info": 1 if meta.get("Flash") else 0,
        "has_author": 1 if meta.get("Author") or meta.get("Artist") else 0,
        "has_copyright": 1 if meta.get("Copyright") else 0,
    }
    
    for key, value in metadata_presence.items():
        features[key] = value
    
    # Metadata completeness score
    metadata_fields = ['Make', 'Model', 'DateTimeOriginal', 'Software', 'LensModel']
    present_fields = sum(1 for field in metadata_fields if meta.get(field))
    features["metadata_completeness"] = present_fields / len(metadata_fields)
    
    # --------------------------------------------------
    # 4. ADVANCED TIMESTAMP ANALYSIS
    # --------------------------------------------------
    
    timestamps = meta.get("Timestamps", {})
    features["num_timestamps"] = len(timestamps)
    
    # Parse timestamps for advanced features
    parsed_timestamps = []
    timestamp_formats = []
    
    for ts_key, ts_value in timestamps.items():
        if ts_value:
            # Extract timestamp format features
            if isinstance(ts_value, str):
                # Check for common formats
                if re.match(r'\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}', ts_value):
                    timestamp_formats.append('standard_exif')
                elif 'T' in ts_value:
                    timestamp_formats.append('iso8601')
                elif '/' in ts_value:
                    timestamp_formats.append('date_slash')
                else:
                    timestamp_formats.append('other')
    
    # Timestamp consistency features
    features["timestamp_format_consistency"] = (
        1.0 if len(set(timestamp_formats)) <= 1 else 0.0
    )
    
    # --------------------------------------------------
    # 5. IMAGE PROPERTIES QUANTIFICATION
    # --------------------------------------------------
    
    # Resolution features
    resolution = meta.get("Resolution")
    megapixels = meta.get("Megapixels")
    
    if megapixels:
        features["megapixels"] = float(megapixels)
        # Resolution categories
        if megapixels < 2:
            features["resolution_category"] = 0  # Very low
        elif megapixels < 8:
            features["resolution_category"] = 1  # Low
        elif megapixels < 16:
            features["resolution_category"] = 2  # Medium
        elif megapixels < 32:
            features["resolution_category"] = 3  # High
        else:
            features["resolution_category"] = 4  # Very high
    else:
        features["megapixels"] = 0.0
        features["resolution_category"] = -1  # Unknown
    
    # Aspect ratio if available
    if resolution and '×' in str(resolution):
        try:
            width, height = map(int, str(resolution).split('×'))
            features["aspect_ratio"] = width / height if height > 0 else 0
        except:
            features["aspect_ratio"] = 0.0
    else:
        features["aspect_ratio"] = 0.0
    
    # --------------------------------------------------
    # 6. FORENSIC INSIGHTS METRICS
    # --------------------------------------------------
    
    insights = analysis_result.get("forensic_insights", {})
    
    # Extract numeric insights
    insight_features = {
        "exif_completeness": insights.get("exif_completeness", 0.0),
        "jpeg_quality": insights.get("estimated_quality", 0.0),
        "compression_level": insights.get("compression_level", 0.0),
        "noise_consistency": insights.get("noise_consistency", 0.0),
        "ela_score": insights.get("ela_score", 0.0),
        "error_level_variance": insights.get("error_level_variance", 0.0),
    }
    
    for key, value in insight_features.items():
        features[key] = float(value)
    
    # --------------------------------------------------
    # 7. STATISTICAL ANALYSIS FEATURES
    # --------------------------------------------------
    
    stats = analysis_result.get("statistical_analysis", {})
    
    if stats:
        for stat_key, stat_value in stats.items():
            if isinstance(stat_value, (int, float)):
                features[f"stat_{stat_key}"] = float(stat_value)
    
    # --------------------------------------------------
    # 8. ADVANCED FEATURES (Full/Research sets only)
    # --------------------------------------------------
    
    if feature_set in ['full', 'research']:
        # Camera brand encoding
        camera_make = str(meta.get("Make", "")).lower()
        common_brands = ['canon', 'nikon', 'sony', 'fujifilm', 'panasonic', 
                        'olympus', 'leica', 'pentax', 'samsung', 'apple', 
                        'huawei', 'xiaomi', 'google', 'oneplus']
        
        for brand in common_brands:
            features[f"camera_brand_{brand}"] = 1.0 if brand in camera_make else 0.0
        
        # Software detection
        software = str(meta.get("Software", "")).lower()
        editing_software = ['photoshop', 'gimp', 'lightroom', 'affinity', 
                           'paint.net', 'pixelmator', 'corel', 'capture']
        
        for sw in editing_software:
            features[f"software_{sw}"] = 1.0 if sw in software else 0.0
        
        # Flag severity weighting
        severity_mapping = {
            'software_edit': 1.0,
            'compression_cycle': 0.8,
            'timestamp': 0.7,
            'ela': 0.6,
            'noise_pattern': 0.5,
            'gps': 0.4,
            'camera': 0.3,
            'metadata': 0.2,
            'format': 0.1
        }
        
        weighted_severity = sum(
            flag_categories[cat] * severity_mapping.get(cat, 0.1)
            for cat in flag_categories
        )
        features["weighted_flag_severity"] = weighted_severity
        
        # Time-based features (if research set)
        if feature_set == 'research':
            # Extract year from timestamps for temporal analysis
            years = []
            for ts_value in timestamps.values():
                if isinstance(ts_value, str):
                    year_match = re.search(r'(\d{4})', ts_value)
                    if year_match:
                        years.append(int(year_match.group(1)))
            
            if years:
                features["min_year"] = min(years)
                features["max_year"] = max(years)
                features["year_range"] = features["max_year"] - features["min_year"]
            
            # File type analysis
            file_format = str(meta.get("FileFormat", "")).lower()
            common_formats = ['jpeg', 'png', 'tiff', 'bmp', 'gif', 'raw', 'heic', 'webp']
            for fmt in common_formats:
                features[f"format_{fmt}"] = 1.0 if fmt in file_format else 0.0
    
    # --------------------------------------------------
    # 9. FEATURE NORMALIZATION & VALIDATION
    # --------------------------------------------------
    
    # Ensure all values are numeric and within reasonable bounds
    for key in list(features.keys()):
        value = features[key]
        
        try:
            # Convert to float
            float_value = float(value)
            
            # Clip extreme values (for ML stability)
            if key.endswith('_score') or key.endswith('_confidence'):
                float_value = np.clip(float_value, 0.0, 1.0)
            elif key == 'megapixels':
                float_value = np.clip(float_value, 0.0, 200.0)  # Reasonable max
            elif key == 'suspicion_score':
                float_value = np.clip(float_value, 0.0, 100.0)
            
            features[key] = float_value
            
        except (ValueError, TypeError):
            # If conversion fails, use 0.0 for numeric features
            features[key] = 0.0
    
    # Add feature metadata
    features["_feature_set"] = feature_set
    features["_feature_count"] = len(features)
    features["_extraction_timestamp"] = datetime.now().isoformat()
    
    return features


# --------------------------------------------------
# Feature Selection and Subset Functions
# --------------------------------------------------

def select_feature_subset(features, subset_name='standard'):
    """
    Select specific feature subsets for different use cases.
    
    Args:
        features (dict): Full feature dictionary
        subset_name (str): Subset to select:
            - 'minimal': Core features only (5-10 features)
            - 'standard': Balanced set for general ML (15-25 features)
            - 'flags_only': Forensic flag features only
            - 'metadata_only': Metadata-based features only
            - 'advanced': Advanced features excluding research-only
    
    Returns:
        dict: Selected feature subset
    """
    
    # Define feature subsets
    subsets = {
        'minimal': [
            'suspicion_score',
            'suspicion_level_numeric',
            'num_forensic_flags',
            'flags_software_edit',
            'metadata_completeness',
            'has_software',
            'has_camera_make',
            'has_camera_model',
        ],
        
        'standard': [
            'suspicion_score',
            'suspicion_level_numeric',
            'num_forensic_flags',
            'flags_software_edit',
            'flags_timestamp',
            'flags_compression',
            'flags_gps',
            'metadata_completeness',
            'has_software',
            'has_gps',
            'has_camera_make',
            'has_camera_model',
            'num_timestamps',
            'timestamp_format_consistency',
            'megapixels',
            'exif_completeness',
            'jpeg_quality',
            'avg_flag_confidence',
        ],
        
        'flags_only': [
            k for k in features.keys() 
            if k.startswith('flags_') or k.startswith('num_forensic')
        ],
        
        'metadata_only': [
            k for k in features.keys() 
            if k.startswith('has_') or 'completeness' in k or 'timestamp' in k
        ],
        
        'advanced': [
            k for k in features.keys() 
            if not k.startswith('_') and 
            not k.startswith('camera_brand_') and 
            not k.startswith('software_') and
            not k.startswith('format_')
        ]
    }
    
    # Get the requested subset or default to all non-metadata features
    if subset_name in subsets:
        selected_keys = subsets[subset_name]
    else:
        # Default: all features except metadata
        selected_keys = [k for k in features.keys() if not k.startswith('_')]
    
    # Create subset dictionary
    subset = {k: features.get(k, 0.0) for k in selected_keys}
    subset['_subset'] = subset_name
    
    return subset


def get_feature_statistics(features):
    """
    Calculate basic statistics for feature validation.
    
    Args:
        features (dict): Feature dictionary
    
    Returns:
        dict: Feature statistics
    """
    numeric_values = []
    for v in features.values():
        if isinstance(v, (int, float)):
            numeric_values.append(v)
    
    if numeric_values:
        stats = {
            'count': len(numeric_values),
            'mean': np.mean(numeric_values),
            'std': np.std(numeric_values),
            'min': np.min(numeric_values),
            'max': np.max(numeric_values),
            'nan_count': sum(np.isnan(v) for v in numeric_values),
            'zero_count': sum(v == 0 for v in numeric_values),
        }
    else:
        stats = {}
    
    return stats


# --------------------------------------------------
# Feature Export Functions
# --------------------------------------------------

def features_to_array(features, feature_order=None):
    """
    Convert feature dictionary to numpy array for ML.
    
    Args:
        features (dict): Feature dictionary
        feature_order (list): Order of features in array
    
    Returns:
        numpy.ndarray: Feature array
    """
    # Remove metadata features
    clean_features = {k: v for k, v in features.items() if not k.startswith('_')}
    
    if feature_order:
        # Use specified order
        array = np.array([clean_features.get(k, 0.0) for k in feature_order])
    else:
        # Use alphabetical order for consistency
        sorted_keys = sorted(clean_features.keys())
        array = np.array([clean_features[k] for k in sorted_keys])
    
    return array


def features_to_dataframe_row(features, row_id=None):
    """
    Convert features to pandas-compatible dictionary (for DataFrame).
    
    Args:
        features (dict): Feature dictionary
        row_id: Optional identifier for the row
    
    Returns:
        dict: DataFrame-compatible row
    """
    # Create copy without metadata
    row = {k: v for k, v in features.items() if not k.startswith('_')}
    
    if row_id is not None:
        row['id'] = row_id
    
    return row


# --------------------------------------------------
# Example Usage and Testing
# --------------------------------------------------

def example_usage():
    """
    Demonstrates the enhanced feature engineering capabilities.
    """
    
    # Sample analysis result (simplified for example)
    sample_analysis = {
        "suspicion_score": 65,
        "suspicion_level": "Medium",
        "suspicion_confidence": 0.75,
        "forensic_flags": [
            {
                "type": "Software Editing",
                "description": "Adobe Photoshop signature detected",
                "confidence": 0.9
            },
            {
                "type": "Timestamp Inconsistency",
                "description": "Modified timestamp differs from original",
                "confidence": 0.7
            },
            {
                "type": "Compression Anomaly",
                "description": "Multiple JPEG compression cycles",
                "confidence": 0.6
            }
        ],
        "normalized_metadata": {
            "Make": "Canon",
            "Model": "EOS 5D Mark IV",
            "Software": "Adobe Photoshop 24.0",
            "GPSInfo": {
                "Latitude": "40.7128° N",
                "Longitude": "74.0060° W"
            },
            "Megapixels": 30.4,
            "Resolution": "6720 × 4480",
            "LensModel": "EF24-70mm f/2.8L II USM",
            "Timestamps": {
                "Original": "2023:10:15 14:30:25",
                "Digitized": "2023:10:15 14:30:25",
                "Modified": "2023:10:16 09:15:42"
            }
        },
        "forensic_insights": {
            "exif_completeness": 0.85,
            "estimated_quality": 92,
            "compression_level": 0.75,
            "ela_score": 0.62
        },
        "statistical_analysis": {
            "ErrorLevelConsistency": 0.8723,
            "NoisePatternDeviation": 0.1542
        }
    }
    
    print("=== ENHANCED FEATURE ENGINEERING DEMO ===\n")
    
    # Test different feature sets
    for feature_set in ['minimal', 'standard', 'full', 'research']:
        print(f"\n--- {feature_set.upper()} Feature Set ---")
        features = extract_features_from_analysis(sample_analysis, feature_set)
        
        print(f"Total features extracted: {features['_feature_count']}")
        
        # Show some key features
        key_features = ['suspicion_score', 'num_forensic_flags', 
                       'flags_software_edit', 'metadata_completeness']
        
        for kf in key_features:
            if kf in features:
                print(f"{kf:30}: {features[kf]:.4f}")
        
        # Get feature subset
        if feature_set == 'full':
            subset = select_feature_subset(features, 'standard')
            print(f"\nStandard subset features: {len(subset)}")
    
    # Demonstrate feature statistics
    print("\n=== FEATURE STATISTICS ===")
    full_features = extract_features_from_analysis(sample_analysis, 'full')
    stats = get_feature_statistics(full_features)
    
    for stat_name, stat_value in stats.items():
        print(f"{stat_name:15}: {stat_value:.4f}")
    
    # Demonstrate array conversion
    print("\n=== ARRAY CONVERSION ===")
    feature_array = features_to_array(full_features)
    print(f"Array shape: {feature_array.shape}")
    print(f"First 10 values: {feature_array[:10]}")


def batch_feature_extraction(analysis_results):
    """
    Example function for batch processing multiple analysis results.
    
    Args:
        analysis_results (list): List of analysis result dictionaries
    
    Returns:
        list: List of feature dictionaries
    """
    all_features = []
    
    for i, result in enumerate(analysis_results):
        try:
            features = extract_features_from_analysis(result, 'standard')
            features['_sample_id'] = i
            all_features.append(features)
        except Exception as e:
            print(f"Error processing sample {i}: {e}")
            # Add placeholder features for error cases
            error_features = {
                'suspicion_score': 0.0,
                'num_forensic_flags': 0.0,
                'metadata_completeness': 0.0,
                '_sample_id': i,
                '_error': str(e)
            }
            all_features.append(error_features)
    
    return all_features


if __name__ == "__main__":
    example_usage()