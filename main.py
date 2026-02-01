"""
main.py

Enhanced central execution pipeline for the
Metadata Extraction and Image Analysis System.

Pipeline order:
1. EXIF / metadata extraction
2. Metadata normalization
3. Pixel-level image forensic analysis
4. Forensic scoring with advanced rules
5. Feature engineering for ML
6. Forensic report generation
7. Unified result output (JSON, CSV, database)

AI/ML will be added AFTER this file.
"""

import os
import sys
import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import traceback

# -------------------------------
# Import project modules
# -------------------------------

# Import with error handling
try:
    from extractor.exif_extractor import extract_metadata
    from preprocessing.normalizer import normalize_metadata
    from image_analysis.image_features import extract_image_features, batch_image_feature_extraction
    from features.feature_engineering import extract_features_from_analysis, select_feature_subset
    from reports.forensic_report import generate_forensic_report
except ImportError as e:
    print(f"[ERROR] Failed to import modules: {e}")
    print("Please ensure all required modules are installed and in the Python path.")
    sys.exit(1)


# -------------------------------
# Configuration
# -------------------------------

class Config:
    """Configuration class for the forensic pipeline."""
    
    # Directories
    OUTPUT_DIR = "data/output"
    REPORT_DIR = "data/reports"
    LOG_DIR = "data/logs"
    DATABASE_DIR = "data/database"
    
    # Processing options
    ENABLE_ADVANCED_FEATURES = True
    GENERATE_REPORTS = True
    SAVE_JSON_OUTPUT = True
    SAVE_CSV_OUTPUT = True
    SAVE_DATABASE = True
    
    # Forensic scoring thresholds
    BLUR_THRESHOLD = 0.5
    ELA_EDIT_THRESHOLD = 0.1
    DOUBLE_COMPRESSION_THRESHOLD = 0.5
    NOISE_INCONSISTENCY_THRESHOLD = 0.3
    
    # Feature engineering
    FEATURE_SET = "full"  # 'minimal', 'standard', 'full', 'research'
    ML_FEATURE_SUBSET = "standard"  # For ML models
    
    # Logging
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    @classmethod
    def setup_directories(cls):
        """Create all required directories."""
        dirs = [cls.OUTPUT_DIR, cls.REPORT_DIR, cls.LOG_DIR, cls.DATABASE_DIR]
        for directory in dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        print(f"[✓] Directories created: {', '.join(dirs)}")


# -------------------------------
# Logging Setup
# -------------------------------

def setup_logging():
    """Configure logging for the forensic pipeline."""
    Config.setup_directories()
    
    log_file = os.path.join(Config.LOG_DIR, f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format=Config.LOG_FORMAT,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Forensic pipeline logging initialized")
    logger.info(f"Log file: {log_file}")
    
    return logger


logger = setup_logging()


# -------------------------------
# Forensic Scoring Engine
# -------------------------------

class ForensicScoringEngine:
    """Advanced forensic scoring with weighted rules and confidence."""
    
    RULES = {
        'blur_detected': {
            'weight': 0.15,
            'description': 'Image appears blurry',
            'confidence_threshold': 0.5
        },
        'double_compression': {
            'weight': 0.25,
            'description': 'Possible double JPEG compression',
            'confidence_threshold': 0.5
        },
        'ela_edits': {
            'weight': 0.30,
            'description': 'ELA indicates potential edited regions',
            'confidence_threshold': 0.6
        },
        'noise_inconsistency': {
            'weight': 0.15,
            'description': 'Noise pattern inconsistency',
            'confidence_threshold': 0.4
        },
        'metadata_inconsistency': {
            'weight': 0.10,
            'description': 'Metadata anomalies',
            'confidence_threshold': 0.3
        },
        'software_signatures': {
            'weight': 0.05,
            'description': 'Editing software signatures detected',
            'confidence_threshold': 0.7
        }
    }
    
    @classmethod
    def calculate_suspicion_score(cls, image_features: Dict, metadata: Dict) -> Dict:
        """
        Calculate forensic suspicion score with advanced rules.
        
        Returns:
            Dict containing score, level, flags, and detailed breakdown
        """
        flags = []
        score_breakdown = {}
        total_score = 0
        
        # Rule 1: Blur detection
        if image_features.get('is_blurry', 0):
            blur_confidence = image_features.get('blur_confidence', 0.5)
            if blur_confidence >= cls.RULES['blur_detected']['confidence_threshold']:
                score = cls.RULES['blur_detected']['weight'] * 100
                total_score += score
                flags.append(cls.RULES['blur_detected']['description'])
                score_breakdown['blur'] = {
                    'score': score,
                    'confidence': blur_confidence,
                    'details': f"Blur confidence: {blur_confidence:.2f}"
                }
        
        # Rule 2: Double compression
        comp_likelihood = image_features.get('compression_double_compression_likelihood', 0)
        if comp_likelihood > cls.RULES['double_compression']['confidence_threshold']:
            score = cls.RULES['double_compression']['weight'] * 100 * comp_likelihood
            total_score += score
            flags.append(cls.RULES['double_compression']['description'])
            score_breakdown['double_compression'] = {
                'score': score,
                'confidence': comp_likelihood,
                'details': f"Double compression likelihood: {comp_likelihood:.2f}"
            }
        
        # Rule 3: ELA edits
        ela_ratio = image_features.get('ela_edit_area_ratio', 0)
        if ela_ratio > cls.RULES['ela_edits']['confidence_threshold']:
            score = cls.RULES['ela_edits']['weight'] * 100 * ela_ratio
            total_score += score
            flags.append(cls.RULES['ela_edits']['description'])
            score_breakdown['ela_edits'] = {
                'score': score,
                'confidence': ela_ratio,
                'details': f"Potential edit area ratio: {ela_ratio:.2f}"
            }
        
        # Rule 4: Noise inconsistency
        noise_std = image_features.get('noise_correlation_std', 0)
        if noise_std > cls.RULES['noise_inconsistency']['confidence_threshold']:
            score = cls.RULES['noise_inconsistency']['weight'] * 100 * min(1.0, noise_std)
            total_score += score
            flags.append(cls.RULES['noise_inconsistency']['description'])
            score_breakdown['noise_inconsistency'] = {
                'score': score,
                'confidence': noise_std,
                'details': f"Noise correlation std: {noise_std:.2f}"
            }
        
        # Rule 5: Metadata inconsistency
        software = metadata.get('Software', '')
        if software and any(editor in software.lower() for editor in ['photoshop', 'gimp', 'lightroom']):
            score = cls.RULES['software_signatures']['weight'] * 100
            total_score += score
            flags.append(f"Software editing detected: {software}")
            score_breakdown['software_signature'] = {
                'score': score,
                'confidence': 0.8,
                'details': f"Editing software: {software}"
            }
        
        # Clamp score to 0-100
        total_score = min(100.0, total_score)
        
        # Determine suspicion level
        if total_score >= 70:
            suspicion_level = "High"
        elif total_score >= 35:
            suspicion_level = "Medium"
        elif total_score >= 15:
            suspicion_level = "Low"
        else:
            suspicion_level = "None"
        
        # Calculate confidence based on rule confidence
        if score_breakdown:
            avg_confidence = sum(b['confidence'] for b in score_breakdown.values()) / len(score_breakdown)
        else:
            avg_confidence = 0.0
        
        return {
            "suspicion_score": round(total_score, 2),
            "suspicion_level": suspicion_level,
            "suspicion_confidence": round(avg_confidence, 3),
            "forensic_flags": flags,
            "score_breakdown": score_breakdown,
            "rules_applied": list(score_breakdown.keys())
        }


# -------------------------------
# Result Storage
# -------------------------------

class ResultStorage:
    """Handle storage of forensic results in multiple formats."""
    
    @staticmethod
    def save_json(result: Dict, filename: str) -> str:
        """Save result as JSON file."""
        output_path = os.path.join(Config.OUTPUT_DIR, filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"JSON output saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save JSON: {e}")
            return None
    
    @staticmethod
    def save_csv(results: List[Dict], filename: str) -> str:
        """Save results as CSV file for batch processing."""
        if not results:
            return None
        
        output_path = os.path.join(Config.OUTPUT_DIR, filename)
        
        try:
            # Extract all unique keys from all results
            all_keys = set()
            for result in results:
                # Flatten nested dictionaries for CSV
                flat_result = ResultStorage.flatten_dict(result)
                all_keys.update(flat_result.keys())
            
            # Write CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                writer.writeheader()
                
                for result in results:
                    flat_result = ResultStorage.flatten_dict(result)
                    writer.writerow(flat_result)
            
            logger.info(f"CSV output saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save CSV: {e}")
            return None
    
    @staticmethod
    def flatten_dict(d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary for CSV export."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(ResultStorage.flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert list to string for CSV
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    @staticmethod
    def save_to_database(result: Dict):
        """Save result to SQLite database (placeholder)."""
        # This would be implemented with actual database connection
        logger.info("Database saving would be implemented here")
        return True


# -------------------------------
# Main processing function
# -------------------------------

def process_image(image_path: str) -> Dict:
    """
    Full forensic processing pipeline for a single image.
    
    Args:
        image_path: Path to the image file
    
    Returns:
        Dictionary with complete forensic analysis results
    """
    
    logger.info("=" * 60)
    logger.info(f"Processing image: {image_path}")
    logger.info("=" * 60)
    
    result = {
        "filename": os.path.basename(image_path),
        "filepath": os.path.abspath(image_path),
        "processed_at": datetime.now().isoformat(),
        "pipeline_version": "2.0.0"
    }
    
    try:
        # --------------------------------------------------
        # 0. Validate input
        # --------------------------------------------------
        
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        file_size = os.path.getsize(image_path)
        if file_size == 0:
            raise ValueError(f"Empty image file: {image_path}")
        
        result["file_size"] = file_size
        result["file_extension"] = os.path.splitext(image_path)[1].lower()
        
        # --------------------------------------------------
        # 1. Extract EXIF / metadata
        # --------------------------------------------------
        
        logger.info("Step 1: Extracting metadata...")
        raw_metadata = extract_metadata(image_path)
        
        if not raw_metadata:
            logger.warning("Metadata extraction returned empty result")
            raw_metadata = {}
        
        result["raw_metadata"] = raw_metadata
        
        # --------------------------------------------------
        # 2. Normalize metadata
        # --------------------------------------------------
        
        logger.info("Step 2: Normalizing metadata...")
        normalized_metadata = normalize_metadata(raw_metadata)
        result["normalized_metadata"] = normalized_metadata
        
        # --------------------------------------------------
        # 3. Pixel-level image forensic analysis
        # --------------------------------------------------
        
        logger.info("Step 3: Performing image forensic analysis...")
        image_features = extract_image_features(image_path, advanced=Config.ENABLE_ADVANCED_FEATURES)
        result["image_features"] = image_features
        
        # --------------------------------------------------
        # 4. Advanced forensic scoring
        # --------------------------------------------------
        
        logger.info("Step 4: Calculating forensic flags and suspicion score...")
        scoring_result = ForensicScoringEngine.calculate_suspicion_score(
            image_features, normalized_metadata
        )
        
        result.update(scoring_result)
        
        # Add forensic insights
        result["forensic_insights"] = {
            "image_quality": image_features.get("image_quality_score", 0),
            "forgery_suspicion": image_features.get("forgery_suspicion_score", 0),
            "metadata_completeness": len(normalized_metadata) / max(len(raw_metadata), 1),
            "processing_success": True
        }
        
        # --------------------------------------------------
        # 5. Feature engineering (AI-ready)
        # --------------------------------------------------
        
        logger.info("Step 5: Generating ML-ready feature vector...")
        feature_vector = extract_features_from_analysis(result, feature_set=Config.FEATURE_SET)
        
        # Select ML-optimal subset
        ml_features = select_feature_subset(feature_vector, Config.ML_FEATURE_SUBSET)
        
        result["feature_vector"] = feature_vector
        result["ml_features"] = ml_features
        
        # --------------------------------------------------
        # 6. Generate forensic report
        # --------------------------------------------------
        
        if Config.GENERATE_REPORTS:
            logger.info("Step 6: Generating forensic report...")
            report_filename = f"{Path(image_path).stem}_forensic_report.txt"
            report_path = os.path.join(Config.REPORT_DIR, report_filename)
            
            try:
                generate_forensic_report(
                    analysis_result=result,
                    output_file=report_path,
                    format="txt"
                )
                result["report_path"] = report_path
                logger.info(f"Report saved: {report_path}")
            except Exception as e:
                logger.error(f"Failed to generate report: {e}")
                result["report_error"] = str(e)
        
        # --------------------------------------------------
        # 7. Save outputs
        # --------------------------------------------------
        
        # Save JSON output
        if Config.SAVE_JSON_OUTPUT:
            json_filename = f"{Path(image_path).stem}_analysis.json"
            json_path = ResultStorage.save_json(result, json_filename)
            if json_path:
                result["json_output_path"] = json_path
        
        # Save to database
        if Config.SAVE_DATABASE:
            ResultStorage.save_to_database(result)
        
        # --------------------------------------------------
        # 8. Summary
        # --------------------------------------------------
        
        logger.info("Processing completed successfully")
        logger.info(f"Summary: {result['suspicion_level']} suspicion ({result['suspicion_score']}/100)")
        logger.info(f"Flags detected: {len(result['forensic_flags'])}")
        logger.info("=" * 60)
        
        # Print quick summary to console
        print_summary(result)
        
        return result
        
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        logger.error(traceback.format_exc())
        
        # Create error result
        error_result = {
            "filename": os.path.basename(image_path),
            "processed_at": datetime.now().isoformat(),
            "error": str(e),
            "traceback": traceback.format_exc(),
            "processing_success": False
        }
        
        # Save error result
        error_filename = f"{Path(image_path).stem}_error.json"
        ResultStorage.save_json(error_result, error_filename)
        
        raise


# -------------------------------
# Batch Processing
# -------------------------------

def process_batch(image_paths: List[str]) -> Dict:
    """
    Process multiple images in batch mode.
    
    Args:
        image_paths: List of image file paths
    
    Returns:
        Dictionary with batch results summary
    """
    logger.info(f"Starting batch processing of {len(image_paths)} images")
    
    all_results = []
    success_count = 0
    failure_count = 0
    
    for idx, image_path in enumerate(image_paths, 1):
        logger.info(f"[{idx}/{len(image_paths)}] Processing: {image_path}")
        
        try:
            result = process_image(image_path)
            all_results.append(result)
            success_count += 1
            
        except Exception as e:
            logger.error(f"Failed to process {image_path}: {e}")
            failure_count += 1
    
    # Save batch CSV if configured
    if Config.SAVE_CSV_OUTPUT and all_results:
        csv_filename = f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_path = ResultStorage.save_csv(all_results, csv_filename)
        
        if csv_path:
            logger.info(f"Batch CSV saved: {csv_path}")
    
    # Generate batch summary
    batch_summary = {
        "total_images": len(image_paths),
        "successful": success_count,
        "failed": failure_count,
        "success_rate": (success_count / len(image_paths)) * 100 if image_paths else 0,
        "processed_at": datetime.now().isoformat(),
        "summary_by_level": {}
    }
    
    # Calculate summary by suspicion level
    for result in all_results:
        level = result.get('suspicion_level', 'Unknown')
        batch_summary["summary_by_level"][level] = batch_summary["summary_by_level"].get(level, 0) + 1
    
    # Save batch summary
    summary_filename = f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    ResultStorage.save_json(batch_summary, summary_filename)
    
    logger.info(f"Batch processing completed: {success_count} succeeded, {failure_count} failed")
    print_batch_summary(batch_summary)
    
    return batch_summary


# -------------------------------
# Utility Functions
# -------------------------------

def print_summary(result: Dict):
    """Print a concise summary of the analysis results."""
    print("\n" + "=" * 60)
    print("FORENSIC ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"File: {result.get('filename', 'Unknown')}")
    print(f"Suspicion Score: {result.get('suspicion_score', 0)}/100")
    print(f"Suspicion Level: {result.get('suspicion_level', 'Unknown')}")
    print(f"Flags Detected: {len(result.get('forensic_flags', []))}")
    
    if result.get('forensic_flags'):
        print("\nForensic Flags:")
        for flag in result['forensic_flags']:
            print(f"  ⚠ {flag}")
    
    print(f"\nImage Quality: {result.get('forensic_insights', {}).get('image_quality', 0):.1f}/100")
    print("=" * 60)


def print_batch_summary(summary: Dict):
    """Print batch processing summary."""
    print("\n" + "=" * 60)
    print("BATCH PROCESSING SUMMARY")
    print("=" * 60)
    print(f"Total Images: {summary.get('total_images', 0)}")
    print(f"Successful: {summary.get('successful', 0)}")
    print(f"Failed: {summary.get('failed', 0)}")
    print(f"Success Rate: {summary.get('success_rate', 0):.1f}%")
    
    if summary.get('summary_by_level'):
        print("\nSuspicion Level Distribution:")
        for level, count in summary['summary_by_level'].items():
            percentage = (count / summary['total_images']) * 100
            print(f"  {level:10}: {count:3} images ({percentage:.1f}%)")
    
    print("=" * 60)


# -------------------------------
# CLI Entry Point
# -------------------------------

def main():
    """Main CLI entry point."""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Forensic Image Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py image.jpg                # Process single image
  python main.py image1.jpg image2.jpg    # Process multiple images
  python main.py --batch folder_path      # Process all images in folder
  python main.py --config config.json     # Load configuration from file
        """
    )
    
    parser.add_argument(
        "images",
        nargs="*",
        help="Image file(s) to process"
    )
    
    parser.add_argument(
        "--batch",
        "-b",
        help="Process all images in a folder"
    )
    
    parser.add_argument(
        "--config",
        "-c",
        help="Load configuration from JSON file"
    )
    
    parser.add_argument(
        "--output-dir",
        "-o",
        help="Override output directory"
    )
    
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Disable report generation"
    )
    
    parser.add_argument(
        "--feature-set",
        choices=["minimal", "standard", "full", "research"],
        default="full",
        help="Feature extraction level"
    )
    
    args = parser.parse_args()
    
    # Load configuration if provided
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
                for key, value in config_data.items():
                    if hasattr(Config, key):
                        setattr(Config, key, value)
            logger.info(f"Configuration loaded from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
    
    # Override config from command line
    if args.output_dir:
        Config.OUTPUT_DIR = args.output_dir
        Config.setup_directories()
    
    if args.no_report:
        Config.GENERATE_REPORTS = False
    
    Config.FEATURE_SET = args.feature_set
    
    # Collect image paths
    image_paths = []
    
    if args.batch:
        # Process all images in folder
        folder_path = args.batch
        if not os.path.exists(folder_path):
            logger.error(f"Folder not found: {folder_path}")
            sys.exit(1)
        
        # Supported image extensions
        image_extensions = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp', '.gif', '.webp'}
        
        for root, _, files in os.walk(folder_path):
            for file in files:
                if Path(file).suffix.lower() in image_extensions:
                    image_paths.append(os.path.join(root, file))
        
        logger.info(f"Found {len(image_paths)} images in {folder_path}")
        
        if not image_paths:
            logger.error("No images found in the specified folder")
            sys.exit(1)
    
    elif args.images:
        # Process specified images
        image_paths = args.images
        
        # Validate images exist
        valid_paths = []
        for path in image_paths:
            if os.path.exists(path):
                valid_paths.append(path)
            else:
                logger.warning(f"Image not found: {path}")
        
        image_paths = valid_paths
    
    else:
        parser.print_help()
        print("\nError: No images specified")
        sys.exit(1)
    
    # Process images
    try:
        if len(image_paths) == 1:
            # Single image processing
            result = process_image(image_paths[0])
            
            # Print feature vector summary for ML
            if 'feature_vector' in result:
                print("\nML Feature Vector Summary:")
                print(f"Total features: {len(result['feature_vector'])}")
                print(f"Selected for ML: {len(result.get('ml_features', {}))}")
                
                # Show top features by value
                ml_features = result.get('ml_features', {})
                if ml_features:
                    print("\nTop ML Features (by value):")
                    sorted_features = sorted(ml_features.items(), key=lambda x: abs(x[1]), reverse=True)[:10]
                    for feature, value in sorted_features:
                        print(f"  {feature:30}: {value:.4f}")
            
        else:
            # Batch processing
            summary = process_batch(image_paths)
    
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()