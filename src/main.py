#!/usr/bin/env python3
"""
MetaForensicAI - Main Entry Point
AI-Assisted Digital Image Forensics System

Version: 1.0.0
Author: MetaForensicAI Research Team
License: MIT
"""

import argparse
import sys
import logging
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from .core.evidence_handler import ForensicEvidenceHandler
from .core.metadata_extractor import EnhancedMetadataExtractor
from .core.forensic_analyzer import MetadataAuthenticityAnalyzer
from .core.origin_detector import OriginDetector
from .analysis.authenticity_analyzer import MetadataAuthenticityAnalyzer as AuthenticityAnalyzer
from .analysis.contextual_analyzer import ContextualAnalyzer
from .analysis.risk_scorer import EvidenceRiskScorer
from .explanation.explanation_engine import ConfidenceExplanationEngine
from .interface.cli_assistant import ForensicCLIAssistant
from .reporting.report_generator import ForensicReportGenerator
from .utils.logging_handler import ForensicLogger, ChainOfCustodyLogger
from .utils.chain_of_custody import ChainOfCustody

class MetaForensicAI:
    """
    Main controller class for the AI-Assisted Digital Image Forensics System.
    Implements the complete forensic analysis pipeline.
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the forensic analysis system.
        
        Args:
            config_path: Path to configuration file (optional)
        """
        self.config = self._load_config(config_path)
        self.logger = ForensicLogger('MetaForensicAI')
        self.chain_of_custody = ChainOfCustodyLogger()
        
        # Initialize core components
        self.evidence_handler = ForensicEvidenceHandler()
        self.metadata_extractor = EnhancedMetadataExtractor()
        self.origin_detector = OriginDetector()
        
        # Initialize analysis components
        self.authenticity_analyzer = MetadataAuthenticityAnalyzer()
        self.contextual_analyzer = ContextualAnalyzer()
        self.risk_scorer = EvidenceRiskScorer()
        
        # Initialize explanation and reporting
        self.explanation_engine = ConfidenceExplanationEngine()
        self.report_generator = ForensicReportGenerator()
        
        # Main analyzer is the authenticity analyzer with supporting components
        self.forensic_analyzer = AuthenticityAnalyzer()
        
        self.analysis_results = None
        self.cli_assistant = None
        
        self.logger.info("MetaForensicAI system initialized successfully")
        self.chain_of_custody.log_event("SYSTEM_INITIALIZED", {
            "config_path": config_path,
            "timestamp": datetime.now().isoformat()
        })
    
    def _load_config(self, config_path):
        """Load configuration from file or use defaults."""
        import yaml
        from pathlib import Path
        
        default_config = {
            'system': {
                'name': 'MetaForensicAI',
                'version': '1.0.0',
                'mode': 'forensic',
                'language': 'en'
            },
            'forensic': {
                'read_only': True,
                'hash_algorithms': ['sha256', 'sha3_256'],
                'audit_logging': True
            },
            'analysis': {
                'enable_timestamp_analysis': True,
                'enable_platform_detection': True,
                'confidence_threshold': 0.7
            },
            'reporting': {
                'generate_pdf': True,
                'generate_json': True,
                'output_dir': './results/reports'
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Recursive merge with default config
                    self._merge_configs(default_config, user_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _merge_configs(self, default, user):
        """Recursively merge user config into default config."""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_configs(default[key], value)
            else:
                default[key] = value
    
    def analyze_image(self, image_path, case_info=None):
        """
        Perform complete forensic analysis on an image.
        
        Args:
            image_path: Path to the image file
            case_info: Dictionary containing case information
        
        Returns:
            Dictionary containing complete analysis results
        """
        try:
            self.logger.info(f"Starting forensic analysis of: {image_path}")
            self.chain_of_custody.log_event("ANALYSIS_STARTED", {
                "image_path": image_path,
                "case_info": case_info or {},
                "timestamp": datetime.now().isoformat()
            })
            
            # Step 1: Evidence integrity verification
            self.logger.info("Step 1: Verifying evidence integrity...")
            integrity_info = self.evidence_handler.process_evidence(image_path)
            
            if not integrity_info['verified']:
                self.logger.error("Evidence integrity verification failed")
                raise ValueError("Evidence integrity check failed")
            
            self.chain_of_custody.log_event("EVIDENCE_VERIFIED", integrity_info)
            
            # Step 2: Perform comprehensive forensic analysis
            self.logger.info("Step 2: Performing forensic analysis...")
            self.analysis_results = self.forensic_analyzer.analyze(
                image_path=image_path,
                case_info=case_info
            )
            
            # Add integrity information to results
            self.analysis_results['evidence_integrity'] = integrity_info
            self.analysis_results['analysis_timestamp'] = datetime.now().isoformat()
            
            self.logger.info("Forensic analysis completed successfully")
            self.chain_of_custody.log_event("ANALYSIS_COMPLETED", {
                "image_path": image_path,
                "risk_score": self.analysis_results.get('risk_assessment', {}).get('score', 0),
                "timestamp": datetime.now().isoformat()
            })
            
            return self.analysis_results
            
        except Exception as e:
            self.logger.error(f"Forensic analysis failed: {e}")
            self.chain_of_custody.log_event("ANALYSIS_FAILED", {
                "image_path": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            raise
    
    def interactive_analysis(self):
        """Launch interactive CLI assistant."""
        if not self.analysis_results:
            print("No analysis results available. Run analyze_image() first.")
            return
        
        self.cli_assistant = ForensicCLIAssistant(
            analysis_results=self.analysis_results,
            forensic_system=self
        )
        self.cli_assistant.start_session()
    
    def generate_reports(self, output_dir=None, formats=None):
        """
        Generate forensic reports.
        
        Args:
            output_dir: Directory to save reports (optional)
            formats: List of formats ['pdf', 'json', 'html'] (optional)
        
        Returns:
            Dictionary of generated report paths
        """
        if not self.analysis_results:
            raise ValueError("No analysis results available. Run analyze_image() first.")
        
        formats = formats or self.config['reporting'].get('formats', ['pdf', 'json'])
        output_dir = output_dir or self.config['reporting'].get('output_dir', './results/reports')
        
        self.logger.info(f"Generating reports in formats: {formats}")
        
        reports = self.report_generator.generate(
            analysis_results=self.analysis_results,
            output_dir=output_dir,
            formats=formats
        )
        
        self.chain_of_custody.log_event("REPORTS_GENERATED", {
            "formats": formats,
            "output_dir": output_dir,
            "report_files": reports,
            "timestamp": datetime.now().isoformat()
        })
        
        return reports
    
    def batch_analyze(self, image_dir, output_dir=None, max_images=None):
        """
        Analyze multiple images in batch mode.
        
        Args:
            image_dir: Directory containing images
            output_dir: Output directory for reports
            max_images: Maximum number of images to process
        
        Returns:
            List of analysis results
        """
        from pathlib import Path
        import concurrent.futures
        import tqdm
        
        image_dir = Path(image_dir)
        if not image_dir.is_dir():
            raise ValueError(f"Not a directory: {image_dir}")
        
        # Find image files
        image_patterns = ['*.jpg', '*.jpeg', '*.png', '*.tiff', '*.tif', 
                         '*.bmp', '*.gif', '*.webp', '*.cr2', '*.nef']
        
        image_files = []
        for pattern in image_patterns:
            image_files.extend(image_dir.rglob(pattern))
        
        if max_images:
            image_files = image_files[:max_images]
        
        self.logger.info(f"Found {len(image_files)} images for batch analysis")
        
        results = []
        successful = 0
        failed = 0
        
        # Process images with progress bar
        with tqdm.tqdm(total=len(image_files), desc="Batch Analysis", unit="image") as pbar:
            for img_file in image_files:
                try:
                    self.logger.debug(f"Analyzing: {img_file.name}")
                    
                    # Create case info based on filename
                    case_info = {
                        'image_filename': img_file.name,
                        'batch_id': f"BATCH_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        'analyst': 'batch_processor'
                    }
                    
                    # Analyze image
                    result = self.analyze_image(str(img_file), case_info)
                    results.append(result)
                    successful += 1
                    
                    # Generate report for this image
                    img_output_dir = Path(output_dir or './results/batch_reports') / img_file.stem
                    self.generate_reports(output_dir=str(img_output_dir))
                    
                except Exception as e:
                    self.logger.error(f"Failed to analyze {img_file}: {e}")
                    failed += 1
                    results.append({
                        'image_path': str(img_file),
                        'error': str(e),
                        'status': 'FAILED'
                    })
                
                pbar.update(1)
                pbar.set_postfix({
                    'success': successful,
                    'failed': failed
                })
        
        # Generate batch summary report
        batch_summary = {
            'batch_id': f"BATCH_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'total_images': len(image_files),
            'successful_analyses': successful,
            'failed_analyses': failed,
            'analysis_timestamp': datetime.now().isoformat(),
            'image_directory': str(image_dir.absolute()),
            'individual_results': results
        }
        
        # Save batch summary
        summary_file = Path(output_dir or './results/batch_reports') / 'batch_summary.json'
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(summary_file, 'w') as f:
            json.dump(batch_summary, f, indent=2)
        
        self.logger.info(f"Batch analysis complete. Success: {successful}/{len(image_files)}")
        self.chain_of_custody.log_event("BATCH_ANALYSIS_COMPLETED", batch_summary)
        
        return batch_summary
    
    def compare_images(self, image_paths, comparison_type='metadata'):
        """
        Compare multiple images for forensic analysis.
        
        Args:
            image_paths: List of image file paths
            comparison_type: Type of comparison ('metadata', 'timestamps', 'origin')
        
        Returns:
            Comparison results
        """
        if len(image_paths) < 2:
            raise ValueError("At least 2 images required for comparison")
        
        self.logger.info(f"Comparing {len(image_paths)} images ({comparison_type})")
        
        analysis_results = []
        for img_path in image_paths:
            try:
                result = self.analyze_image(img_path)
                analysis_results.append(result)
            except Exception as e:
                self.logger.warning(f"Failed to analyze {img_path}: {e}")
                analysis_results.append({
                    'image_path': img_path,
                    'error': str(e),
                    'status': 'FAILED'
                })
        
        # Perform comparison based on type
        comparison_results = self._perform_comparison(
            analysis_results=analysis_results,
            comparison_type=comparison_type
        )
        
        return comparison_results
    
    def _perform_comparison(self, analysis_results, comparison_type):
        """Perform specific type of comparison on analysis results."""
        comparison = {
            'comparison_type': comparison_type,
            'compared_images': len([r for r in analysis_results if 'error' not in r]),
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        if comparison_type == 'metadata':
            comparison['results'] = self._compare_metadata(analysis_results)
        elif comparison_type == 'timestamps':
            comparison['results'] = self._compare_timestamps(analysis_results)
        elif comparison_type == 'origin':
            comparison['results'] = self._compare_origins(analysis_results)
        else:
            comparison['results'] = {'error': f'Unknown comparison type: {comparison_type}'}
        
        return comparison
    
    def _compare_metadata(self, analysis_results):
        """Compare metadata across multiple images."""
        comparison = {}
        valid_results = [r for r in analysis_results if 'error' not in r]
        
        for i, result in enumerate(valid_results):
            metadata = result.get('metadata', {}).get('summary', {})
            comparison[f'image_{i}'] = {
                'filename': Path(result.get('evidence_integrity', {}).get('file_path', '')).name,
                'camera': metadata.get('camera_make', 'Unknown'),
                'timestamp': metadata.get('datetime_original', 'Unknown'),
                'dimensions': metadata.get('dimensions', 'Unknown')
            }
        
        return comparison
    
    def _compare_timestamps(self, analysis_results):
        """Compare timestamps across multiple images."""
        comparison = {
            'timestamps': [],
            'time_differences': {},
            'chronological_order': []
        }
        
        valid_results = [r for r in analysis_results if 'error' not in r]
        
        # Extract timestamps
        timestamps = []
        for result in valid_results:
            metadata = result.get('metadata', {}).get('summary', {})
            ts = metadata.get('datetime_original')
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    timestamps.append((dt, result))
                except:
                    pass
        
        # Sort chronologically
        timestamps.sort(key=lambda x: x[0])
        comparison['chronological_order'] = [
            {
                'timestamp': ts.isoformat(),
                'filename': Path(r.get('evidence_integrity', {}).get('file_path', '')).name
            }
            for ts, r in timestamps
        ]
        
        # Calculate time differences
        if len(timestamps) >= 2:
            for i in range(len(timestamps)-1):
                ts1, r1 = timestamps[i]
                ts2, r2 = timestamps[i+1]
                diff = (ts2 - ts1).total_seconds()
                
                comparison['time_differences'][f'image_{i}_to_{i+1}'] = {
                    'difference_seconds': diff,
                    'difference_human': f"{diff:.1f} seconds",
                    'from': Path(r1.get('evidence_integrity', {}).get('file_path', '')).name,
                    'to': Path(r2.get('evidence_integrity', {}).get('file_path', '')).name
                }
        
        return comparison
    
    def _compare_origins(self, analysis_results):
        """Compare origins across multiple images."""
        comparison = {
            'origins': {},
            'consistency': 'mixed'
        }
        
        origins = []
        for result in analysis_results:
            origin = result.get('origin_detection', {}).get('primary_origin', 'Unknown')
            origins.append(origin)
            comparison['origins'][Path(result.get('evidence_integrity', {}).get('file_path', '')).name] = origin
        
        # Check consistency
        if len(set(origins)) == 1:
            comparison['consistency'] = 'consistent'
        else:
            comparison['consistency'] = 'inconsistent'
        
        return comparison
    
    def get_system_info(self):
        """Get system information and status."""
        return {
            'system': {
                'name': 'MetaForensicAI',
                'version': '1.0.0',
                'status': 'operational',
                'timestamp': datetime.now().isoformat()
            },
            'components': {
                'evidence_handler': self.evidence_handler.__class__.__name__,
                'metadata_extractor': self.metadata_extractor.__class__.__name__,
                'forensic_analyzer': self.forensic_analyzer.__class__.__name__,
                'origin_detector': self.origin_detector.__class__.__name__
            },
            'config': {
                'forensic_mode': self.config['forensic']['read_only'],
                'analysis_modules': list(self.config['analysis'].keys()),
                'reporting_formats': self.config['reporting'].get('formats', ['pdf', 'json'])
            }
        }


def main():
    """Command-line entry point for MetaForensicAI."""
    parser = argparse.ArgumentParser(
        description="MetaForensicAI: AI-Assisted Digital Image Forensics System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --image evidence.jpg
  %(prog)s --image evidence.jpg --interactive
  %(prog)s --batch evidence_folder/ --output reports/
  %(prog)s --image evidence.jpg --report pdf --verbose
  %(prog)s --compare image1.jpg image2.jpg --type metadata
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--image', '-i',
        help='Path to image file for analysis'
    )
    input_group.add_argument(
        '--batch', '-b',
        help='Path to directory for batch analysis'
    )
    input_group.add_argument(
        '--compare',
        nargs='+',
        help='Compare multiple images'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        default='./results',
        help='Output directory for reports (default: ./results)'
    )
    
    # Analysis options
    parser.add_argument(
        '--interactive', '-I',
        action='store_true',
        help='Launch interactive CLI after analysis'
    )
    
    parser.add_argument(
        '--report', '-r',
        choices=['pdf', 'json', 'both', 'none'],
        default='both',
        help='Report format to generate (default: both)'
    )
    
    parser.add_argument(
        '--compare-type',
        choices=['metadata', 'timestamps', 'origin'],
        default='metadata',
        help='Type of comparison for --compare (default: metadata)'
    )
    
    # Configuration options
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--case-id',
        help='Case identifier for reporting'
    )
    
    parser.add_argument(
        '--analyst',
        help='Analyst name for reporting'
    )
    
    parser.add_argument(
        '--max-images',
        type=int,
        help='Maximum number of images for batch analysis'
    )
    
    # Verbosity options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode with detailed output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('forensic_analysis.log'),
            logging.StreamHandler()
        ]
    )
    
    try:
        # Initialize system
        print("\n" + "="*70)
        print("META FORENSIC AI: Digital Image Forensics System".center(70))
        print("="*70 + "\n")
        
        forensic_system = MetaForensicAI(config_path=args.config)
        
        # Prepare case info
        case_info = {}
        if args.case_id:
            case_info['case_id'] = args.case_id
        if args.analyst:
            case_info['analyst'] = args.analyst
        
        # Process based on input type
        if args.image:
            print(f"🔍 Analyzing image: {args.image}")
            
            # Perform analysis
            results = forensic_system.analyze_image(args.image, case_info)
            
            # Display summary
            risk_score = results.get('risk_assessment', {}).get('score', 0)
            risk_level = results.get('risk_assessment', {}).get('interpretation', 'Unknown')
            origin = results.get('origin_detection', {}).get('primary_origin', 'Unknown')
            
            print(f"\n📊 Analysis Results:")
            print(f"   • Evidence Risk Score: {risk_score}/100")
            print(f"   • Risk Level: {risk_level}")
            print(f"   • Primary Origin: {origin}")
            print(f"   • Authenticity Flags: {len(results.get('authenticity_analysis', {}).get('flags', []))}")
            
            # Generate reports
            if args.report != 'none':
                report_formats = []
                if args.report in ['pdf', 'both']:
                    report_formats.append('pdf')
                if args.report in ['json', 'both']:
                    report_formats.append('json')
                
                print(f"\n📄 Generating reports ({', '.join(report_formats)})...")
                reports = forensic_system.generate_reports(
                    output_dir=args.output,
                    formats=report_formats
                )
                
                for fmt, path in reports.items():
                    print(f"   ✅ {fmt.upper()} report: {path}")
            
            # Interactive mode
            if args.interactive:
                print(f"\n💻 Launching interactive CLI assistant...")
                forensic_system.interactive_analysis()
        
        elif args.batch:
            print(f"🔍 Batch analyzing directory: {args.batch}")
            
            # Perform batch analysis
            batch_results = forensic_system.batch_analyze(
                image_dir=args.batch,
                output_dir=args.output,
                max_images=args.max_images
            )
            
            print(f"\n📊 Batch Analysis Summary:")
            print(f"   • Total Images: {batch_results.get('total_images', 0)}")
            print(f"   • Successful: {batch_results.get('successful_analyses', 0)}")
            print(f"   • Failed: {batch_results.get('failed_analyses', 0)}")
            print(f"   • Summary Report: {args.output}/batch_summary.json")
        
        elif args.compare:
            print(f"🔍 Comparing {len(args.compare)} images...")
            
            # Perform comparison
            comparison_results = forensic_system.compare_images(
                image_paths=args.compare,
                comparison_type=args.compare_type
            )
            
            print(f"\n📊 Comparison Results ({args.compare_type}):")
            
            if args.compare_type == 'metadata':
                for img, info in comparison_results.get('results', {}).get('metadata', {}).items():
                    print(f"   • {img}: {info.get('camera', 'Unknown')} - {info.get('timestamp', 'Unknown')}")
            
            elif args.compare_type == 'timestamps':
                order = comparison_results.get('results', {}).get('chronological_order', [])
                print(f"   • Chronological Order:")
                for i, item in enumerate(order):
                    print(f"     {i+1}. {item['filename']} - {item['timestamp']}")
            
            elif args.compare_type == 'origin':
                origins = comparison_results.get('results', {}).get('origins', {})
                consistency = comparison_results.get('results', {}).get('consistency', 'Unknown')
                print(f"   • Origin Consistency: {consistency}")
                for filename, origin in origins.items():
                    print(f"     - {filename}: {origin}")
        
        print(f"\n✨ Analysis completed successfully!")
        print(f"Logs: forensic_analysis.log")
        print(f"Reports: {args.output}/")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.debug or args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()