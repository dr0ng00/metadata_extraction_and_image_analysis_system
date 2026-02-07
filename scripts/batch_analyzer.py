#!/usr/bin/env python3
"""
Batch Image Analysis Script
Process multiple images in batch mode for forensic analysis.
"""

import argparse
import sys
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import concurrent.futures
import traceback
from tqdm import tqdm

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import MetaForensicAI
from src.utils.logging_handler import ForensicLogger

class BatchAnalyzer:
    """Batch analysis of multiple images with forensic integrity."""
    
    def __init__(self, config_path=None):
        """Initialize batch analyzer."""
        self.logger = ForensicLogger('BatchAnalyzer')
        self.forensic_system = MetaForensicAI(config_path=config_path)
        self.results = []
        self.statistics = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'start_time': None,
            'end_time': None
        }
    
    def analyze_directory(self, 
                         input_dir: str,
                         output_dir: str | None = None,
                         recursive: bool = True,
                         max_workers: int = 4,
                         max_images: int | None = None,
                         skip_existing: bool = True) -> Dict[str, Any]:
        """
        Analyze all images in a directory.
        
        Args:
            input_dir: Directory containing images
            output_dir: Directory for output reports
            recursive: Search subdirectories recursively
            max_workers: Maximum parallel workers
            max_images: Maximum number of images to process
            skip_existing: Skip images with existing reports
        
        Returns:
            Batch analysis results
        """
        input_path = Path(input_dir)
        if not input_path.exists():
            raise ValueError(f"Input directory does not exist: {input_dir}")
        
        output_path = Path(output_dir or f"./results/batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        output_path.mkdir(parents=True, exist_ok=True)
        
        self.statistics['start_time'] = datetime.now().isoformat()
        
        # Find image files
        image_files = self._find_image_files(input_path, recursive)
        
        if max_images:
            image_files = image_files[:max_images]
        
        self.statistics['total'] = len(image_files)
        
        self.logger.info(f"Starting batch analysis of {len(image_files)} images")
        self.logger.info(f"Input directory: {input_path}")
        self.logger.info(f"Output directory: {output_path}")
        
        # Create batch metadata
        batch_metadata = self._create_batch_metadata(input_path, output_path, image_files)
        
        # Process images
        if max_workers > 1:
            self._process_parallel(image_files, output_path, max_workers, skip_existing)
        else:
            self._process_sequential(image_files, output_path, skip_existing)
        
        self.statistics['end_time'] = datetime.now().isoformat()
        
        # Generate batch report
        batch_report = self._generate_batch_report(batch_metadata)
        
        # Save results
        self._save_results(output_path, batch_report)
        
        return batch_report
    
    def _find_image_files(self, directory: Path, recursive: bool) -> List[Path]:
        """Find all image files in directory."""
        image_extensions = [
            '*.jpg', '*.jpeg', '*.jpe', '*.jfif',
            '*.png', '*.tiff', '*.tif', '*.bmp',
            '*.gif', '*.webp', '*.cr2', '*.nef',
            '*.arw', '*.dng', '*.rw2', '*.orf'
        ]
        
        image_files = []
        
        if recursive:
            for ext in image_extensions:
                image_files.extend(directory.rglob(ext))
        else:
            for ext in image_extensions:
                image_files.extend(directory.glob(ext))
        
        # Sort by filename for consistent processing
        image_files.sort(key=lambda x: x.name.lower())
        
        return image_files
    
    def _create_batch_metadata(self, input_dir: Path, output_dir: Path, image_files: List[Path]) -> Dict[str, Any]:
        """Create metadata for batch analysis."""
        return {
            'batch_id': f"BATCH-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'created': datetime.now().isoformat(),
            'input_directory': str(input_dir.absolute()),
            'output_directory': str(output_dir.absolute()),
            'total_images': len(image_files),
            'image_files': [str(f.absolute()) for f in image_files],
            'analyst': self._get_current_user(),
            'system_info': self._get_system_info()
        }
    
    def _get_current_user(self) -> str:
        """Get current username."""
        import getpass
        return getpass.getuser()
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        import platform
        return {
            'system': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'python_version': platform.python_version()
        }
    
    def _process_sequential(self, image_files: List[Path], output_dir: Path, skip_existing: bool):
        """Process images sequentially."""
        with tqdm(total=len(image_files), desc="Analyzing images", unit="image") as pbar:
            for image_file in image_files:
                self._process_single_image(image_file, output_dir, skip_existing)
                pbar.update(1)
                pbar.set_postfix({
                    'success': self.statistics['successful'],
                    'failed': self.statistics['failed'],
                    'skipped': self.statistics['skipped']
                })
    
    def _process_parallel(self, image_files: List[Path], output_dir: Path, max_workers: int, skip_existing: bool):
        """Process images in parallel."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_image = {
                executor.submit(self._process_single_image, img, output_dir, skip_existing): img
                for img in image_files
            }
            
            # Process completed tasks
            with tqdm(total=len(future_to_image), desc="Analyzing images", unit="image") as pbar:
                for future in as_completed(future_to_image):
                    image_file = future_to_image[future]
                    try:
                        future.result()  # Will re-raise any exceptions
                    except Exception as e:
                        self.logger.error(f"Failed to process {image_file}: {e}")
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        'success': self.statistics['successful'],
                        'failed': self.statistics['failed'],
                        'skipped': self.statistics['skipped']
                    })
    
    def _process_single_image(self, image_file: Path, output_dir: Path, skip_existing: bool):
        """Process a single image."""
        # Check if report already exists
        if skip_existing:
            report_dir = output_dir / 'individual_reports' / image_file.stem
            if report_dir.exists():
                json_report = report_dir / 'report.json'
                if json_report.exists():
                    self.statistics['skipped'] += 1
                    self.logger.debug(f"Skipping {image_file} - report exists")
                    return
        
        try:
            # Create case info
            case_info = {
                'batch_id': f"BATCH-{datetime.now().strftime('%Y%m%d')}",
                'image_filename': image_file.name,
                'image_path': str(image_file.absolute()),
                'analyst': self._get_current_user()
            }
            
            # Analyze image
            self.logger.info(f"Analyzing: {image_file.name}")
            analysis_results = self.forensic_system.analyze_image(
                str(image_file),
                case_info=case_info
            )
            
            # Create individual report directory
            report_dir = output_dir / 'individual_reports' / image_file.stem
            report_dir.mkdir(parents=True, exist_ok=True)
            
            # Save individual results
            self._save_individual_results(report_dir, analysis_results)
            
            # Add to results list
            self.results.append({
                'image_file': str(image_file.absolute()),
                'image_name': image_file.name,
                'analysis_time': datetime.now().isoformat(),
                'risk_score': analysis_results.get('risk_assessment', {}).get('score', 0),
                'primary_origin': analysis_results.get('origin_detection', {}).get('primary_origin', 'Unknown'),
                'result_path': str(report_dir.absolute()),
                'status': 'SUCCESS'
            })
            
            self.statistics['successful'] += 1
            
        except Exception as e:
            self.logger.error(f"Failed to analyze {image_file}: {e}")
            self.results.append({
                'image_file': str(image_file.absolute()),
                'image_name': image_file.name,
                'analysis_time': datetime.now().isoformat(),
                'error': str(e),
                'status': 'FAILED'
            })
            self.statistics['failed'] += 1
    
    def _save_individual_results(self, report_dir: Path, analysis_results: Dict[str, Any]):
        """Save individual analysis results."""
        # Save full JSON results
        json_file = report_dir / 'report.json'
        with open(json_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        # Save summary CSV
        summary = self._extract_summary(analysis_results)
        csv_file = report_dir / 'summary.csv'
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=summary.keys())
            writer.writeheader()
            writer.writerow(summary)
        
        # Generate PDF report if configured
        try:
            reports = self.forensic_system.generate_reports(
                output_dir=str(report_dir),
                formats=['pdf']
            )
        except:
            pass  # PDF generation might fail if reportlab not installed
    
    def _extract_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract summary from analysis results."""
        return {
            'filename': analysis_results.get('evidence_integrity', {}).get('file_path', '').split('/')[-1],
            'risk_score': analysis_results.get('risk_assessment', {}).get('score', 0),
            'risk_level': analysis_results.get('risk_assessment', {}).get('interpretation', 'Unknown'),
            'primary_origin': analysis_results.get('origin_detection', {}).get('primary_origin', 'Unknown'),
            'origin_confidence': analysis_results.get('origin_detection', {}).get('confidence', 0),
            'camera_make': analysis_results.get('metadata', {}).get('summary', {}).get('camera_info', {}).get('make', 'Unknown'),
            'camera_model': analysis_results.get('metadata', {}).get('summary', {}).get('camera_info', {}).get('model', 'Unknown'),
            'timestamp': analysis_results.get('metadata', {}).get('summary', {}).get('timestamp_info', {}).get('datetimeoriginal', 'Unknown'),
            'dimensions': f"{analysis_results.get('metadata', {}).get('summary', {}).get('file_info', {}).get('image_width', 0)}x{analysis_results.get('metadata', {}).get('summary', {}).get('file_info', {}).get('image_height', 0)}",
            'file_size_mb': round(analysis_results.get('evidence_integrity', {}).get('file_size', 0) / (1024 * 1024), 2),
            'authenticity_flags': len(analysis_results.get('authenticity_analysis', {}).get('flags', [])),
            'analysis_time': analysis_results.get('analysis_timestamp', 'Unknown')
        }
    
    def _generate_batch_report(self, batch_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive batch report."""
        # Calculate statistics
        risk_scores = [r.get('risk_score', 0) for r in self.results if r.get('status') == 'SUCCESS']
        origins = [r.get('primary_origin', 'Unknown') for r in self.results if r.get('status') == 'SUCCESS']
        
        # Count origins
        origin_counts = {}
        for origin in origins:
            origin_counts[origin] = origin_counts.get(origin, 0) + 1
        
        report = {
            'batch_metadata': batch_metadata,
            'statistics': {
                **self.statistics,
                'duration_seconds': self._calculate_duration(),
                'avg_risk_score': sum(risk_scores) / len(risk_scores) if risk_scores else 0,
                'min_risk_score': min(risk_scores) if risk_scores else 0,
                'max_risk_score': max(risk_scores) if risk_scores else 0,
                'origin_distribution': origin_counts,
                'success_rate': (self.statistics['successful'] / self.statistics['total'] * 100) if self.statistics['total'] > 0 else 0
            },
            'results_summary': self.results,
            'high_risk_images': [
                r for r in self.results 
                if r.get('status') == 'SUCCESS' and r.get('risk_score', 0) > 70
            ],
            'failed_images': [
                r for r in self.results 
                if r.get('status') == 'FAILED'
            ]
        }
        
        return report
    
    def _calculate_duration(self) -> float:
        """Calculate analysis duration in seconds."""
        if self.statistics['start_time'] and self.statistics['end_time']:
            start = datetime.fromisoformat(self.statistics['start_time'])
            end = datetime.fromisoformat(self.statistics['end_time'])
            return (end - start).total_seconds()
        return 0
    
    def _save_results(self, output_dir: Path, batch_report: Dict[str, Any]):
        """Save batch analysis results."""
        # Save batch report JSON
        report_file = output_dir / 'batch_report.json'
        with open(report_file, 'w') as f:
            json.dump(batch_report, f, indent=2)
        
        # Save summary CSV
        summary_file = output_dir / 'batch_summary.csv'
        with open(summary_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Batch Analysis Summary'])
            writer.writerow([])
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Batch ID', batch_report['batch_metadata']['batch_id']])
            writer.writerow(['Total Images', batch_report['statistics']['total']])
            writer.writerow(['Successful', batch_report['statistics']['successful']])
            writer.writerow(['Failed', batch_report['statistics']['failed']])
            writer.writerow(['Skipped', batch_report['statistics']['skipped']])
            writer.writerow(['Success Rate', f"{batch_report['statistics']['success_rate']:.2f}%"])
            writer.writerow(['Average Risk Score', f"{batch_report['statistics']['avg_risk_score']:.2f}"])
            writer.writerow(['Duration', f"{batch_report['statistics']['duration_seconds']:.2f} seconds"])
            writer.writerow([])
            
            # Origin distribution
            writer.writerow(['Origin Distribution'])
            for origin, count in batch_report['statistics']['origin_distribution'].items():
                writer.writerow([origin, count])
        
        # Save detailed results CSV
        detailed_file = output_dir / 'detailed_results.csv'
        if self.results:
            fieldnames = list(self.results[0].keys())
            with open(detailed_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for result in self.results:
                    writer.writerow(result)
        
        # Generate HTML report
        self._generate_html_report(output_dir, batch_report)
        
        self.logger.info(f"Batch results saved to: {output_dir}")
        self.logger.info(f"  • JSON report: {report_file}")
        self.logger.info(f"  • CSV summary: {summary_file}")
        self.logger.info(f"  • Detailed CSV: {detailed_file}")
    
    def _generate_html_report(self, output_dir: Path, batch_report: Dict[str, Any]):
        """Generate HTML batch report."""
        html_file = output_dir / 'batch_report.html'
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MetaForensicAI - Batch Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #4CAF50; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #333; margin-bottom: 10px; }}
        .header .subtitle {{ color: #666; font-size: 18px; }}
        .section {{ margin-bottom: 30px; padding: 20px; background: #f9f9f9; border-radius: 5px; }}
        .section h2 {{ color: #4CAF50; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 5px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #4CAF50; margin: 10px 0; }}
        .stat-label {{ color: #666; font-size: 14px; }}
        .table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .table th {{ background: #4CAF50; color: white; padding: 12px; text-align: left; }}
        .table td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .table tr:hover {{ background: #f5f5f5; }}
        .risk-high {{ color: #e74c3c; font-weight: bold; }}
        .risk-medium {{ color: #f39c12; font-weight: bold; }}
        .risk-low {{ color: #27ae60; font-weight: bold; }}
        .status-success {{ color: #27ae60; }}
        .status-failed {{ color: #e74c3c; }}
        .status-skipped {{ color: #f39c12; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MetaForensicAI - Batch Analysis Report</h1>
            <div class="subtitle">Forensic Analysis of {batch_report['statistics']['total']} Images</div>
            <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="section">
            <h2>Batch Information</h2>
            <p><strong>Batch ID:</strong> {batch_report['batch_metadata']['batch_id']}</p>
            <p><strong>Analyst:</strong> {batch_report['batch_metadata']['analyst']}</p>
            <p><strong>Input Directory:</strong> {batch_report['batch_metadata']['input_directory']}</p>
            <p><strong>Output Directory:</strong> {batch_report['batch_metadata']['output_directory']}</p>
        </div>
        
        <div class="section">
            <h2>Analysis Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{batch_report['statistics']['total']}</div>
                    <div class="stat-label">Total Images</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{batch_report['statistics']['successful']}</div>
                    <div class="stat-label status-success">Successful</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{batch_report['statistics']['failed']}</div>
                    <div class="stat-label status-failed">Failed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{batch_report['statistics']['skipped']}</div>
                    <div class="stat-label status-skipped">Skipped</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{batch_report['statistics']['success_rate']:.1f}%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{batch_report['statistics']['duration_seconds']:.1f}s</div>
                    <div class="stat-label">Duration</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Risk Score Distribution</h2>
            <p><strong>Average Risk Score:</strong> {batch_report['statistics']['avg_risk_score']:.2f}</p>
            <p><strong>Range:</strong> {batch_report['statistics']['min_risk_score']:.2f} - {batch_report['statistics']['max_risk_score']:.2f}</p>
            <p><strong>High Risk Images (>70):</strong> {len(batch_report['high_risk_images'])}</p>
        </div>
        
        <div class="section">
            <h2>Origin Distribution</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Origin Platform</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add origin distribution rows
        total_success = batch_report['statistics']['successful']
        for origin, count in batch_report['statistics']['origin_distribution'].items():
            percentage = (count / total_success * 100) if total_success > 0 else 0
            html_content += f"""
                    <tr>
                        <td>{origin}</td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>High Risk Images</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Image Name</th>
                        <th>Risk Score</th>
                        <th>Origin</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add high risk images
        for image in batch_report['high_risk_images'][:20]:  # Limit to 20
            risk_class = 'risk-high' if image['risk_score'] > 80 else 'risk-medium'
            html_content += f"""
                    <tr>
                        <td>{image['image_name']}</td>
                        <td class="{risk_class}">{image['risk_score']}</td>
                        <td>{image['primary_origin']}</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
            <p><em>Showing top 20 high risk images</em></p>
        </div>
        
        <div class="section">
            <h2>Failed Images</h2>
        """
        
        if batch_report['failed_images']:
            html_content += """
            <table class="table">
                <thead>
                    <tr>
                        <th>Image Name</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for image in batch_report['failed_images'][:10]:  # Limit to 10
                html_content += f"""
                    <tr>
                        <td>{image['image_name']}</td>
                        <td>{image.get('error', 'Unknown error')[:100]}...</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        else:
            html_content += "<p>No failed images.</p>"
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>Report Information</h2>
            <p>This report was generated by MetaForensicAI v1.0.0</p>
            <p>System: {batch_report['batch_metadata']['system_info']['system']} {batch_report['batch_metadata']['system_info']['release']}</p>
            <p>Python: {batch_report['batch_metadata']['system_info']['python_version']}</p>
            <p>Analysis Period: {batch_report['statistics']['start_time']} to {batch_report['statistics']['end_time']}</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        return str(html_file)


def main():
    """Main entry point for batch analysis."""
    parser = argparse.ArgumentParser(
        description='Batch image analysis with MetaForensicAI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input evidence/ --output results/
  %(prog)s --input images/ --recursive --workers 8
  %(prog)s --input photos/ --max-images 100 --skip-existing
  %(prog)s --input dataset/ --config config/custom.yaml
        """
    )
    
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input directory containing images'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output directory for results (default: results/batch_TIMESTAMP)'
    )
    
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Search subdirectories recursively'
    )
    
    parser.add_argument(
        '--max-workers', '-w',
        type=int,
        default=4,
        help='Maximum parallel workers (default: 4)'
    )
    
    parser.add_argument(
        '--max-images', '-m',
        type=int,
        help='Maximum number of images to process'
    )
    
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        help='Skip images with existing reports'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick mode (skip detailed reports)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    import logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("\n" + "="*70)
    print("META FORENSIC AI - BATCH ANALYSIS".center(70))
    print("="*70 + "\n")
    
    try:
        # Initialize analyzer
        analyzer = BatchAnalyzer(config_path=args.config)
        
        # Run batch analysis
        report = analyzer.analyze_directory(
            input_dir=args.input,
            output_dir=args.output,
            recursive=args.recursive,
            max_workers=args.max_workers,
            max_images=args.max_images,
            skip_existing=args.skip_existing
        )
        
        # Display summary
        print("\n" + "="*70)
        print("BATCH ANALYSIS COMPLETE".center(70))
        print("="*70 + "\n")
        
        stats = report['statistics']
        print(f"📊 Summary:")
        print(f"   • Total Images: {stats['total']}")
        print(f"   • Successful: {stats['successful']}")
        print(f"   • Failed: {stats['failed']}")
        print(f"   • Skipped: {stats['skipped']}")
        print(f"   • Success Rate: {stats['success_rate']:.1f}%")
        print(f"   • Duration: {stats['duration_seconds']:.2f} seconds")
        print(f"   • Average Risk Score: {stats['avg_risk_score']:.2f}")
        
        print(f"\n📁 Results saved to: {report['batch_metadata']['output_directory']}")
        print(f"   • JSON report: batch_report.json")
        print(f"   • CSV summary: batch_summary.csv")
        print(f"   • HTML report: batch_report.html")
        print(f"   • Individual reports: individual_reports/")
        
        print(f"\n⚠️  High Risk Images: {len(report['high_risk_images'])}")
        for img in report['high_risk_images'][:5]:  # Show top 5
            print(f"   • {img['image_name']}: {img['risk_score']}/100")
        
        if report['failed_images']:
            print(f"\n❌ Failed Images: {len(report['failed_images'])}")
            for img in report['failed_images'][:3]:  # Show top 3
                print(f"   • {img['image_name']}: {img.get('error', 'Unknown')}")
        
        print("\n" + "="*70)
        
    except Exception as e:
        print(f"\n❌ Batch analysis failed: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()