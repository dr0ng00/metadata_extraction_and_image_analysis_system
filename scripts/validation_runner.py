#!/usr/bin/env python3
"""
Validation Test Runner Script
Run comprehensive validation tests for MetaForensicAI system.
"""

import argparse
import sys
import json
import yaml
from pathlib import Path
from datetime import datetime
import traceback
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import MetaForensicAI
from tests.test_validation import ValidationSuite, PerformanceEvaluator, DatasetValidator

class ValidationRunner:
    """Run comprehensive validation tests for MetaForensicAI."""
    
    def __init__(self, config_path=None):
        """Initialize validation runner."""
        self.config_path = config_path
        self.forensic_system: Any = None
        self.validation_suite: ValidationSuite | None = None
        self.results: Dict[str, Any] = {}
        
    def run_all_tests(self, output_dir=None) -> Dict[str, Any]:
        """Run all validation tests."""
        print("\n" + "="*70)
        print("META FORENSIC AI - VALIDATION TEST SUITE".center(70))
        print("="*70 + "\n")
        
        # Step 1: Initialize system
        print("Step 1: Initializing forensic system...")
        self._initialize_system()
        
        # Step 2: Validate test dataset
        print("\nStep 2: Validating test dataset...")
        dataset_results = self._validate_dataset()
        
        # Step 3: Run validation suite
        print("\nStep 3: Running validation tests...")
        validation_results = self._run_validation_suite()
        
        # Step 4: Performance evaluation
        print("\nStep 4: Evaluating system performance...")
        performance_results = self._evaluate_performance()
        
        # Step 5: Generate comprehensive report
        print("\nStep 5: Generating validation report...")
        self.results = self._generate_comprehensive_report(
            dataset_results,
            validation_results,
            performance_results
        )
        
        # Step 6: Save results
        if output_dir:
            self._save_results(output_dir)
        
        return self.results
    
    def _initialize_system(self):
        """Initialize forensic system for testing."""
        try:
            self.forensic_system = MetaForensicAI(config_path=self.config_path)
            self.validation_suite = ValidationSuite(self.forensic_system)
            print("  ✅ System initialized successfully")
        except Exception as e:
            print(f"  ❌ Failed to initialize system: {e}")
            raise
    
    def _validate_dataset(self) -> Dict[str, Any]:
        """Validate test dataset integrity."""
        dataset_path = Path(__file__).parent.parent / 'tests' / 'test_validation'
        validator = DatasetValidator(str(dataset_path))
        
        results = validator.generate_dataset_report()
        
        # Display summary
        structure = results['structure_validation']
        integrity = results['integrity_validation']
        
        print(f"  📁 Dataset Path: {results['dataset_path']}")
        print(f"  ✅ Structure: {structure['structure_valid'] and 'VALID' or 'INVALID'}")
        print(f"  📊 Statistics:")
        for section, count in structure['statistics'].items():
            print(f"    • {section}: {count} images")
        
        print(f"  🔍 Integrity: {integrity['valid_images']}/{integrity['total_images']} valid")
        if integrity['corrupted_images']:
            print(f"  ⚠️  Corrupted: {len(integrity['corrupted_images'])} images")
        
        return results
    
    def _run_validation_suite(self) -> Dict[str, Any]:
        """Run comprehensive validation suite."""
        if not self.validation_suite:
            raise RuntimeError("Validation suite not initialized. Call _initialize_system() first.")
        
        results = self.validation_suite.run_comprehensive_validation()
        
        # Display test results
        print("  📊 Validation Results:")
        
        for test_name, result in results.items():
            if isinstance(result, dict) and 'test_name' in result:
                if 'accuracy' in result:
                    accuracy_pct = result['accuracy'] * 100
                    status = "✅" if accuracy_pct >= 90 else "⚠️" if accuracy_pct >= 70 else "❌"
                    print(f"    {status} {test_name}: {accuracy_pct:.1f}%")
                elif 'consistency_score' in result:
                    print(f"    📈 {test_name}: {result['consistency_score']:.1f}/100")
        
        # Calculate overall score
        accuracy_scores = []
        for test_name, result in results.items():
            if isinstance(result, dict) and 'accuracy' in result:
                accuracy_scores.append(result['accuracy'])
        
        if accuracy_scores:
            overall_accuracy = sum(accuracy_scores) / len(accuracy_scores) * 100
            print(f"  🎯 Overall Accuracy: {overall_accuracy:.1f}%")
        
        return results
    
    def _evaluate_performance(self) -> Dict[str, Any]:
        """Evaluate system performance."""
        evaluator = PerformanceEvaluator(self.forensic_system)
        
        # Run performance tests
        batch_performance = evaluator.evaluate_batch_performance(image_count=5)
        
        print("  ⚡ Performance Metrics:")
        if 'metrics' in batch_performance:
            metrics = batch_performance['metrics']
            print(f"    • Avg Execution Time: {metrics.get('avg_execution_time', 0):.2f}s")
            print(f"    • Throughput: {metrics.get('throughput', 0):.2f} images/second")
        
        return batch_performance
    
    def _generate_comprehensive_report(self, dataset_results, validation_results, performance_results) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        report = {
            'validation_report': {
                'id': f"VALIDATION-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'generated': datetime.now().isoformat(),
                'system': 'MetaForensicAI v1.0.0',
                'purpose': 'Comprehensive system validation'
            },
            'dataset_validation': dataset_results,
            'test_results': validation_results,
            'performance_evaluation': performance_results,
            'summary': self._generate_summary(validation_results, performance_results),
            'recommendations': self._generate_recommendations(validation_results, performance_results)
        }
        
        return report
    
    def _generate_summary(self, validation_results, performance_results) -> Dict[str, Any]:
        """Generate validation summary."""
        # Calculate overall metrics
        test_accuracies = []
        test_details = {}
        
        for test_name, result in validation_results.items():
            if isinstance(result, dict):
                if 'accuracy' in result:
                    test_accuracies.append(result['accuracy'])
                    test_details[test_name] = {
                        'accuracy': result['accuracy'] * 100,
                        'total_tests': result.get('total_tests', 0),
                        'passed_tests': result.get('passed_tests', 0)
                    }
        
        overall_accuracy = (sum(test_accuracies) / len(test_accuracies) * 100) if test_accuracies else 0
        
        return {
            'overall_accuracy': overall_accuracy,
            'total_tests_run': sum(r.get('total_tests', 0) for r in validation_results.values() if isinstance(r, dict)),
            'tests_passed': sum(r.get('passed_tests', 0) for r in validation_results.values() if isinstance(r, dict)),
            'performance_metrics': performance_results.get('metrics', {}),
            'validation_status': 'PASS' if overall_accuracy >= 85 else 'WARNING' if overall_accuracy >= 70 else 'FAIL'
        }
    
    def _generate_recommendations(self, validation_results, performance_results) -> List[Dict[str, Any]]:
        """Generate recommendations based on validation results."""
        recommendations = []
        
        # Check accuracy thresholds
        for test_name, result in validation_results.items():
            if isinstance(result, dict) and 'accuracy' in result:
                accuracy = result['accuracy'] * 100
                if accuracy < 80:
                    recommendations.append({
                        'priority': 'HIGH' if accuracy < 70 else 'MEDIUM',
                        'area': test_name,
                        'issue': f'Accuracy below threshold ({accuracy:.1f}%)',
                        'suggestion': f'Review and improve {test_name} algorithms'
                    })
        
        # Check performance
        metrics = performance_results.get('metrics', {})
        avg_time = metrics.get('avg_execution_time', 10)
        if avg_time > 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'area': 'Performance',
                'issue': f'Slow analysis time ({avg_time:.2f}s per image)',
                'suggestion': 'Optimize processing pipeline and enable caching'
            })
        
        # Check dataset issues
        if 'dataset' in validation_results:
            dataset = validation_results['dataset']
            if dataset.get('overall_status') != 'VALID':
                recommendations.append({
                    'priority': 'MEDIUM',
                    'area': 'Test Dataset',
                    'issue': 'Dataset validation issues',
                    'suggestion': 'Review and fix test dataset structure'
                })
        
        if not recommendations:
            recommendations.append({
                'priority': 'LOW',
                'area': 'General',
                'issue': 'No major issues detected',
                'suggestion': 'System meets validation criteria'
            })
        
        return recommendations
    
    def _save_results(self, output_dir: str):
        """Save validation results to output directory."""
        output_path = Path(output_dir) / 'validation_results'
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save full results as JSON
        json_file = output_path / f'validation_results_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save summary as YAML
        yaml_file = output_path / f'validation_summary_{timestamp}.yaml'
        summary = {
            'validation_summary': self.results['summary'],
            'recommendations': self.results['recommendations']
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(summary, f, default_flow_style=False)
        
        # Generate human-readable report
        report_file = output_path / f'validation_report_{timestamp}.md'
        self._generate_markdown_report(report_file)
        
        print(f"\n📄 Validation results saved to: {output_path}")
        print(f"   • Full results: {json_file.name}")
        print(f"   • Summary: {yaml_file.name}")
        print(f"   • Report: {report_file.name}")
    
    def _generate_markdown_report(self, report_file: Path):
        """Generate markdown validation report."""
        report = [
            "# MetaForensicAI Validation Report",
            "",
            f"**Report ID:** {self.results['validation_report']['id']}",
            f"**Generated:** {self.results['validation_report']['generated']}",
            f"**System:** {self.results['validation_report']['system']}",
            "",
            "## Executive Summary",
            "",
            f"- **Overall Accuracy:** {self.results['summary']['overall_accuracy']:.1f}%",
            f"- **Validation Status:** {self.results['summary']['validation_status']}",
            f"- **Total Tests:** {self.results['summary']['total_tests_run']}",
            f"- **Tests Passed:** {self.results['summary']['tests_passed']}",
            "",
            "## Test Results",
            ""
        ]
        
        # Add test results
        for test_name, result in self.results['test_results'].items():
            if isinstance(result, dict) and 'test_name' in result:
                report.append(f"### {result['test_name']}")
                report.append("")
                
                if 'accuracy' in result:
                    report.append(f"- **Accuracy:** {result['accuracy']*100:.1f}%")
                
                if 'total_tests' in result:
                    report.append(f"- **Total Tests:** {result['total_tests']}")
                    report.append(f"- **Passed:** {result.get('passed_tests', 0)}")
                    report.append(f"- **Failed:** {result.get('failed_tests', 0)}")
                
                report.append("")
        
        # Add performance metrics
        report.append("## Performance Evaluation")
        report.append("")
        
        metrics = self.results['performance_evaluation'].get('metrics', {})
        if metrics:
            report.append(f"- **Average Execution Time:** {metrics.get('avg_execution_time', 0):.2f} seconds")
            report.append(f"- **Throughput:** {metrics.get('throughput', 0):.2f} images/second")
            report.append(f"- **Total Execution Time:** {metrics.get('total_execution_time', 0):.2f} seconds")
        else:
            report.append("- No performance metrics available")
        
        report.append("")
        
        # Add recommendations
        report.append("## Recommendations")
        report.append("")
        
        for rec in self.results['recommendations']:
            priority_icon = '🔴' if rec['priority'] == 'HIGH' else '🟡' if rec['priority'] == 'MEDIUM' else '🟢'
            report.append(f"{priority_icon} **{rec['priority']}** - {rec['area']}")
            report.append(f"  - **Issue:** {rec['issue']}")
            report.append(f"  - **Suggestion:** {rec['suggestion']}")
            report.append("")
        
        # Add conclusion
        report.append("## Conclusion")
        report.append("")
        
        status = self.results['summary']['validation_status']
        accuracy = self.results['summary']['overall_accuracy']
        
        if status == 'PASS':
            report.append(f"✅ The MetaForensicAI system has passed validation with {accuracy:.1f}% overall accuracy.")
            report.append("The system meets the required standards for forensic analysis.")
        elif status == 'WARNING':
            report.append(f"⚠️  The system has passed validation with warnings ({accuracy:.1f}% accuracy).")
            report.append("Some areas require improvement before production deployment.")
        else:
            report.append(f"❌ The system has failed validation ({accuracy:.1f}% accuracy).")
            report.append("Significant improvements are required before the system can be used.")
        
        report.append("")
        report.append("---")
        report.append("*Generated by MetaForensicAI Validation Suite*")
        
        with open(report_file, 'w') as f:
            f.write('\n'.join(report))
        
        return str(report_file)


def main():
    """Main entry point for validation runner."""
    parser = argparse.ArgumentParser(
        description='Run validation tests for MetaForensicAI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --output validation_results/
  %(prog)s --quick --config config/test_config.yaml
  %(prog)s --specific timestamp --verbose
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        default='./results/validation',
        help='Output directory for validation results'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Configuration file for testing'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Run quick validation (skip performance tests)'
    )
    
    parser.add_argument(
        '--specific',
        choices=['timestamp', 'origin', 'authenticity', 'risk', 'explanations'],
        help='Run specific test only'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    import logging
    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Create output directory
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Run validation
        runner = ValidationRunner(config_path=args.config)
        results = runner.run_all_tests(output_dir=args.output)
        
        # Display final summary
        print("\n" + "="*70)
        print("VALIDATION COMPLETE".center(70))
        print("="*70 + "\n")
        
        summary = results['summary']
        print(f"📊 Final Results:")
        print(f"   • Overall Accuracy: {summary['overall_accuracy']:.1f}%")
        print(f"   • Validation Status: {summary['validation_status']}")
        print(f"   • Tests Run: {summary['total_tests_run']}")
        print(f"   • Tests Passed: {summary['tests_passed']}")
        
        print(f"\n⚠️  Recommendations: {len(results['recommendations'])}")
        for rec in results['recommendations'][:3]:  # Show top 3
            print(f"   • {rec['priority']}: {rec['area']} - {rec['issue']}")
        
        if len(results['recommendations']) > 3:
            print(f"   • ... and {len(results['recommendations']) - 3} more")
        
        print(f"\n📁 Results saved to: {output_path}")
        
        # Exit code based on validation status
        if summary['validation_status'] == 'FAIL':
            sys.exit(1)
        elif summary['validation_status'] == 'WARNING':
            sys.exit(2)
        else:
            sys.exit(0)
            
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        if args.debug or args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()