#!/usr/bin/env python3
"""
Forensic Environment Setup Script
Sets up a forensically sound analysis environment for MetaForensicAI.
"""

import os
import sys
import json
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
import subprocess
import platform
import stat

class ForensicEnvironmentSetup:
    """Setup forensic analysis environment with proper security controls."""
    
    def __init__(self, workspace_dir=None):
        """Initialize forensic environment setup."""
        self.workspace_dir = Path(workspace_dir or './forensic_workspace')
        self.config_dir = Path('./config')
        self.results_dir = Path('./results')
        self.evidence_dir = Path('./evidence')
        
        # Forensic configuration
        self.config = {
            'environment': {
                'name': 'MetaForensicAI_Forensic_Workspace',
                'version': '1.0.0',
                'created': datetime.now().isoformat(),
                'hostname': platform.node(),
                'platform': platform.platform()
            },
            'security': {
                'read_only_evidence': True,
                'audit_logging': True,
                'hash_verification': True,
                'access_control': True
            },
            'directories': {
                'workspace': str(self.workspace_dir),
                'evidence': str(self.evidence_dir),
                'results': str(self.results_dir),
                'config': str(self.config_dir)
            }
        }
    
    def setup_complete_environment(self):
        """Setup complete forensic analysis environment."""
        print("=" * 70)
        print("FORENSIC ENVIRONMENT SETUP".center(70))
        print("=" * 70)
        print()
        
        # Step 1: Verify system requirements
        print("Step 1: Verifying system requirements...")
        self.verify_system_requirements()
        
        # Step 2: Create forensic directories
        print("\nStep 2: Creating forensic directory structure...")
        self.create_forensic_directories()
        
        # Step 3: Set directory permissions
        print("\nStep 3: Setting security permissions...")
        self.set_forensic_permissions()
        
        # Step 4: Initialize audit logging
        print("\nStep 4: Initializing audit system...")
        self.initialize_audit_system()
        
        # Step 5: Create chain of custody
        print("\nStep 5: Creating chain of custody...")
        self.create_chain_of_custody()
        
        # Step 6: Verify environment integrity
        print("\nStep 6: Verifying environment integrity...")
        self.verify_environment_integrity()
        
        # Step 7: Generate setup report
        print("\nStep 7: Generating setup report...")
        report = self.generate_setup_report()
        
        print("\n" + "=" * 70)
        print("SETUP COMPLETE".center(70))
        print("=" * 70)
        
        return report
    
    def verify_system_requirements(self):
        """Verify system meets forensic requirements."""
        requirements = {
            'python_version': (3, 8),
            'disk_space_mb': 1000,  # 1GB minimum
            'ram_mb': 4096,  # 4GB RAM minimum
            'tools': ['exiftool', 'python3']
        }
        
        results = {
            'passed': [],
            'warnings': [],
            'errors': []
        }
        
        # Check Python version
        py_version = sys.version_info
        if py_version.major >= requirements['python_version'][0] and \
           py_version.minor >= requirements['python_version'][1]:
            results['passed'].append(f"Python {py_version.major}.{py_version.minor}.{py_version.micro}")
        else:
            results['errors'].append(f"Python {requirements['python_version'][0]}.{requirements['python_version'][1]}+ required")
        
        # Check disk space
        try:
            import shutil
            total, used, free = shutil.disk_usage('.')
            free_mb = free // (1024 * 1024)
            if free_mb >= requirements['disk_space_mb']:
                results['passed'].append(f"Disk space: {free_mb}MB available")
            else:
                results['warnings'].append(f"Low disk space: {free_mb}MB (recommended: {requirements['disk_space_mb']}MB)")
        except:
            results['warnings'].append("Could not check disk space")
        
        # Check required tools
        for tool in requirements['tools']:
            try:
                if tool == 'python3':
                    subprocess.run([tool, '--version'], capture_output=True, check=True)
                else:
                    subprocess.run([tool, '-ver'], capture_output=True, check=True)
                results['passed'].append(f"Tool: {tool}")
            except (subprocess.CalledProcessError, FileNotFoundError):
                if tool == 'exiftool':
                    results['warnings'].append(f"Tool missing: {tool} (required for full metadata extraction)")
                else:
                    results['errors'].append(f"Tool missing: {tool}")
        
        # Display results
        for item in results['passed']:
            print(f"  ✅ {item}")
        
        for item in results['warnings']:
            print(f"  ⚠️  {item}")
        
        for item in results['errors']:
            print(f"  ❌ {item}")
        
        if results['errors']:
            print("\n⚠️  Critical requirements missing. Setup may fail.")
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                sys.exit(1)
        
        return results
    
    def create_forensic_directories(self):
        """Create forensic directory structure."""
        directories = {
            'workspace': [
                'temp',
                'backups',
                'cache',
                'evidence_copies',
                'logs/audit',
                'logs/system',
                'logs/analysis'
            ],
            'results': [
                'reports/pdf',
                'reports/json',
                'reports/html',
                'exports',
                'comparisons',
                'timelines'
            ],
            'evidence': [
                'received',
                'processed',
                'archived',
                'quarantine'
            ],
            'config': [
                'backups',
                'templates',
                'rules'
            ]
        }
        
        created_dirs = []
        
        # Create main directories
        for main_dir, subdirs in directories.items():
            dir_path = getattr(self, f'{main_dir}_dir')
            dir_path.mkdir(parents=True, exist_ok=True)
            created_dirs.append(str(dir_path))
            
            # Create subdirectories
            for subdir in subdirs:
                subdir_path = dir_path / subdir
                subdir_path.mkdir(parents=True, exist_ok=True)
                created_dirs.append(str(subdir_path))
        
        # Create readme files
        readme_content = """# Forensic Workspace
        
This directory contains forensic analysis workspaces and should be treated as 
sensitive. All operations are logged for chain of custody.
        
DO NOT MODIFY FILES IN THIS DIRECTORY MANUALLY.
All modifications should be performed through the MetaForensicAI system.
"""
        
        for readme_dir in [self.workspace_dir, self.evidence_dir]:
            readme_file = readme_dir / 'README_FORENSIC.txt'
            readme_file.write_text(readme_content)
            created_dirs.append(str(readme_file))
        
        print(f"  ✅ Created {len(created_dirs)} directories")
        return created_dirs
    
    def set_forensic_permissions(self):
        """Set forensically appropriate permissions."""
        permission_settings = {
            'evidence': {
                'dir': self.evidence_dir,
                'mode': 0o555,  # Read and execute only
                'description': 'Evidence directory (read-only)'
            },
            'workspace': {
                'dir': self.workspace_dir,
                'mode': 0o700,  # Owner read/write/execute only
                'description': 'Forensic workspace (restricted)'
            },
            'results': {
                'dir': self.results_dir,
                'mode': 0o755,  # Owner full, others read/execute
                'description': 'Results directory (controlled access)'
            }
        }
        
        set_permissions = []
        
        for name, settings in permission_settings.items():
            try:
                settings['dir'].chmod(settings['mode'])
                set_permissions.append(f"{name}: {settings['description']}")
                print(f"  ✅ {settings['description']}")
            except Exception as e:
                print(f"  ⚠️  Could not set permissions for {name}: {e}")
        
        # Set sticky bit on workspace to prevent deletion
        try:
            os.chmod(str(self.workspace_dir), os.stat(str(self.workspace_dir)).st_mode | stat.S_ISVTX)
            print("  ✅ Set sticky bit on workspace directory")
        except:
            pass
        
        return set_permissions
    
    def initialize_audit_system(self):
        """Initialize forensic audit logging system."""
        audit_config = {
            'system': {
                'name': 'MetaForensicAI_Audit_System',
                'version': '1.0.0',
                'start_time': datetime.now().isoformat()
            },
            'logging': {
                'levels': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                'formats': {
                    'audit': '%(asctime)s | %(levelname)s | %(user)s | %(action)s | %(target)s | %(details)s',
                    'system': '%(asctime)s | %(levelname)s | %(module)s | %(message)s'
                }
            },
            'retention': {
                'audit_logs_days': 365,
                'system_logs_days': 90,
                'max_log_size_mb': 100
            }
        }
        
        # Create audit configuration
        audit_dir = self.workspace_dir / 'logs' / 'audit'
        audit_config_file = audit_dir / 'audit_config.json'
        
        with open(audit_config_file, 'w') as f:
            json.dump(audit_config, f, indent=2)
        
        # Create initial audit entry
        initial_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': 'ENVIRONMENT_SETUP',
            'user': os.getlogin() if hasattr(os, 'getlogin') else 'system',
            'action': 'initialize',
            'target': 'forensic_environment',
            'details': {
                'workspace': str(self.workspace_dir),
                'hostname': platform.node(),
                'python_version': platform.python_version()
            },
            'integrity_hashes': self._calculate_directory_hashes()
        }
        
        audit_log_file = audit_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.json"
        
        # Create or append to audit log
        if audit_log_file.exists():
            with open(audit_log_file, 'r') as f:
                audit_log = json.load(f)
        else:
            audit_log = {'entries': []}
        
        audit_log['entries'].append(initial_entry)
        
        with open(audit_log_file, 'w') as f:
            json.dump(audit_log, f, indent=2)
        
        print(f"  ✅ Audit system initialized: {audit_log_file}")
        return str(audit_log_file)
    
    def _calculate_directory_hashes(self):
        """Calculate integrity hashes for critical directories."""
        dirs_to_hash = [
            str(self.config_dir),
            str(self.workspace_dir / 'logs'),
            str(self.results_dir)
        ]
        
        hashes = {}
        for dir_path in dirs_to_hash:
            if Path(dir_path).exists():
                dir_hash = self._hash_directory(dir_path)
                hashes[Path(dir_path).name] = dir_hash
        
        return hashes
    
    def _hash_directory(self, directory_path):
        """Calculate SHA-256 hash of directory contents."""
        directory = Path(directory_path)
        hash_objects = {}
        
        # Initialize hash for each algorithm
        for alg in ['sha256', 'sha3_256']:
            hash_objects[alg] = getattr(hashlib, alg)()
        
        # Walk through directory and hash all files
        for root, dirs, files in os.walk(directory):
            # Sort for consistent hashing
            dirs.sort()
            files.sort()
            
            for file in files:
                file_path = Path(root) / file
                try:
                    with open(file_path, 'rb') as f:
                        while chunk := f.read(8192):
                            for hash_obj in hash_objects.values():
                                hash_obj.update(chunk)
                except (IOError, PermissionError):
                    pass
        
        # Return dictionary of hashes
        return {alg: hash_obj.hexdigest() for alg, hash_obj in hash_objects.items()}
    
    def create_chain_of_custody(self):
        """Create initial chain of custody document."""
        chain_config = {
            'chain_id': f"COC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'creation_time': datetime.now().isoformat(),
            'environment': {
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'hostname': platform.node()
            },
            'software': {
                'metaforensicai_version': '1.0.0',
                'python_version': platform.python_version(),
                'exiftool_version': self._get_exiftool_version()
            },
            'directories': {
                'workspace': str(self.workspace_dir.absolute()),
                'evidence': str(self.evidence_dir.absolute()),
                'results': str(self.results_dir.absolute())
            },
            'security': {
                'read_only_evidence': True,
                'audit_logging': True,
                'hash_verification': True
            }
        }
        
        # Create chain of custody file
        chain_file = self.workspace_dir / 'chain_of_custody' / 'initial_chain.json'
        chain_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(chain_file, 'w') as f:
            json.dump(chain_config, f, indent=2)
        
        # Also create a human-readable version
        human_chain = self.workspace_dir / 'chain_of_custody' / 'chain_of_custody.txt'
        with open(human_chain, 'w') as f:
            f.write(f"CHAIN OF CUSTODY - META FORENSIC AI\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"Chain ID: {chain_config['chain_id']}\n")
            f.write(f"Created: {chain_config['creation_time']}\n")
            f.write(f"\nENVIRONMENT:\n")
            f.write(f"  System: {chain_config['environment']['system']}\n")
            f.write(f"  Hostname: {chain_config['environment']['hostname']}\n")
            f.write(f"\nSOFTWARE:\n")
            f.write(f"  MetaForensicAI: {chain_config['software']['metaforensicai_version']}\n")
            f.write(f"  Python: {chain_config['software']['python_version']}\n")
            f.write(f"  ExifTool: {chain_config['software']['exiftool_version']}\n")
            f.write(f"\nDIRECTORIES:\n")
            f.write(f"  Workspace: {chain_config['directories']['workspace']}\n")
            f.write(f"  Evidence: {chain_config['directories']['evidence']}\n")
            f.write(f"  Results: {chain_config['directories']['results']}\n")
            f.write(f"\nSECURITY CONTROLS:\n")
            for control, enabled in chain_config['security'].items():
                f.write(f"  {control.replace('_', ' ').title()}: {'Enabled' if enabled else 'Disabled'}\n")
            f.write(f"\n{'='*50}\n")
            f.write(f"END OF CHAIN OF CUSTODY\n")
        
        print(f"  ✅ Chain of custody created: {chain_file}")
        return str(chain_file)
    
    def _get_exiftool_version(self):
        """Get ExifTool version if available."""
        try:
            result = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return "Not available"
    
    def verify_environment_integrity(self):
        """Verify the integrity of the forensic environment."""
        print("  Verifying directory structure...")
        
        required_dirs = [
            self.workspace_dir,
            self.evidence_dir,
            self.results_dir,
            self.workspace_dir / 'logs' / 'audit',
            self.workspace_dir / 'chain_of_custody',
            self.results_dir / 'reports' / 'pdf'
        ]
        
        missing_dirs = []
        for dir_path in required_dirs:
            if not dir_path.exists():
                missing_dirs.append(str(dir_path))
        
        if missing_dirs:
            print(f"  ⚠️  Missing directories: {len(missing_dirs)}")
            for missing in missing_dirs[:3]:  # Show first 3
                print(f"    • {missing}")
            if len(missing_dirs) > 3:
                print(f"    • ... and {len(missing_dirs) - 3} more")
        else:
            print("  ✅ All required directories present")
        
        # Check file permissions
        print("  Checking file permissions...")
        evidence_perms = oct(self.evidence_dir.stat().st_mode)[-3:]
        if evidence_perms == '555':
            print("  ✅ Evidence directory permissions correct (read-only)")
        else:
            print(f"  ⚠️  Evidence directory permissions: {evidence_perms} (should be 555)")
        
        # Calculate environment hash
        print("  Calculating environment integrity hash...")
        env_hash = self._hash_directory(str(self.workspace_dir))
        hash_file = self.workspace_dir / 'environment_integrity.hash'
        
        with open(hash_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'directory': str(self.workspace_dir),
                'hashes': env_hash
            }, f, indent=2)
        
        print(f"  ✅ Environment integrity hash saved: {env_hash['sha256'][:16]}...")
        
        return {
            'missing_dirs': missing_dirs,
            'evidence_perms': evidence_perms,
            'integrity_hash': env_hash['sha256'][:32]
        }
    
    def generate_setup_report(self):
        """Generate comprehensive setup report."""
        report = {
            'setup_report': {
                'id': f"SETUP-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'timestamp': datetime.now().isoformat(),
                'status': 'COMPLETED'
            },
            'environment': self.config['environment'],
            'directories': self.config['directories'],
            'security': self.config['security'],
            'verification': self.verify_environment_integrity()
        }
        
        # Save report
        report_dir = self.results_dir / 'setup_reports'
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_file_json = report_dir / f"{report['setup_report']['id']}.json"
        report_file_txt = report_dir / f"{report['setup_report']['id']}.txt"
        
        # JSON version
        with open(report_file_json, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Human-readable version
        with open(report_file_txt, 'w') as f:
            f.write("META FORENSIC AI - ENVIRONMENT SETUP REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Report ID: {report['setup_report']['id']}\n")
            f.write(f"Generated: {report['setup_report']['timestamp']}\n")
            f.write(f"Status: {report['setup_report']['status']}\n\n")
            
            f.write("ENVIRONMENT:\n")
            f.write("-" * 40 + "\n")
            for key, value in report['environment'].items():
                f.write(f"  {key}: {value}\n")
            
            f.write("\nDIRECTORIES:\n")
            f.write("-" * 40 + "\n")
            for key, value in report['directories'].items():
                f.write(f"  {key}: {value}\n")
            
            f.write("\nSECURITY CONTROLS:\n")
            f.write("-" * 40 + "\n")
            for key, value in report['security'].items():
                f.write(f"  {key}: {'ENABLED' if value else 'DISABLED'}\n")
            
            f.write("\nVERIFICATION RESULTS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Missing Directories: {len(report['verification']['missing_dirs'])}\n")
            f.write(f"  Evidence Permissions: {report['verification']['evidence_perms']}\n")
            f.write(f"  Integrity Hash: {report['verification']['integrity_hash']}\n\n")
            
            f.write("=" * 60 + "\n")
            f.write("END OF REPORT\n")
        
        print(f"  ✅ Setup report generated: {report_file_json}")
        print(f"  ✅ Human-readable report: {report_file_txt}")
        
        return str(report_file_json)


def main():
    """Main entry point for forensic environment setup."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Setup forensic analysis environment for MetaForensicAI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Setup with default workspace
  %(prog)s --workspace /forensic  # Custom workspace location
  %(prog)s --quick                # Quick setup with minimal verification
        """
    )
    
    parser.add_argument(
        '--workspace',
        default='./forensic_workspace',
        help='Forensic workspace directory (default: ./forensic_workspace)'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick setup (skip detailed verification)'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force setup even if workspace exists'
    )
    
    args = parser.parse_args()
    
    # Check if workspace already exists
    workspace_path = Path(args.workspace)
    if workspace_path.exists() and not args.force:
        print(f"Workspace already exists: {workspace_path}")
        response = input("Continue and overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Setup cancelled.")
            sys.exit(0)
    
    # Run setup
    setup = ForensicEnvironmentSetup(workspace_dir=args.workspace)
    report = setup.setup_complete_environment()
    
    print(f"\nSetup completed successfully!")
    print(f"Report saved: {report}")
    print(f"\nNext steps:")
    print(f"1. Place evidence in: {setup.evidence_dir}")
    print(f"2. Run analysis: python -m src.main --image evidence/sample.jpg")
    print(f"3. Check logs in: {setup.workspace_dir / 'logs'}")
    print(f"\nForensic environment ready for analysis.")


if __name__ == "__main__":
    main()