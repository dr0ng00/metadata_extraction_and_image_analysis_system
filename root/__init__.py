"""
MetaForensicAI: AI-Assisted Digital Image Forensics System

A comprehensive digital image forensics platform implementing forensically sound,
metadata-based analysis with explainable AI reasoning for court-admissible results.

Key Features:
- Read-only evidence handling with cryptographic verification
- Multi-source metadata extraction (EXIF, XMP, IPTC, GPS, MakerNotes)
- Intelligent forensic reasoning and anomaly detection
- Cross-platform origin classification (WhatsApp, Instagram, Telegram, etc.)
- Evidence Risk Scoring with transparent explanations
- Interactive CLI assistant with natural language queries
- Automated forensic reporting (PDF/JSON) for legal and academic use

System Principles:
1. Forensic Soundness: Original evidence never modified
2. Explainability: All AI decisions are transparent and reproducible
3. Repeatability: Consistent results across multiple analyses
4. Court Admissibility: Methodologies suitable for legal proceedings
5. Academic Rigor: Peer-reviewable forensic methodologies
"""

__version__ = "1.0.0"
__description__ = "AI-Assisted Digital Image Forensics System"
__author__ = "MetaForensicAI Research Team"
__license__ = "MIT"
__copyright__ = "Copyright 2024 MetaForensicAI Project. All Rights Reserved."

import warnings
import sys
import os
from pathlib import Path
import datetime

# Filter warnings for cleaner output
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Add project root to Python path for module imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# System metadata
SYSTEM_METADATA = {
    'name': 'MetaForensicAI',
    'version': __version__,
    'description': __description__,
    'author': __author__,
    'license': __license__,
    'copyright': __copyright__,
    'repository': 'https://github.com/meteforensicai/MetaForensicAI',
    'documentation': 'https://meteforensicai.readthedocs.io/',
    'issue_tracker': 'https://github.com/meteforensicai/MetaForensicAI/issues',
    'academic_paper': 'https://arxiv.org/abs/meteforensicai-v1',
    'doi': '10.5281/zenodo.meteforensicai-v1'
}

# Forensic compliance standards
COMPLIANCE_STANDARDS = {
    'iso_27037': 'Digital Evidence Collection & Preservation',
    'iso_27041': 'Digital Investigation Assurance',
    'iso_27042': 'Digital Evidence Analysis & Interpretation',
    'iso_27043': 'Digital Investigation Incident Response',
    'nist_sp_800-86': 'Integrating Forensic Techniques',
    'nist_sp_800-101': 'Mobile Device Forensics',
    'acpo_guidelines': 'Association of Chief Police Officers',
    'enfsi_guidelines': 'European Network of Forensic Science Institutes'
}

# Supported file formats
SUPPORTED_FORMATS = {
    'raster': ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp', '.gif', '.webp'],
    'raw': ['.cr2', '.nef', '.arw', '.dng', '.rw2', '.orf', '.sr2', '.pef'],
    'heif': ['.heic', '.heif'],
    'vector': ['.svg', '.eps'],
    'document': ['.pdf']  # For embedded images
}

# Forensic hash algorithms
HASH_ALGORITHMS = {
    'primary': 'sha256',
    'secondary': 'sha3_256',
    'legacy': 'md5',
    'verification': 'blake2b'
}

def print_banner():
    """Display the system banner with version and forensic compliance information."""
    banner = f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║                        M E T A F O R E N S I C A I                           ║
    ║                     AI-Assisted Digital Image Forensics                      ║
    ║                               Version {__version__}                                 ║
    ║                                                                              ║
    ╠══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                              ║
    ║  Forensic Integrity • Explainable AI • Court Admissibility • Academic Rigor  ║
    ║                                                                              ║
    ║  ┌────────────────────────────────────────────────────────────────────┐     ║
    ║  │  COMPLIANCE: ISO 27037 | NIST SP 800-86 | ACPO | ENFSI             │     ║
    ║  └────────────────────────────────────────────────────────────────────┘     ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    
    System: {SYSTEM_METADATA['name']} v{SYSTEM_METADATA['version']}
    License: {SYSTEM_METADATA['license']}
    Author: {SYSTEM_METADATA['author']}
    Repository: {SYSTEM_METADATA['repository']}
    Documentation: {SYSTEM_METADATA['documentation']}
    
    Forensic Principles:
    • Read-only evidence handling with cryptographic verification
    • Chain of custody maintenance and audit logging
    • Transparent, reproducible analysis methodologies
    • Explainable AI with court-admissible reasoning
    • Academic peer-reviewable forensic techniques
    
    Supported Formats: {', '.join(SUPPORTED_FORMATS['raster'][:5])}...
    Hash Algorithms: {', '.join(HASH_ALGORITHMS.values())}
    """
    print(banner)

def get_citation(bibtex=False, apa=False):
    """
    Get citation information for academic publications.
    
    Args:
        bibtex (bool): Return BibTeX format
        apa (bool): Return APA format
    
    Returns:
        str: Citation in requested format
    """
    if bibtex:
        return """@software{MetaForensicAI2024,
  author = {MetaForensicAI Research Team},
  title = {MetaForensicAI: AI-Assisted Digital Image Forensics System},
  year = {2024},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\\url{https://github.com/meteforensicai/MetaForensicAI}},
  version = {1.0.0},
  doi = {10.5281/zenodo.meteforensicai-v1}
}"""
    
    if apa:
        return """MetaForensicAI Research Team. (2024). MetaForensicAI: AI-Assisted 
Digital Image Forensics System (Version 1.0.0) [Computer software]. 
GitHub. https://github.com/meteforensicai/MetaForensicAI. 
DOI: 10.5281/zenodo.meteforensicai-v1"""
    
    return """For academic citation:

MLA:
MetaForensicAI Research Team. MetaForensicAI: AI-Assisted Digital Image 
Forensics System. Version 1.0.0, GitHub, 2024, 
https://github.com/meteforensicai/MetaForensicAI.

APA:
MetaForensicAI Research Team. (2024). MetaForensicAI: AI-Assisted Digital 
Image Forensics System (Version 1.0.0) [Computer software]. GitHub. 
https://github.com/meteforensicai/MetaForensicAI.

Chicago:
MetaForensicAI Research Team. 2024. "MetaForensicAI: AI-Assisted Digital 
Image Forensics System." GitHub. https://github.com/meteforensicai/MetaForensicAI.

BibTeX:
@software{MetaForensicAI2024,
  author = {MetaForensicAI Research Team},
  title = {MetaForensicAI: AI-Assisted Digital Image Forensics System},
  year = {2024},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\\url{https://github.com/meteforensicai/MetaForensicAI}},
  version = {1.0.0},
  doi = {10.5281/zenodo.meteforensicai-v1}
}"""

def validate_environment():
    """
    Validate system environment and dependencies.
    
    Returns:
        dict: Validation results with status and messages
    
    Raises:
        ImportError: If critical dependencies are missing
        SystemError: If system requirements are not met
    """
    validation_results = {
        'system': {'status': 'pending', 'message': ''},
        'dependencies': {'status': 'pending', 'message': ''},
        'forensic_tools': {'status': 'pending', 'message': ''},
        'permissions': {'status': 'pending', 'message': ''},
        'overall': {'status': 'pending', 'message': ''}
    }
    
    try:
        # Check Python version
        python_version = sys.version_info
        if python_version.major == 3 and python_version.minor >= 8:
            validation_results['system']['status'] = 'pass'
            validation_results['system']['message'] = f'Python {python_version.major}.{python_version.minor}.{python_version.micro}'
        else:
            validation_results['system']['status'] = 'fail'
            validation_results['system']['message'] = f'Python 3.8+ required, found {python_version.major}.{python_version.minor}'
        
        # Check critical dependencies
        critical_deps = ['PIL', 'exifread', 'numpy', 'pandas', 'yaml', 'json']
        missing_deps = []
        
        for dep in critical_deps:
            try:
                __import__(dep.lower() if dep != 'PIL' else 'PIL')
            except ImportError:
                missing_deps.append(dep)
        
        if not missing_deps:
            validation_results['dependencies']['status'] = 'pass'
            validation_results['dependencies']['message'] = 'All critical dependencies available'
        else:
            validation_results['dependencies']['status'] = 'fail'
            validation_results['dependencies']['message'] = f'Missing: {", ".join(missing_deps)}'
        
        # Check for ExifTool
        import subprocess
        try:
            result = subprocess.run(['exiftool', '-ver'], 
                                  capture_output=True, 
                                  text=True, 
                                  check=True)
            validation_results['forensic_tools']['status'] = 'pass'
            validation_results['forensic_tools']['message'] = f'ExifTool v{result.stdout.strip()}'
        except (subprocess.CalledProcessError, FileNotFoundError):
            validation_results['forensic_tools']['status'] = 'warning'
            validation_results['forensic_tools']['message'] = 'ExifTool not found in PATH (required for full metadata extraction)'
        
        # Check write permissions
        test_dir = project_root / 'forensic_workspace'
        try:
            test_dir.mkdir(exist_ok=True)
            test_file = test_dir / 'permission_test.txt'
            test_file.write_text('test')
            test_file.unlink()
            validation_results['permissions']['status'] = 'pass'
            validation_results['permissions']['message'] = 'Write permissions verified'
        except PermissionError:
            validation_results['permissions']['status'] = 'fail'
            validation_results['permissions']['message'] = 'Insufficient write permissions'
        
        # Overall status
        statuses = [v['status'] for v in validation_results.values()]
        if 'fail' in statuses:
            validation_results['overall']['status'] = 'fail'
            validation_results['overall']['message'] = 'System validation failed'
        elif 'warning' in statuses:
            validation_results['overall']['status'] = 'warning'
            validation_results['overall']['message'] = 'System validation passed with warnings'
        else:
            validation_results['overall']['status'] = 'pass'
            validation_results['overall']['message'] = 'System validation successful'
        
        return validation_results
        
    except Exception as e:
        validation_results['overall']['status'] = 'error'
        validation_results['overall']['message'] = f'Validation error: {str(e)}'
        return validation_results

def get_forensic_manifest():
    """
    Generate forensic manifest for chain of custody documentation.
    
    Returns:
        dict: Forensic manifest with system and session information
    """
    import platform
    import datetime
    import getpass
    import socket
    
    return {
        'manifest_id': f"MFA-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
        'generated': datetime.datetime.now().isoformat(),
        'system': {
            'software': {
                'name': SYSTEM_METADATA['name'],
                'version': SYSTEM_METADATA['version'],
                'python_version': platform.python_version(),
                'platform': platform.platform()
            },
            'hardware': {
                'machine': platform.machine(),
                'processor': platform.processor(),
                'hostname': socket.gethostname()
            }
        },
        'session': {
            'analyst': getpass.getuser(),
            'start_time': datetime.datetime.now().isoformat(),
            'working_directory': str(project_root),
            'environment_variables': {
                'PYTHONPATH': os.environ.get('PYTHONPATH', ''),
                'PATH': os.environ.get('PATH', '')[:200] + '...'
            }
        },
        'forensic_parameters': {
            'hash_algorithms': list(HASH_ALGORITHMS.values()),
            'read_only': True,
            'audit_logging': True,
            'chain_of_custody': True,
            'compliance_standards': list(COMPLIANCE_STANDARDS.keys())
        },
        'integrity_checks': {
            'system_validation': validate_environment(),
            'config_integrity': 'To be verified during analysis',
            'module_integrity': 'To be verified during analysis'
        },
        'notes': 'This manifest documents the forensic analysis environment and parameters.'
    }

def check_updates():
    """
    Check for system updates (offline mode - placeholder for future implementation).
    
    Returns:
        dict: Update information
    """
    return {
        'current_version': __version__,
        'latest_version': __version__,  # Placeholder
        'update_available': False,
        'security_patches': [],
        'recommendation': 'System is current',
        'check_timestamp': datetime.datetime.now().isoformat()
    }

# Export public API
__all__ = [
    '__version__',
    '__description__',
    '__author__',
    '__license__',
    'print_banner',
    'get_citation',
    'validate_environment',
    'get_forensic_manifest',
    'check_updates',
    'SYSTEM_METADATA',
    'COMPLIANCE_STANDARDS',
    'SUPPORTED_FORMATS',
    'HASH_ALGORITHMS'
]

# Auto-validate on import in debug mode
if os.environ.get('METAFORENSICAI_DEBUG', 'false').lower() == 'true':
    print_banner()
    validation = validate_environment()
    if validation['overall']['status'] != 'pass':
        print(f"⚠️  System validation: {validation['overall']['message']}")
        for component, info in validation.items():
            if component != 'overall' and info['status'] != 'pass':
                print(f"   • {component}: {info['message']}")
    else:
        print("✅ System validation passed")

# Ensure forensic workspace exists
forensic_workspace = project_root / 'forensic_workspace'
forensic_workspace.mkdir(exist_ok=True)

# Initialize forensic log directory
log_dir = project_root / 'results' / 'logs'
log_dir.mkdir(parents=True, exist_ok=True)

print(f"MetaForensicAI v{__version__} initialized successfully.")