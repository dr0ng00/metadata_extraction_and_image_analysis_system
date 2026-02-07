#!/usr/bin/env python3
"""
MetaForensicAI Setup Configuration
"""

from setuptools import setup, find_packages
import os
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
install_requires = []
if requirements_path.exists():
    with open(requirements_path, "r", encoding="utf-8") as f:
        install_requires = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith("#")
        ]

# Version from package
version = {}
with open(Path(__file__).parent / "src" / "__init__.py", "r") as f:
    exec(f.read(), version)

setup(
    # Basic Information
    name="metaforensicai",
    version=version.get("__version__", "1.0.0"),
    author="MetaForensicAI Research Team",
    author_email="contact@metaforensicai.com",
    description="AI-Assisted Digital Image Forensics System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # Project URLs
    url="https://github.com/meteforensicai/MetaForensicAI",
    project_urls={
        "Bug Tracker": "https://github.com/meteforensicai/MetaForensicAI/issues",
        "Documentation": "https://meteforensicai.readthedocs.io/",
        "Source Code": "https://github.com/meteforensicai/MetaForensicAI",
        "Academic Paper": "https://arxiv.org/abs/meteforensicai-v1",
    },
    
    # Classification
    classifiers=[
        # Development Status
        "Development Status :: 4 - Beta",
        
        # Intended Audience
        "Intended Audience :: Legal Industry",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Education",
        
        # Topics
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Multimedia :: Graphics",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Scientific/Engineering :: Image Recognition",
        
        # License
        "License :: OSI Approved :: MIT License",
        
        # Programming Language
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        
        # Operating System
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        
        # Forensics Specific
        "Environment :: Console",
        "Natural Language :: English",
    ],
    
    # Package Information
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8, <4",
    
    # Dependencies
    install_requires=install_requires,
    
    # Optional Dependencies (for advanced features)
    extras_require={
        "full": [
            "opencv-python>=4.8.0.74",
            "scipy>=1.11.0",
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "networkx>=3.0",
        ],
        "gpu": [
            "torch>=2.0.0",
            "torchvision>=0.15.0",
        ],
        "web": [
            "flask>=2.3.0",
            "flask-cors>=4.0.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "sphinx>=7.1.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
        "docs": [
            "sphinx>=7.1.0",
            "sphinx-rtd-theme>=1.3.0",
            "sphinx-autodoc-typehints>=1.23.0",
        ],
    },
    
    # Package Data (non-Python files)
    package_data={
        "metaforensicai": [
            # Configuration files
            "config/*.yaml",
            "config/*.json",
            "config/*.yml",
            
            # Report templates
            "reporting/pdf_templates/*.html",
            "reporting/pdf_templates/*.json",
            
            # Data models
            "models/*.json",
            "models/*.yaml",
            
            # Example data
            "examples/*.jpg",
            "examples/*.json",
        ],
    },
    
    # Data files outside packages
    data_files=[
        # Documentation
        ("share/doc/metaforensicai", [
            "README.md",
            "LICENSE",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
        ]),
        
        # Example configurations
        ("share/metaforensicai/config", [
            "config/default_config.yaml",
            "config/forensic_rules.json",
        ]),
        
        # Scripts
        ("share/metaforensicai/scripts", [
            "scripts/install_dependencies.sh",
            "scripts/setup_forensic_env.py",
            "scripts/batch_analyzer.py",
            "scripts/validation_runner.py",
        ]),
    ],
    
    # Entry Points (console scripts)
    entry_points={
        "console_scripts": [
            "metaforensicai=main:main",
            "mfa-analyze=scripts.batch_analyzer:main",
            "mfa-validate=scripts.validation_runner:main",
            "mfa-setup=scripts.setup_forensic_env:main",
        ],
    },
    
    # Scripts (old style, for compatibility)
    scripts=[
        "scripts/install_dependencies.sh",
    ],
    
    # Options
    options={
        "bdist_wheel": {
            "universal": False,  # Not universal, Python 3 only
        },
        "build": {
            "build_base": "build",
        },
    },
    
    # Zip Safe
    zip_safe=False,  # Not zip safe due to config files
    
    # Include package data
    include_package_data=True,
    
    # Keywords
    keywords=[
        "forensic",
        "digital-forensics",
        "image-analysis",
        "metadata",
        "exif",
        "ai",
        "machine-learning",
        "computer-vision",
        "security",
        "investigation",
        "legal",
        "academic",
    ],
    
    # License
    license="MIT",
    
    # Platform
    platforms=["Linux", "Mac OS-X", "Windows"],
    
    # Maintainer Information
    maintainer="MetaForensicAI Research Team",
    maintainer_email="lorenz04ack3r@gmail.com",
    
    # Download URL
    download_url="https://github.com/meteforensicai/MetaForensicAI/releases",
    
    # Provides
    provides=["metaforensicai"],
    
    # Requires External (non-Python)
    requires_external=[
        "exiftool",  # Required for full functionality
    ],
    
    # Metadata
    metadata_version="2.1",
)#!/usr/bin/env python3
"""
Setup script for MetaForensicAI - Comprehensive Forensic Image Analysis Toolkit
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
import subprocess
import platform

# Check Python version
PYTHON_REQUIRED = (3, 8)
if sys.version_info < PYTHON_REQUIRED:
    print(f"MetaForensicAI requires Python {PYTHON_REQUIRED[0]}.{PYTHON_REQUIRED[1]}+")
    sys.exit(1)

# Read package metadata
def read_metadata():
    """Read package metadata from files"""
    metadata = {}
    
    # Read version from version file
    version_path = Path("src/forensicai/__version__.py")
    if version_path.exists():
        with open(version_path) as f:
            exec(f.read(), metadata)
    else:
        metadata['__version__'] = '1.0.0'
    
    # Read README
    readme_path = Path("README.md")
    if readme_path.exists():
        with open(readme_path, encoding='utf-8') as f:
            metadata['long_description'] = f.read()
    else:
        metadata['long_description'] = "MetaForensicAI - Forensic Image Analysis Toolkit"
    
    # Read requirements
    requirements_path = Path("requirements.txt")
    if requirements_path.exists():
        with open(requirements_path) as f:
            metadata['install_requires'] = [
                line.strip() 
                for line in f 
                if line.strip() and not line.startswith('#')
            ]
    else:
        metadata['install_requires'] = []
    
    return metadata

def check_system_requirements():
    """Check system requirements and dependencies"""
    print("Checking system requirements...")
    
    # Check OS
    system = platform.system()
    print(f"  System: {system} {platform.release()}")
    
    # Check Python version
    python_version = platform.python_version()
    print(f"  Python: {python_version}")
    
    # Check for GPU
    try:
        import torch  # type: ignore
        if torch.cuda.is_available():
            print(f"  GPU: CUDA available ({torch.cuda.get_device_name(0)})")
        else:
            print("  GPU: CUDA not available (CPU only)")
    except ImportError:
        print("  GPU: PyTorch not installed")
    
    # Check for OpenCV
    try:
        import cv2  # type: ignore
        print(f"  OpenCV: {cv2.__version__}")
    except ImportError:
        print("  OpenCV: Not installed")
    
    return True

class PostInstallCommand(install):
    """Post-installation commands"""
    def run(self):
        # Run standard install
        install.run(self)
        
        # Run post-install setup
        self.run_post_install()
    
    def run_post_install(self):
        """Execute post-installation tasks"""
        print("\n" + "="*60)
        print("META FORENSIC AI - POST INSTALLATION SETUP")
        print("="*60)
        
        # Check system requirements
        check_system_requirements()
        
        # Create necessary directories
        self.create_directories()
        
        # Initialize configuration
        self.initialize_configuration()
        
        # Download models if needed
        self.download_models()
        
        print("\n" + "="*60)
        print("INSTALLATION COMPLETE!")
        print("="*60)
        print("\nNext steps:")
        print("1. Configure your settings: config/default_config.yaml")
        print("2. Test installation: python -m pytest tests/ -v")
        print("3. Run demo: python examples/demo_analysis.py")
        print("4. Check documentation: docs/")
        print("\nFor support: https://github.com/yourusername/MetaForensicAI")
    
    def create_directories(self):
        """Create necessary directories"""
        print("\nCreating directory structure...")
        
        directories = [
            "datasets",
            "datasets/ground_truth",
            "datasets/ground_truth/original_camera",
            "datasets/ground_truth/social_media", 
            "datasets/ground_truth/edited_images",
            "datasets/ground_truth/manipulated",
            "datasets/validation_sets",
            "results",
            "results/reports",
            "results/logs",
            "results/exports",
            "models",
            "config",
            "logs",
            "exports",
            "evidence"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"  Created: {directory}/")
        
        # Create .gitkeep files to preserve empty directories
        gitkeep_dirs = [
            "datasets/ground_truth/original_camera",
            "datasets/ground_truth/social_media",
            "datasets/ground_truth/edited_images",
            "datasets/ground_truth/manipulated",
            "datasets/validation_sets",
            "results/reports",
            "results/logs",
            "results/exports"
        ]
        
        for directory in gitkeep_dirs:
            gitkeep_file = Path(directory) / ".gitkeep"
            gitkeep_file.write_text("# Keep directory in git\n")
    
    def initialize_configuration(self):
        """Initialize configuration files"""
        print("\nInitializing configuration...")
        
        # Create default config if doesn't exist
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        default_config = config_dir / "default_config.yaml"
        if not default_config.exists():
            default_config_content = """# MetaForensicAI Default Configuration
# Version: 1.0.0

# Application Settings
app:
  name: "MetaForensicAI"
  version: "1.0.0"
  debug: false
  log_level: "INFO"
  max_file_size_mb: 100
  supported_formats: [".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"]

# Forensic Analysis Settings
forensic_analysis:
  extraction_depth: "comprehensive"  # basic, standard, comprehensive
  preserve_metadata: true
  hash_algorithms: ["sha256", "md5"]
  compression_analysis: true
  error_level_analysis: true
  noise_analysis: true
  
  # Metadata extraction
  extract_exif: true
  extract_xmp: true
  extract_iptc: true
  extract_icc: true
  
  # Platform detection
  detect_camera_models: true
  detect_social_media: true
  detect_editing_software: true

# Machine Learning Settings
machine_learning:
  # Model settings
  model_type: "ensemble"  # cnn, transformer, ensemble
  use_pretrained: true
  fine_tune: true
  
  # Training settings
  batch_size: 32
  learning_rate: 0.001
  epochs: 100
  early_stopping_patience: 10
  
  # Hardware acceleration
  device: "auto"  # auto, cpu, cuda, mps
  num_workers: 4
  mixed_precision: true

# Risk Assessment Settings
risk_assessment:
  authenticity_threshold: 85  # 0-100
  manipulation_threshold: 30  # 0-100
  platform_trust_scores:
    original_camera: 95
    professional_edit: 80
    social_media: 60
    unknown_source: 40
  
  # Risk categories
  risk_categories:
    low: [0, 30]
    medium: [31, 70]
    high: [71, 100]

# Reporting Settings
reporting:
  # Output formats
  formats: ["pdf", "html", "json"]
  default_format: "pdf"
  
  # Content options
  include_technical_details: true
  include_visualizations: true
  include_recommendations: true
  include_legal_disclaimers: true
  
  # PDF settings
  pdf:
    page_size: "A4"
    margin: 0.5  # inches
    font_size: 10
    include_header: true
    include_footer: true
  
  # JSON settings
  json:
    pretty_print: true
    include_timestamps: true
    include_hashes: true

# Validation Settings
validation:
  ground_truth_comparison: true
  cross_validation_folds: 5
  test_size: 0.2
  
  # Benchmark datasets
  benchmark_datasets:
    - "MICC-F220"
    - "CASIA v2"
    - "CoVERAGE"
  
  # Performance metrics
  metrics:
    - "accuracy"
    - "precision"
    - "recall"
    - "f1_score"
    - "auc_roc"

# Security Settings
security:
  # Hashing
  hash_algorithm: "sha256"
  hash_salt: ""
  
  # Encryption
  encrypt_reports: false
  encryption_algorithm: "AES-256"
  
  # Chain of custody
  track_chain_of_custody: true
  log_all_operations: true
  audit_trail_retention_days: 365

# Performance Settings
performance:
  # Processing
  max_workers: 4
  chunk_size: 1024
  cache_enabled: true
  cache_size_mb: 1024
  
  # Memory management
  max_memory_mb: 4096
  cleanup_interval: 60  # seconds
  
  # Parallel processing
  parallel_processing: true
  batch_processing: true

# Interface Settings
interface:
  # CLI settings
  cli:
    show_progress: true
    verbose: false
    color_output: true
    
  # Web interface
  web:
    enabled: false
    host: "127.0.0.1"
    port: 5000
    debug: false
    
  # API settings
  api:
    enabled: false
    rate_limit: 100  # requests per minute
    authentication_required: false

# Database Settings (Optional)
database:
  enabled: false
  type: "sqlite"  # sqlite, postgresql, mysql
  path: "results/forensic_db.sqlite"
  backup_enabled: true
  backup_interval_hours: 24

# External Services
external_services:
  # Reverse image search
  reverse_image_search:
    enabled: false
    providers: ["google", "tineye", "yandex"]
    api_keys: {}
    
  # Metadata databases
  metadata_databases:
    - "exif.tools"
    - "exifdata.com"
    
  # Threat intelligence
  threat_intelligence:
    enabled: false
    providers: ["virustotal", "hybrid-analysis"]

# Plugin System
plugins:
  enabled: true
  directory: "plugins"
  auto_discover: true
  
  # Built-in plugins
  builtin_plugins:
    - "metadata_analyzer"
    - "compression_analyzer"
    - "manipulation_detector"
    - "origin_detector"

# Updates and Maintenance
updates:
  auto_check: true
  check_interval_hours: 24
  notify_on_update: true
  
  # Backup settings
  auto_backup: true
  backup_directory: "backups"
  max_backups: 10

# Legal and Compliance
legal:
  disclaimer: |
    This tool is for educational and research purposes only.
    Users are responsible for complying with all applicable laws.
    
  privacy_policy: |
    No personal data is collected or stored.
    All analysis is performed locally.
    
  terms_of_service: |
    Use at your own risk.
    No warranty provided.

# Logging Settings
logging:
  enabled: true
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "logs/forensicai.log"
  max_size_mb: 100
  backup_count: 5
  
  # Audit logging
  audit_logging: true
  audit_file: "logs/audit.log"

# System Paths
paths:
  # Core directories
  datasets: "datasets"
  models: "models"
  results: "results"
  logs: "logs"
  config: "config"
  plugins: "plugins"
  
  # Temporary directories
  temp: "temp"
  cache: ".cache"
  
  # Evidence handling
  evidence: "evidence"
  chain_of_custody: "chain_of_custody"

# Feature Flags
features:
  # Core features
  enable_metadata_analysis: true
  enable_compression_analysis: true
  enable_manipulation_detection: true
  enable_origin_detection: true
  enable_risk_assessment: true
  
  # Advanced features
  enable_deep_learning: true
  enable_explainable_ai: true
  enable_batch_processing: true
  enable_api: false
  enable_web_interface: false
  
  # Experimental features
  experimental_features: false
  enable_ai_generated_detection: true
  enable_3d_forensics: false
  enable_video_forensics: false

# Version Information
version:
  major: 1
  minor: 0
  patch: 0
  build: "2024.01.20"
  compatible_versions: ["1.0.0"]

# About
about:
  name: "MetaForensicAI"
  description: "Comprehensive Forensic Image Analysis Toolkit"
  author: "MetaForensicAI Research Team"
  email: "contact@metaforensicai.org"
  website: "https://metaforensicai.org"
  repository: "https://github.com/yourusername/MetaForensicAI"
  license: "MIT"
  copyright: "Copyright 2024 MetaForensicAI Research Team"
"""
            default_config.write_text(default_config_content)
            print("  Created: config/default_config.yaml")
        
        # Create forensic rules configuration
        forensic_rules = config_dir / "forensic_rules.json"
        if not forensic_rules.exists():
            forensic_rules_content = """{
  "metadata_consistency": {
    "enabled": true,
    "rules": [
      {
        "name": "datetime_consistency",
        "description": "Check consistency between EXIF DateTime fields",
        "weight": 0.2,
        "threshold": 0.8
      },
      {
        "name": "gps_correlation",
        "description": "Verify GPS coordinates are plausible",
        "weight": 0.15,
        "threshold": 0.7
      },
      {
        "name": "device_consistency",
        "description": "Check consistency of device information",
        "weight": 0.1,
        "threshold": 0.6
      },
      {
        "name": "software_consistency",
        "description": "Verify software metadata consistency",
        "weight": 0.15,
        "threshold": 0.7
      }
    ],
    "total_weight": 0.6
  },
  
  "compression_analysis": {
    "enabled": true,
    "rules": [
      {
        "name": "jpeg_quantization",
        "description": "Analyze JPEG quantization tables",
        "weight": 0.25,
        "threshold": 0.75
      },
      {
        "name": "resampling_detection",
        "description": "Detect image resampling artifacts",
        "weight": 0.2,
        "threshold": 0.7
      },
      {
        "name": "double_compression",
        "description": "Detect double JPEG compression",
        "weight": 0.3,
        "threshold": 0.8
      },
      {
        "name": "compression_inconsistency",
        "description": "Detect inconsistent compression patterns",
        "weight": 0.25,
        "threshold": 0.75
      }
    ],
    "total_weight": 0.7
  },
  
  "manipulation_indicators": {
    "enabled": true,
    "rules": [
      {
        "name": "clone_detection",
        "description": "Detect copy-move forgery",
        "weight": 0.3,
        "threshold": 0.85
      },
      {
        "name": "splicing_artifacts",
        "description": "Detect image splicing artifacts",
        "weight": 0.25,
        "threshold": 0.8
      },
      {
        "name": "lighting_inconsistency",
        "description": "Detect inconsistent lighting/shadow directions",
        "weight": 0.2,
        "threshold": 0.75
      },
      {
        "name": "perspective_inconsistency",
        "description": "Detect perspective inconsistencies",
        "weight": 0.15,
        "threshold": 0.7
      },
      {
        "name": "noise_inconsistency",
        "description": "Detect inconsistent noise patterns",
        "weight": 0.1,
        "threshold": 0.65
      }
    ],
    "total_weight": 1.0
  },
  
  "origin_detection": {
    "enabled": true,
    "rules": [
      {
        "name": "camera_fingerprint",
        "description": "Match camera model fingerprint",
        "weight": 0.4,
        "threshold": 0.8
      },
      {
        "name": "sensor_pattern_noise",
        "description": "Analyze sensor pattern noise",
        "weight": 0.3,
        "threshold": 0.75
      },
      {
        "name": "lens_distortion",
        "description": "Analyze lens distortion patterns",
        "weight": 0.2,
        "threshold": 0.7
      },
      {
        "name": "platform_signatures",
        "description": "Detect social media platform signatures",
        "weight": 0.1,
        "threshold": 0.65
      }
    ],
    "total_weight": 1.0
  },
  
  "ai_generated_detection": {
    "enabled": true,
    "rules": [
      {
        "name": "gan_fingerprint",
        "description": "Detect GAN-generated image fingerprints",
        "weight": 0.35,
        "threshold": 0.85
      },
      {
        "name": "frequency_analysis",
        "description": "Analyze frequency domain artifacts",
        "weight": 0.25,
        "threshold": 0.8
      },
      {
        "name": "texture_inconsistency",
        "description": "Detect texture inconsistencies in AI images",
        "weight": 0.2,
        "threshold": 0.75
      },
      {
        "name": "semantic_inconsistency",
        "description": "Detect semantic inconsistencies",
        "weight": 0.2,
        "threshold": 0.7
      }
    ],
    "total_weight": 1.0
  },
  
  "scoring_system": {
    "authenticity_score": {
      "weights": {
        "metadata_consistency": 0.25,
        "compression_analysis": 0.35,
        "manipulation_indicators": 0.40
      },
      "thresholds": {
        "high_confidence": 85,
        "medium_confidence": 70,
        "low_confidence": 50
      }
    },
    "risk_score": {
      "weights": {
        "authenticity_score": 0.4,
        "origin_confidence": 0.3,
        "manipulation_evidence": 0.3
      },
      "categories": {
        "low": [0, 30],
        "medium": [31, 70],
        "high": [71, 100]
      }
    }
  }
}"""
            forensic_rules.write_text(forensic_rules_content)
            print("  Created: config/forensic_rules.json")
    
    def download_models(self):
        """Download pre-trained models if needed"""
        print("\nChecking for model files...")
        
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        # Create camera database template
        camera_db = models_dir / "camera_database.json"
        if not camera_db.exists():
            camera_db_content = """{
  "cameras": [
    {
      "make": "Canon",
      "model": "EOS 5D Mark IV",
      "sensor": "Full Frame (36.0 x 24.0 mm)",
      "resolution": [6720, 4480],
      "firmware_versions": ["1.x", "2.x", "3.x"],
      "compression_patterns": ["canon_5div_pattern1", "canon_5div_pattern2"],
      "noise_profile": "canon_5div_noise_profile",
      "lens_profiles": ["canon_ef_series", "canon_rf_series"]
    },
    {
      "make": "Nikon",
      "model": "D850",
      "sensor": "Full Frame (35.9 x 23.9 mm)",
      "resolution": [8256, 5504],
      "firmware_versions": ["A:x", "B:x", "C:x"],
      "compression_patterns": ["nikon_d850_pattern1", "nikon_d850_pattern2"],
      "noise_profile": "nikon_d850_noise_profile",
      "lens_profiles": ["nikon_f_series", "nikon_z_series"]
    },
    {
      "make": "Sony",
      "model": "Alpha 7R IV",
      "sensor": "Full Frame (35.7 x 23.8 mm)",
      "resolution": [9504, 6336],
      "firmware_versions": ["1.00", "2.00", "3.00"],
      "compression_patterns": ["sony_a7riv_pattern1", "sony_a7riv_pattern2"],
      "noise_profile": "sony_a7riv_noise_profile",
      "lens_profiles": ["sony_e_mount", "sony_fe_mount"]
    },
    {
      "make": "Apple",
      "model": "iPhone 14 Pro",
      "sensor": "Triple 48MP",
      "resolution": [4032, 3024],
      "firmware_versions": ["iOS 16.x", "iOS 17.x"],
      "compression_patterns": ["iphone_heic_pattern", "iphone_jpeg_pattern"],
      "noise_profile": "iphone_14_pro_noise_profile",
      "lens_profiles": ["iphone_main", "iphone_ultrawide", "iphone_telephoto"]
    }
  ],
  "platforms": [
    {
      "name": "Facebook",
      "compression_profile": "facebook_jpeg_high",
      "max_dimensions": [2048, 2048],
      "quality_range": [60, 85],
      "metadata_modifications": ["strip_location", "strip_device_info"],
      "watermark": false
    },
    {
      "name": "Instagram",
      "compression_profile": "instagram_jpeg_medium",
      "max_dimensions": [1080, 1350],
      "quality_range": [70, 90],
      "metadata_modifications": ["strip_all_except_copyright", "add_instagram_data"],
      "watermark": false
    },
    {
      "name": "Twitter",
      "compression_profile": "twitter_jpeg_high",
      "max_dimensions": [4096, 4096],
      "quality_range": [75, 95],
      "metadata_modifications": ["strip_gps", "compress_metadata"],
      "watermark": false
    },
    {
      "name": "TikTok",
      "compression_profile": "tiktok_video_frame",
      "max_dimensions": [1080, 1920],
      "quality_range": [65, 80],
      "metadata_modifications": ["strip_all_metadata", "add_tiktok_watermark"],
      "watermark": true
    }
  ],
  "software": [
    {
      "name": "Adobe Photoshop",
      "versions": ["CC 2023", "CC 2024"],
      "signatures": ["photoshop_app_id", "photoshop_version_id"],
      "compression_profiles": ["photoshop_jpeg_max", "photoshop_png_24"],
      "metadata_additions": ["photoshop_history", "xmp_metadata"]
    },
    {
      "name": "Adobe Lightroom",
      "versions": ["Classic 12.x", "Classic 13.x"],
      "signatures": ["lightroom_processing", "lightroom_profiles"],
      "compression_profiles": ["lightroom_export_high", "lightroom_export_web"],
      "metadata_additions": ["lightroom_develop_settings", "xmp_sidecar"]
    },
    {
      "name": "GIMP",
      "versions": ["2.10.x", "3.0.x"],
      "signatures": ["gimp_export", "gimp_plugin_info"],
      "compression_profiles": ["gimp_jpeg_default", "gimp_png_default"],
      "metadata_additions": ["gimp_history", "gimp_comment"]
    }
  ]
}"""
            camera_db.write_text(camera_db_content)
            print("  Created: models/camera_database.json")
        
        # Create model checkpoints directory
        checkpoints_dir = models_dir / "checkpoints"
        checkpoints_dir.mkdir(exist_ok=True)
        
        # Create placeholder for pre-trained models
        placeholder = checkpoints_dir / "README.md"
        if not placeholder.exists():
            placeholder_content = """# Model Checkpoints

This directory contains pre-trained model checkpoints for MetaForensicAI.

## Available Models

### 1. Forensic Detection Models
- `authenticity_detector.pth` - Image authenticity classification
- `manipulation_detector.pth` - Manipulation detection and localization
- `origin_classifier.pth` - Origin and platform classification

### 2. Feature Extraction Models
- `metadata_embedder.pth` - Metadata feature extraction
- `compression_analyzer.pth` - Compression pattern analysis
- `noise_analyzer.pth` - Sensor noise analysis

### 3. Advanced Models
- `ai_generated_detector.pth` - AI-generated content detection
- `deepfake_detector.pth` - Deepfake video/image detection
- `splicing_localizer.pth` - Splicing boundary localization

## Download Instructions

Run the following command to download pre-trained models:

```bash
python scripts/download_models.py"""
            placeholder.write_text(placeholder_content)
