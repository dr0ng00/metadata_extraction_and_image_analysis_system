"""
Configuration management for MetaForensicAI.

This package handles system configuration, forensic rules, and
analysis parameters.
"""

import os
import yaml
import json
from pathlib import Path

__all__ = ['load_config', 'get_default_config', 'save_config']

def load_config(config_path=None):
    """Load configuration from file or return defaults."""
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                return yaml.safe_load(f)
            elif config_path.endswith('.json'):
                return json.load(f)
    
    # Return default configuration
    return get_default_config()

def get_default_config():
    """Return default system configuration."""
    return {
        'system': {
            'name': 'MetaForensicAI',
            'version': '1.0.0',
            'debug': False,
            'max_file_size_mb': 100
        },
        'forensic': {
            'hash_algorithms': ['sha256', 'sha3_256'],
            'read_only': True,
            'create_backup': True,
            'audit_logging': True,
            'chain_of_custody': True
        },
        'analysis': {
            'enable_timestamp_analysis': True,
            'enable_compression_analysis': True,
            'enable_platform_detection': True,
            'enable_gps_analysis': True,
            'enable_object_detection': False,
            'confidence_threshold': 0.7
        },
        'reporting': {
            'generate_pdf': True,
            'generate_json': True,
            'include_explanations': True,
            'include_metadata': True,
            'output_dir': './results/reports'
        },
        'interface': {
            'interactive_mode': True,
            'color_output': True,
            'verbose': False
        }
    }

def save_config(config, config_path):
    """Save configuration to file."""
    config_dir = Path(config_path).parent
    config_dir.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            yaml.dump(config, f, default_flow_style=False)
        elif config_path.endswith('.json'):
            json.dump(config, f, indent=2)
    
    return config_path

def get_config_path():
    """Get default configuration file paths."""
    base_dir = Path(__file__).parent
    return {
        'yaml': base_dir / 'default_config.yaml',
        'json': base_dir / 'default_config.json',
        'rules': base_dir / 'forensic_rules.json'
    }