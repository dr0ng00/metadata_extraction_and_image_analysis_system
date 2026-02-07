"""
User interface modules for MetaForensicAI.

This package contains CLI assistant, web interface, and natural language
processing components for interactive forensic analysis.
"""

from .cli_assistant import ForensicCLIAssistant
from .natural_language_processor import NaturalLanguageProcessor
from .web_interface import ForensicWebInterface

__all__ = [
    'ForensicCLIAssistant',
    'NaturalLanguageProcessor',
    'ForensicWebInterface'
]

# CLI commands and help
CLI_COMMANDS = {
    'analyze': 'Perform forensic analysis on an image',
    'explain': 'Explain specific forensic findings',
    'metadata': 'Show extracted metadata',
    'compare': 'Compare with another image',
    'risk': 'Show risk factors and scores',
    'origin': 'Show origin detection results',
    'export': 'Generate forensic reports',
    'help': 'Show available commands',
    'exit': 'Exit the interactive session'
}

def get_cli_help():
    """Return formatted CLI help information."""
    help_text = "Available Commands:\n"
    for cmd, desc in CLI_COMMANDS.items():
        help_text += f"  {cmd:<10} - {desc}\n"
    return help_text