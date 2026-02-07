"""Command-line assistant for interactive forensic analysis (stub).

Provides a minimal `ForensicCLIAssistant` class so imports resolve for
development and IDE checks. Full CLI implementation can be added later.
"""
from typing import Any


class ForensicCLIAssistant:
    """Simple CLI assistant stub with basic command dispatch."""
    def __init__(self, analyzer: Any | None = None, analysis_results: Any | None = None, forensic_system: Any | None = None):
        self.analyzer = analyzer
        self.analysis_results = analysis_results
        self.forensic_system = forensic_system
        self.running = False

    def start(self) -> None:
        self.running = True

    def stop(self) -> None:
        self.running = False

    def start_session(self) -> None:
        """Start an interactive CLI session."""
        self.running = True

    def run_command(self, command: str) -> str:
        cmd = command.strip().lower()
        if cmd == 'help':
            return 'Use get_cli_help() for available commands.'
        if cmd == 'exit':
            self.stop()
            return 'Exiting'
        return f'Command "{command}" received (stub)'


__all__ = ['ForensicCLIAssistant']
