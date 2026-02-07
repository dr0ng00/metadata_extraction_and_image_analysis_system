"""Forensic logging handler (stub).

Provides `ForensicLogger` for forensic audit logging. This minimal
implementation logs key events and can be expanded with persistent storage.
"""
from typing import Any, Dict
from datetime import datetime


class ForensicLogger:
    """Lightweight logger for forensic events."""
    def __init__(self, name: str = 'ForensicAnalysis'):
        self.name = name
        self.events = []

    def log_event(self, event_type: str, details: Dict[str, Any] | None = None) -> None:
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details or {}
        }
        self.events.append(entry)

    def info(self, message: str) -> None:
        """Log an info message."""
        self.log_event('INFO', {'message': message})

    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.log_event('WARNING', {'message': message})

    def error(self, message: str) -> None:
        """Log an error message."""
        self.log_event('ERROR', {'message': message})

    def debug(self, message: str) -> None:
        """Log a debug message."""
        self.log_event('DEBUG', {'message': message})

    def get_log(self) -> list:
        return self.events.copy()

    def export_log(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'events': self.events,
            'total_events': len(self.events)
        }


# Alias for backwards compatibility
ChainOfCustodyLogger = ForensicLogger

__all__ = ['ForensicLogger', 'ChainOfCustodyLogger']