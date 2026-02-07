"""Minimal web interface stub for forensic reporting and visualization.

Provides a `ForensicWebInterface` class so `src.interface` imports resolve.
A real web server (Flask/FastAPI) can replace this stub later.
"""
from typing import Any, Dict


class ForensicWebInterface:
    """Stub web interface exposing simple start/stop hooks."""
    def __init__(self, host: str = '127.0.0.1', port: int = 8000):
        self.host = host
        self.port = port
        self.running = False

    def start(self) -> Dict[str, Any]:
        self.running = True
        return {'status': 'running', 'host': self.host, 'port': self.port}

    def stop(self) -> Dict[str, Any]:
        self.running = False
        return {'status': 'stopped'}

    def status(self) -> Dict[str, Any]:
        return {'running': self.running, 'host': self.host, 'port': self.port}


__all__ = ['ForensicWebInterface']
