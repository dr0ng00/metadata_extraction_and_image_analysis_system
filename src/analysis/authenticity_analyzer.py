"""Adapter exposing core `MetadataAuthenticityAnalyzer` to the analysis package.

This module re-exports the implementation from the `core` package so
`from .authenticity_analyzer import MetadataAuthenticityAnalyzer` works
for consumers of `src.analysis`.
"""
from ..core import MetadataAuthenticityAnalyzer

__all__ = [
    'MetadataAuthenticityAnalyzer'
]
