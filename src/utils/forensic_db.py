"""Forensic database and persistence layer.

Provides a SQLite-based storage for case findings to enable
cross-case evidentiary correlation.
"""
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

class ForensicDatabase:
    """Persistent storage for forensic findings and fingerprints."""

    def __init__(self, db_path: str = "forensic_intelligence.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table for Case Metadata
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                created_at TIMESTAMP,
                description TEXT
            )
        ''')
        
        # Table for Evidence Fingerprints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_hash TEXT PRIMARY KEY,
                case_id TEXT,
                filename TEXT,
                file_size INTEGER,
                hardware_make TEXT,
                hardware_model TEXT,
                software_tag TEXT,
                ela_intensity TEXT,
                qtable_sig TEXT,
                analysis_json TEXT,
                captured_at TIMESTAMP,
                processed_at TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def ingest_case(self, results: Dict[str, Any]):
        """Ingest analysis results into the intelligence database."""
        case_id = results.get('case_info', {}).get('case_id', 'UNKNOWN_CASE')
        metadata = results.get('metadata', {})
        file_info = metadata.get('file_info', {})
        summary = metadata.get('summary', {})
        artifacts = results.get('artifact_analysis', {})
        integrity = results.get('evidence_integrity', {})
        
        # 1. Ensure case exists
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO cases (case_id, created_at) VALUES (?, ?)", 
                       (case_id, datetime.now().isoformat()))
        
        # 2. Extract key fingerprints
        evidence_hash = integrity.get('hash_sha256') or results.get('hash_sha256')
        if not evidence_hash:
            # Fallback for demonstration if hash tool wasn't run
            evidence_hash = f"HASH_{file_info.get('File Name')}_{file_info.get('size_bytes')}"

        cursor.execute('''
            INSERT OR REPLACE INTO evidence (
                evidence_hash, case_id, filename, file_size,
                hardware_make, hardware_model, software_tag,
                ela_intensity, qtable_sig, analysis_json,
                captured_at, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence_hash,
            case_id,
            file_info.get('File Name'),
            file_info.get('size_bytes'),
            summary.get('camera_make'),
            summary.get('camera_model'),
            summary.get('software'),
            artifacts.get('ela_results', {}).get('ela_intensity'),
            artifacts.get('qtable_audit', {}).get('signature_match'),
            json.dumps(results),
            summary.get('datetime_original'),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()

    def find_similar_evidence(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find evidence with matching hardware, software, or quantization signatures."""
        summary = results.get('metadata', {}).get('summary', {})
        make = summary.get('camera_make')
        model = summary.get('camera_model')
        software = summary.get('software')
        
        artifacts = results.get('artifact_analysis', {})
        qtable = artifacts.get('qtable_audit', {}).get('signature_match')
        
        if not any([make, model, software, qtable]):
            return []

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Search by hardware signature
        matches = []
        if make and model:
            cursor.execute('''
                SELECT * FROM evidence 
                WHERE hardware_make = ? AND hardware_model = ?
                LIMIT 10
            ''', (make, model))
            matches.extend([dict(row) for row in cursor.fetchall()])
            
        # Search by specific software tag
        if software:
            cursor.execute('''
                SELECT * FROM evidence 
                WHERE software_tag = ?
                LIMIT 5
            ''', (software,))
            matches.extend([dict(row) for row in cursor.fetchall()])

        # Search by Quantization Signature (Point 14 link)
        if qtable and qtable != 'UNKNOWN':
            cursor.execute('''
                SELECT * FROM evidence 
                WHERE qtable_sig = ?
                LIMIT 5
            ''', (qtable,))
            matches.extend([dict(row) for row in cursor.fetchall()])
            
        conn.close()
        
        # Unique matches by case (not the current case)
        current_case = results.get('case_info', {}).get('case_id')
        unique_matches = {}
        for m in matches:
            if m['case_id'] != current_case:
                unique_matches[m['case_id']] = m
                
        return list(unique_matches.values())

__all__ = ['ForensicDatabase']
