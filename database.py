"""
Database management for Wi-Fi Security Analysis System
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from contextlib import contextmanager
import config

class Database:
    """Database manager for scan history and analytics"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.DATABASE_CONFIG['path']
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    ssid TEXT,
                    bssid TEXT,
                    risk_level TEXT,
                    overall_risk_score REAL,
                    scan_data TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    vuln_id TEXT,
                    name TEXT,
                    severity TEXT,
                    cve TEXT,
                    cvss_score REAL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    threat_type TEXT,
                    confidence REAL,
                    description TEXT,
                    timestamp DATETIME,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Compliance checks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    standard TEXT,
                    requirement_id TEXT,
                    status TEXT,
                    details TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_ssid ON scans(ssid)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_scan ON threats(scan_id)')
    
    def save_scan(self, scan_result: Dict) -> bool:
        """Save scan result to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Insert main scan record
                cursor.execute('''
                    INSERT INTO scans (scan_id, timestamp, ssid, bssid, risk_level, 
                                     overall_risk_score, scan_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_result['scan_id'],
                    scan_result['timestamp'],
                    scan_result['network_info']['ssid'],
                    scan_result['network_info']['bssid'],
                    scan_result['risk_level'],
                    scan_result['security_metrics']['overall_risk_score'],
                    json.dumps(scan_result)
                ))
                
                # Insert vulnerabilities
                for vuln in scan_result.get('vulnerabilities', []):
                    cursor.execute('''
                        INSERT INTO vulnerabilities (scan_id, vuln_id, name, severity, cve, cvss_score)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_result['scan_id'],
                        vuln['id'],
                        vuln['name'],
                        vuln['severity'],
                        vuln.get('cve'),
                        vuln.get('cvss_score')
                    ))
                
                # Insert threats
                for threat in scan_result.get('threats', []):
                    cursor.execute('''
                        INSERT INTO threats (scan_id, threat_type, confidence, description, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_result['scan_id'],
                        threat['threat_type'],
                        threat['confidence'],
                        threat['description'],
                        threat['timestamp']
                    ))
                
                # Insert compliance checks
                for check in scan_result.get('compliance_checks', []):
                    cursor.execute('''
                        INSERT INTO compliance_checks (scan_id, standard, requirement_id, status, details)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_result['scan_id'],
                        check['standard'],
                        check['requirement_id'],
                        check['status'],
                        check['details']
                    ))
                
                return True
        except Exception as e:
            print(f"Error saving scan: {e}")
            return False
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Retrieve scan by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT scan_data FROM scans WHERE scan_id = ?', (scan_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['scan_data'])
            return None
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent scans"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, timestamp, ssid, bssid, risk_level, overall_risk_score
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scans_by_ssid(self, ssid: str, days: int = 30) -> List[Dict]:
        """Get scans for specific SSID within date range"""
        cutoff_date = datetime.now() - timedelta(days=days)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_data FROM scans
                WHERE ssid = ? AND timestamp >= ?
                ORDER BY timestamp DESC
            ''', (ssid, cutoff_date))
            return [json.loads(row['scan_data']) for row in cursor.fetchall()]
    
    def get_trend_data(self, days: int = 30) -> Dict:
        """Get trend data for analytics"""
        cutoff_date = datetime.now() - timedelta(days=days)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Risk score trends
            cursor.execute('''
                SELECT DATE(timestamp) as date, AVG(overall_risk_score) as avg_score
                FROM scans
                WHERE timestamp >= ?
                GROUP BY DATE(timestamp)
                ORDER BY date
            ''', (cutoff_date,))
            risk_trends = [dict(row) for row in cursor.fetchall()]
            
            # Vulnerability counts
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.scan_id
                WHERE s.timestamp >= ?
                GROUP BY severity
            ''', (cutoff_date,))
            vuln_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Threat types
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM threats t
                JOIN scans s ON t.scan_id = s.scan_id
                WHERE s.timestamp >= ?
                GROUP BY threat_type
            ''', (cutoff_date,))
            threat_counts = {row['threat_type']: row['count'] for row in cursor.fetchall()}
            
            return {
                'risk_trends': risk_trends,
                'vulnerability_counts': vuln_counts,
                'threat_counts': threat_counts
            }
    
    def cleanup_old_scans(self, days: int = None):
        """Remove scans older than retention period"""
        retention_days = days or config.DATABASE_CONFIG['retention_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scans WHERE timestamp < ?', (cutoff_date,))
            deleted = cursor.rowcount
            return deleted
