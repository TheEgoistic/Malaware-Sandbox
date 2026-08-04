"""
Database Operations Module
Handles all database CRUD operations for the malware sandbox
"""

import sqlite3
import json
import os
from datetime import datetime

class DatabaseOperations:
    def __init__(self, db_path='database/malware_sandbox.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    def get_connection(self):
        """Get a database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def save_scan(self, scan_data):
        """Save a complete scan result to the database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Insert main scan record
            cursor.execute('''
                INSERT OR REPLACE INTO scans (
                    scan_id, original_filename, stored_filename,
                    file_size, file_type, md5, sha1, sha256,
                    entropy, is_pe_file, pe_sections, pe_imports_count,
                    pe_entry_point, is_malicious, confidence,
                    benign_probability, malicious_probability,
                    yara_matches_count, yara_matches, iocs_count,
                    risk_score, risk_level, status, upload_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_data.get('scan_id'),
                scan_data.get('original_filename'),
                scan_data.get('stored_filename'),
                scan_data.get('file_size', 0),
                scan_data.get('file_type'),
                scan_data.get('hashes', {}).get('md5'),
                scan_data.get('hashes', {}).get('sha1'),
                scan_data.get('hashes', {}).get('sha256'),
                scan_data.get('entropy', 0),
                1 if scan_data.get('pe_info', {}).get('is_pe') else 0,
                scan_data.get('pe_info', {}).get('number_of_sections', 0),
                len(scan_data.get('pe_info', {}).get('imports', [])),
                scan_data.get('pe_info', {}).get('entry_point'),
                1 if scan_data.get('ml_prediction', {}).get('label') == 'Malicious' else 0,
                scan_data.get('ml_prediction', {}).get('confidence', 0),
                scan_data.get('ml_prediction', {}).get('probabilities', {}).get('benign', 0),
                scan_data.get('ml_prediction', {}).get('probabilities', {}).get('malicious', 0),
                len(scan_data.get('yara_matches', [])),
                json.dumps(scan_data.get('yara_matches', [])),
                sum(len(v) for v in scan_data.get('iocs', {}).values() if isinstance(v, list)),
                0,  # risk_score (calculated by trigger)
                'unknown',  # risk_level (calculated by trigger)
                'completed',
                scan_data.get('upload_time', datetime.now().isoformat())
            ))
            
            # Insert IOCs
            iocs = scan_data.get('iocs', {})
            for ioc_type, ioc_list in iocs.items():
                if isinstance(ioc_list, list):
                    for ioc_value in ioc_list:
                        cursor.execute('''
                            INSERT INTO iocs (scan_id, ioc_type, ioc_value)
                            VALUES (?, ?, ?)
                        ''', (scan_data.get('scan_id'), ioc_type, ioc_value))
            
            # Insert YARA matches
            for match in scan_data.get('yara_matches', []):
                cursor.execute('''
                    INSERT INTO yara_matches (
                        scan_id, rule_name, namespace, tags,
                        meta_data, matched_strings, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_data.get('scan_id'),
                    match.get('rule', 'unknown'),
                    match.get('namespace', ''),
                    json.dumps(match.get('tags', [])),
                    json.dumps(match.get('meta', {})),
                    json.dumps(match.get('strings', [])),
                    match.get('meta', {}).get('severity', 'medium')
                ))
            
            # Insert PE sections
            for section in scan_data.get('pe_info', {}).get('sections', []):
                cursor.execute('''
                    INSERT INTO pe_sections (
                        scan_id, section_name, virtual_size,
                        virtual_address, entropy
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    scan_data.get('scan_id'),
                    section.get('name', ''),
                    section.get('virtual_size', 0),
                    section.get('virtual_address', ''),
                    section.get('entropy', 0)
                ))
            
            # Insert PE imports
            for imp in scan_data.get('pe_info', {}).get('imports', []):
                if ':' in imp:
                    dll, func = imp.split(':', 1)
                    cursor.execute('''
                        INSERT INTO pe_imports (scan_id, dll_name, function_name)
                        VALUES (?, ?, ?)
                    ''', (scan_data.get('scan_id'), dll, func))
            
            # Insert suspicious strings
            strings = scan_data.get('strings', {})
            for url in strings.get('urls', []):
                cursor.execute('''
                    INSERT INTO suspicious_strings (scan_id, string_value, string_type)
                    VALUES (?, ?, 'url')
                ''', (scan_data.get('scan_id'), url))
            
            for ip in strings.get('ips', []):
                cursor.execute('''
                    INSERT INTO suspicious_strings (scan_id, string_value, string_type)
                    VALUES (?, ?, 'ip')
                ''', (scan_data.get('scan_id'), ip))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error saving scan: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def get_scan(self, scan_id):
        """Retrieve a scan by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
        scan = cursor.fetchone()
        conn.close()
        
        return dict(scan) if scan else None
    
    def get_recent_scans(self, limit=10):
        """Get recent scans"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM v_recent_scans LIMIT ?', (limit,))
        scans = cursor.fetchall()
        conn.close()
        
        return [dict(scan) for scan in scans]
    
    def get_malicious_files(self, limit=20):
        """Get malicious files"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM v_malicious_files LIMIT ?', (limit,))
        files = cursor.fetchall()
        conn.close()
        
        return [dict(f) for f in files]
    
    def get_daily_stats(self, days=7):
        """Get daily statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM v_daily_stats 
            ORDER BY date DESC 
            LIMIT ?
        ''', (days,))
        stats = cursor.fetchall()
        conn.close()
        
        return [dict(s) for s in stats]
    
    def search_by_hash(self, hash_value):
        """Search for a file by hash"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans 
            WHERE md5 = ? OR sha1 = ? OR sha256 = ?
        ''', (hash_value, hash_value, hash_value))
        scan = cursor.fetchone()
        conn.close()
        
        return dict(scan) if scan else None
    
    def search_iocs(self, ioc_value):
        """Search for IOCs across all scans"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT s.*, i.ioc_type, i.ioc_value
            FROM scans s
            JOIN iocs i ON s.scan_id = i.scan_id
            WHERE i.ioc_value LIKE ?
            ORDER BY s.upload_time DESC
        ''', (f'%{ioc_value}%',))
        results = cursor.fetchall()
        conn.close()
        
        return [dict(r) for r in results]
    
    def get_statistics(self):
        """Get overall statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        stats['total_scans'] = cursor.fetchone()[0]
        
        # Malicious count
        cursor.execute('SELECT COUNT(*) FROM scans WHERE is_malicious = 1')
        stats['malicious_count'] = cursor.fetchone()[0]
        
        # Today's scans
        cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(upload_time) = DATE('now')")
        stats['today_scans'] = cursor.fetchone()[0]
        
        # Average entropy
        cursor.execute('SELECT AVG(entropy) FROM scans')
        stats['avg_entropy'] = round(cursor.fetchone()[0] or 0, 2)
        
        # Top YARA rules
        cursor.execute('''
            SELECT rule_name, COUNT(*) as count 
            FROM yara_matches 
            GROUP BY rule_name 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        stats['top_yara_rules'] = [dict(r) for r in cursor.fetchall()]
        
        # Top IOCs
        cursor.execute('''
            SELECT ioc_type, COUNT(*) as count 
            FROM iocs 
            GROUP BY ioc_type 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        stats['top_iocs'] = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        return stats
    
    def delete_scan(self, scan_id):
        """Delete a scan and all associated data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting scan: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def cleanup_old_scans(self, days=30):
        """Delete scans older than specified days"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                DELETE FROM scans 
                WHERE upload_time < datetime('now', ?)
            ''', (f'-{days} days',))
            deleted_count = cursor.rowcount
            conn.commit()
            return deleted_count
        except Exception as e:
            print(f"Error cleaning up scans: {e}")
            conn.rollback()
            return 0
        finally:
            conn.close()

if __name__ == "__main__":
    # Test database operations
    db = DatabaseOperations()
    stats = db.get_statistics()
    print("Database Statistics:")
    print(json.dumps(stats, indent=2))

