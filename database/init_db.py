"""
Database Initialization Script for Malware Analysis Sandbox
Creates all necessary tables and indexes
"""

import sqlite3
import os
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path='database/malware_sandbox.db'):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
    
    def connect(self):
        """Establish database connection"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        return self.conn
    
    def create_tables(self):
        """Create all database tables"""
        
        # Scans table - main analysis records
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                file_type TEXT,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                entropy REAL DEFAULT 0.0,
                is_pe_file BOOLEAN DEFAULT 0,
                pe_sections INTEGER DEFAULT 0,
                pe_imports_count INTEGER DEFAULT 0,
                pe_entry_point TEXT,
                is_malicious BOOLEAN DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                benign_probability REAL DEFAULT 0.0,
                malicious_probability REAL DEFAULT 0.0,
                yara_matches_count INTEGER DEFAULT 0,
                yara_matches TEXT,
                iocs_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'unknown',
                analysis_duration REAL DEFAULT 0.0,
                status TEXT DEFAULT 'pending',
                error_message TEXT,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                analysis_time TIMESTAMP,
                user_ip TEXT,
                user_agent TEXT
            )
        ''')
        
        # IOCs table - Indicators of Compromise
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                ioc_category TEXT,
                severity TEXT DEFAULT 'low',
                description TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        ''')
        
        # YARA matches table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS yara_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                rule_file TEXT,
                namespace TEXT,
                tags TEXT,
                meta_data TEXT,
                matched_strings TEXT,
                severity TEXT DEFAULT 'medium',
                match_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        ''')
        
        # PE sections table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS pe_sections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                section_name TEXT NOT NULL,
                virtual_size INTEGER,
                virtual_address TEXT,
                raw_size INTEGER,
                raw_address TEXT,
                entropy REAL DEFAULT 0.0,
                characteristics TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        ''')
        
        # PE imports table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS pe_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                dll_name TEXT NOT NULL,
                function_name TEXT NOT NULL,
                import_type TEXT DEFAULT 'import',
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        ''')
        
        # Strings found table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_strings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                string_value TEXT NOT NULL,
                string_type TEXT,
                offset INTEGER,
                length INTEGER,
                encoding TEXT DEFAULT 'ascii',
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        ''')
        
        # Analysis statistics table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE UNIQUE NOT NULL,
                total_scans INTEGER DEFAULT 0,
                malicious_count INTEGER DEFAULT 0,
                benign_count INTEGER DEFAULT 0,
                unknown_count INTEGER DEFAULT 0,
                avg_entropy REAL DEFAULT 0.0,
                avg_confidence REAL DEFAULT 0.0,
                most_common_malware_type TEXT,
                top_yara_rule TEXT,
                top_ioc_type TEXT
            )
        ''')
        
        # Users table (for future authentication)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # API keys table (for future API access)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                api_key TEXT UNIQUE NOT NULL,
                name TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
    
    def create_indexes(self):
        """Create database indexes for performance"""
        
        # Scans indexes
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_md5 ON scans(md5)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_malicious ON scans(is_malicious)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_upload_time ON scans(upload_time)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level)')
        
        # IOCs indexes
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_scan_id ON iocs(scan_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_category ON iocs(ioc_category)')
        
        # YARA matches indexes
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_yara_scan_id ON yara_matches(scan_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_yara_rule_name ON yara_matches(rule_name)')
        
        # PE data indexes
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_pe_sections_scan_id ON pe_sections(scan_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_pe_imports_scan_id ON pe_imports(scan_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_pe_imports_dll ON pe_imports(dll_name)')
        
        # Suspicious strings index
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_strings_scan_id ON suspicious_strings(scan_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_strings_type ON suspicious_strings(string_type)')
        
        # Stats index
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_stats_date ON analysis_stats(date)')
    
    def create_views(self):
        """Create useful database views"""
        
        # Recent scans summary view
        self.cursor.execute('''
            CREATE VIEW IF NOT EXISTS v_recent_scans AS
            SELECT 
                scan_id,
                original_filename,
                file_size,
                md5,
                sha256,
                entropy,
                is_malicious,
                confidence,
                risk_level,
                status,
                upload_time
            FROM scans
            ORDER BY upload_time DESC
        ''')
        
        # Malicious files view
        self.cursor.execute('''
            CREATE VIEW IF NOT EXISTS v_malicious_files AS
            SELECT 
                s.scan_id,
                s.original_filename,
                s.file_size,
                s.md5,
                s.sha256,
                s.entropy,
                s.confidence,
                s.risk_level,
                COUNT(i.id) as ioc_count,
                COUNT(y.id) as yara_count,
                s.upload_time
            FROM scans s
            LEFT JOIN iocs i ON s.scan_id = i.scan_id
            LEFT JOIN yara_matches y ON s.scan_id = y.scan_id
            WHERE s.is_malicious = 1
            GROUP BY s.scan_id
            ORDER BY s.upload_time DESC
        ''')
        
        # Daily statistics view
        self.cursor.execute('''
            CREATE VIEW IF NOT EXISTS v_daily_stats AS
            SELECT 
                DATE(upload_time) as date,
                COUNT(*) as total_scans,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious_count,
                SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as benign_count,
                AVG(entropy) as avg_entropy,
                AVG(confidence) as avg_confidence,
                COUNT(DISTINCT user_ip) as unique_ips
            FROM scans
            GROUP BY DATE(upload_time)
            ORDER BY date DESC
        ''')
    
    def create_triggers(self):
        """Create database triggers for automatic updates"""
        
        # Update analysis stats trigger
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS trg_update_stats
            AFTER INSERT ON scans
            BEGIN
                INSERT OR REPLACE INTO analysis_stats (
                    date,
                    total_scans,
                    malicious_count,
                    benign_count,
                    avg_entropy,
                    avg_confidence
                )
                SELECT 
                    DATE(NEW.upload_time),
                    COUNT(*),
                    SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END),
                    AVG(entropy),
                    AVG(confidence)
                FROM scans
                WHERE DATE(upload_time) = DATE(NEW.upload_time);
            END
        ''')
        
        # Update risk score trigger
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS trg_calculate_risk
            AFTER INSERT ON iocs
            BEGIN
                UPDATE scans 
                SET risk_score = (
                    SELECT 
                        CASE 
                            WHEN COUNT(*) > 10 THEN 100
                            WHEN COUNT(*) > 5 THEN 75
                            WHEN COUNT(*) > 2 THEN 50
                            WHEN COUNT(*) > 0 THEN 25
                            ELSE 0
                        END
                    FROM iocs 
                    WHERE scan_id = NEW.scan_id
                ),
                risk_level = (
                    SELECT 
                        CASE 
                            WHEN COUNT(*) > 10 THEN 'critical'
                            WHEN COUNT(*) > 5 THEN 'high'
                            WHEN COUNT(*) > 2 THEN 'medium'
                            WHEN COUNT(*) > 0 THEN 'low'
                            ELSE 'clean'
                        END
                    FROM iocs 
                    WHERE scan_id = NEW.scan_id
                )
                WHERE scan_id = NEW.scan_id;
            END
        ''')
    
    def insert_sample_data(self):
        """Insert sample data for testing"""
        
        # Insert default admin user (password: admin123)
        import hashlib
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        
        self.cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin@malware-sandbox.local', admin_password, 'admin'))
        
        # Insert sample API key
        self.cursor.execute('''
            INSERT OR IGNORE INTO api_keys (user_id, api_key, name)
            VALUES (?, ?, ?)
        ''', (1, 'sample-api-key-for-testing', 'Test Key'))
    
    def initialize(self):
        """Run full database initialization"""
        self.connect()
        
        print("[*] Creating tables...")
        self.create_tables()
        
        print("[*] Creating indexes...")
        self.create_indexes()
        
        print("[*] Creating views...")
        self.create_views()
        
        print("[*] Creating triggers...")
        self.create_triggers()
        
        print("[*] Inserting sample data...")
        self.insert_sample_data()
        
        # Commit changes
        self.conn.commit()
        
        # Print database info
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = self.cursor.fetchall()
        print(f"\n[+] Created {len(tables)} tables:")
        for table in tables:
            self.cursor.execute(f"SELECT COUNT(*) FROM {table['name']}")
            count = self.cursor.fetchone()[0]
            print(f"    - {table['name']}: {count} rows")
        
        self.conn.close()
        print("\n[✓] Database initialization complete!")

if __name__ == "__main__":
    db = DatabaseManager()
    db.initialize()

