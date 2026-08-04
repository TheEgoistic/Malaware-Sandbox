"""
Configuration Settings for Malware Analysis Sandbox
Central configuration file for all components
"""

import os
from datetime import timedelta

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration class"""
    
    # ============================================
    # Flask Settings
    # ============================================
    SECRET_KEY = os.environ.get('SECRET_KEY', 'malware-sandbox-secret-key-change-in-production')
    DEBUG = False
    TESTING = False
    HOST = '0.0.0.0'
    PORT = 5000
    
    # ============================================
    # File Upload Settings
    # ============================================
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORT_FOLDER = os.path.join(BASE_DIR, 'reports')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max file size
    
    # Allowed file extensions for analysis
    ALLOWED_EXTENSIONS = {
        'exe', 'dll', 'bin', 'sys', 'com', 'scr',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', '7z', 'tar', 'gz',
        'js', 'vbs', 'ps1', 'bat', 'cmd',
        'msi', 'jar', 'py', 'php'
    }
    
    # File size categories (bytes)
    FILE_SIZE_CATEGORIES = {
        'small': 1024 * 1024,        # 1 MB
        'medium': 10 * 1024 * 1024,  # 10 MB
        'large': 50 * 1024 * 1024,   # 50 MB
    }
    
    # ============================================
    # Database Settings
    # ============================================
    DATABASE_FOLDER = os.path.join(BASE_DIR, 'database')
    DATABASE_PATH = os.path.join(DATABASE_FOLDER, 'malware_sandbox.db')
    DATABASE_BACKUP_FOLDER = os.path.join(DATABASE_FOLDER, 'backups')
    
    # SQLite pragmas for performance
    SQLITE_PRAGMAS = {
        'journal_mode': 'WAL',           # Write-Ahead Logging
        'cache_size': -64 * 1024,        # 64 MB cache
        'foreign_keys': 'ON',            # Enable foreign keys
        'temp_store': 'MEMORY',          # Store temp tables in memory
        'synchronous': 'NORMAL',         # Balance safety/speed
    }
    
    # ============================================
    # Docker Settings
    # ============================================
    DOCKER_IMAGE_NAME = 'malware-analyzer'
    DOCKERFILE_PATH = os.path.join(BASE_DIR, 'docker', 'Dockerfile')
    DOCKER_TIMEOUT = 120  # seconds
    DOCKER_MEMORY_LIMIT = '512m'
    DOCKER_CPU_LIMIT = 1
    
    # Docker security options
    DOCKER_SECURITY_OPTS = [
        'no-new-privileges',
    ]
    
    # Docker capabilities to drop
    DOCKER_CAP_DROP = [
        'ALL',
    ]
    
    # Docker mount points
    DOCKER_MOUNTS = {
        'samples': {
            'host': UPLOAD_FOLDER,
            'container': '/samples',
            'mode': 'ro'  # read-only
        }
    }
    
    # ============================================
    # Analysis Settings
    # ============================================
    ANALYSIS_TIMEOUT = 300  # 5 minutes max analysis time
    
    # Hash types to generate
    HASH_ALGORITHMS = ['md5', 'sha1', 'sha256']
    
    # String extraction settings
    STRING_MIN_LENGTH = 4
    STRING_MAX_COUNT = 10000
    
    # Entropy thresholds
    ENTROPY_THRESHOLDS = {
        'low': 4.0,      # Normal files
        'medium': 7.0,   # Possibly packed
        'high': 7.5,     # Likely packed/encrypted
        'critical': 8.0  # Maximum entropy
    }
    
    # PE Analysis settings
    PE_SETTINGS = {
        'max_sections': 20,           # Suspicious if more sections
        'suspicious_section_names': [  # Commonly abused section names
            '.text', '.data', '.rdata', '.bss',
            '.edata', '.idata', '.reloc', '.rsrc'
        ],
        'suspicious_imports': [       # APIs commonly used by malware
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'OpenProcess', 'ReadProcessMemory',
            'NtUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext',
            'CryptEncrypt', 'CryptDecrypt', 'WinExec', 'ShellExecute',
            'URLDownloadToFile', 'InternetOpen', 'InternetConnect'
        ]
    }
    
    # ============================================
    # YARA Settings
    # ============================================
    YARA_RULES_FOLDER = os.path.join(BASE_DIR, 'yara_rules')
    YARA_TIMEOUT = 60  # seconds per scan
    YARA_MAX_RULES = 1000
    
    # YARA rule categories
    YARA_CATEGORIES = {
        'ransomware': 'ransomware.yar',
        'trojan': 'trojan.yar',
        'miner': 'miner.yar',
        'generic': 'generic_malware.yar'
    }
    
    # ============================================
    # Machine Learning Settings
    # ============================================
    ML_MODEL_PATH = os.path.join(BASE_DIR, 'models', 'malware_model.pkl')
    ML_FEATURE_NAMES_PATH = os.path.join(BASE_DIR, 'models', 'feature_names.pkl')
    ML_CONFIDENCE_THRESHOLD = 0.6  # 60% confidence required for classification
    
    # Feature extraction settings
    FEATURE_SETTINGS = {
        'use_derived_features': True,
        'normalize_features': True,
        'feature_version': '1.0'
    }
    
    # ============================================
    # VirusTotal Settings (Optional)
    # ============================================
    VIRUSTOTAL_ENABLED = False
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', None)
    VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3'
    VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute (free tier)
    
    # ============================================
    # Logging Settings
    # ============================================
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = 'malware_sandbox.log'
    LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 5
    
    # ============================================
    # Report Settings
    # ============================================
    REPORT_FORMATS = ['json', 'pdf']
    REPORT_TEMPLATE = os.path.join(BASE_DIR, 'templates', 'report.html')
    
    # Risk scoring weights
    RISK_SCORE_WEIGHTS = {
        'entropy': 0.20,
        'yara_matches': 0.30,
        'ml_prediction': 0.25,
        'suspicious_imports': 0.15,
        'ioc_count': 0.10
    }
    
    # Risk level thresholds
    RISK_LEVELS = {
        'clean': 0,
        'low': 25,
        'medium': 50,
        'high': 75,
        'critical': 90
    }
    
    # ============================================
    # Dashboard Settings
    # ============================================
    DASHBOARD_REFRESH_INTERVAL = 30  # seconds
    RECENT_SCANS_LIMIT = 50
    CHART_COLORS = {
        'malicious': '#dc3545',
        'benign': '#28a745',
        'unknown': '#ffc107',
        'entropy_low': '#28a745',
        'entropy_medium': '#ffc107',
        'entropy_high': '#dc3545'
    }
    
    # ============================================
    # API Settings (Future)
    # ============================================
    API_VERSION = 'v1'
    API_RATE_LIMIT = 100  # requests per hour
    API_KEY_LENGTH = 32
    
    # ============================================
    # Security Settings
    # ============================================
    # Session settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # Rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 60  # requests per minute
    RATE_LIMIT_WINDOW = 60  # seconds
    
    # ============================================
    # Paths Configuration
    # ============================================
    @classmethod
    def get_all_paths(cls):
        """Return all important paths"""
        return {
            'BASE_DIR': cls.BASE_DIR,
            'UPLOAD_FOLDER': cls.UPLOAD_FOLDER,
            'REPORT_FOLDER': cls.REPORT_FOLDER,
            'DATABASE_PATH': cls.DATABASE_PATH,
            'YARA_RULES_FOLDER': cls.YARA_RULES_FOLDER,
            'ML_MODEL_PATH': cls.ML_MODEL_PATH,
            'LOG_FOLDER': cls.LOG_FOLDER,
            'DOCKERFILE_PATH': cls.DOCKERFILE_PATH,
        }
    
    # ============================================
    # Initialization
    # ============================================
    @classmethod
    def init_directories(cls):
        """Create all necessary directories"""
        directories = [
            cls.UPLOAD_FOLDER,
            cls.REPORT_FOLDER,
            cls.DATABASE_FOLDER,
            cls.DATABASE_BACKUP_FOLDER,
            cls.YARA_RULES_FOLDER,
            cls.LOG_FOLDER,
            os.path.dirname(cls.ML_MODEL_PATH),
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        # Create .gitkeep files to track empty directories
        gitkeep_dirs = [cls.UPLOAD_FOLDER, cls.REPORT_FOLDER, cls.LOG_FOLDER]
        for directory in gitkeep_dirs:
            gitkeep_path = os.path.join(directory, '.gitkeep')
            if not os.path.exists(gitkeep_path):
                with open(gitkeep_path, 'w') as f:
                    pass


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    SECRET_KEY = 'dev-secret-key-not-for-production'
    SESSION_COOKIE_SECURE = False
    DOCKER_TIMEOUT = 300  # Longer timeout for debugging
    RATE_LIMIT_ENABLED = False


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    DATABASE_PATH = os.path.join(Config.BASE_DIR, 'database', 'test_malware_sandbox.db')
    UPLOAD_FOLDER = os.path.join(Config.BASE_DIR, 'uploads_test')
    REPORT_FOLDER = os.path.join(Config.BASE_DIR, 'reports_test')
    WTF_CSRF_ENABLED = False
    DOCKER_TIMEOUT = 60


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Production database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', '/var/lib/malware-sandbox/malware_sandbox.db')
    
    # Stricter security
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Production rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 30


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    
    return config.get(env, config['default'])


# Helper functions
def get_database_uri():
    """Get database URI"""
    return f"sqlite:///{Config.DATABASE_PATH}"


def get_upload_path(filename=None):
    """Get upload path for a file"""
    if filename:
        return os.path.join(Config.UPLOAD_FOLDER, filename)
    return Config.UPLOAD_FOLDER


def get_report_path(report_id=None):
    """Get report path"""
    if report_id:
        return os.path.join(Config.REPORT_FOLDER, f"{report_id}_report.json")
    return Config.REPORT_FOLDER


def is_allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS


# Initialize directories when module is imported
Config.init_directories()


if __name__ == "__main__":
    # Print configuration summary when run directly
    print("=" * 60)
    print("MALWARE SANDBOX CONFIGURATION")
    print("=" * 60)
    
    current_config = get_config()
    
    print(f"\nEnvironment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"Debug Mode: {current_config.DEBUG}")
    
    print("\n--- Paths ---")
    for name, path in current_config.get_all_paths().items():
        exists = os.path.exists(path)
        status = "✓" if exists else "✗ (not created yet)"
        print(f"  {name}: {path} {status}")
    
    print("\n--- Analysis Settings ---")
    print(f"  YARA Rules: {len(current_config.YARA_CATEGORIES)} categories")
    print(f"  ML Model: {'Available' if os.path.exists(current_config.ML_MODEL_PATH) else 'Not found'}")
    print(f"  VirusTotal: {'Enabled' if current_config.VIRUSTOTAL_ENABLED else 'Disabled'}")
    
    print("\n--- Security Settings ---")
    print(f"  Session Secure: {current_config.SESSION_COOKIE_SECURE}")
    print(f"  Rate Limiting: {'Enabled' if current_config.RATE_LIMIT_ENABLED else 'Disabled'}")
    print(f"  Max Upload Size: {current_config.MAX_CONTENT_LENGTH / (1024*1024):.0f} MB")
    
    print("\n--- Allowed File Types ---")
    print(f"  {', '.join(sorted(current_config.ALLOWED_EXTENSIONS))}")
    
    print("\n" + "=" * 60)


