import os
import subprocess
import json
import uuid
import sqlite3
import sys
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from werkzeug.utils import secure_filename
import hashlib

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['REPORT_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'malware_sandbox.db')
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production-2024'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'js', 'vbs', 'ps1', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_database():
    """Initialize SQLite database with required tables."""
    os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_size INTEGER,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            is_malicious BOOLEAN,
            confidence REAL,
            entropy REAL,
            yara_matches TEXT,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'completed'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
        )
    ''')
    
    conn.commit()
    conn.close()

def run_analysis(sample_path):
    """Run analysis directly without Docker"""
    try:
        # Add project root to Python path
        project_root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_root)
        
        # Import and run analysis directly
        from analysis import hash_analysis, pe_analysis, string_analysis, entropy, yara_scan, feature_extractor, ml_predict, ioc
        
        # Initialize report
        report = {
            "filename": os.path.basename(sample_path),
            "hashes": {},
            "pe_info": {},
            "strings": {},
            "entropy": 0,
            "yara_matches": [],
            "ml_prediction": {"label": "Unknown", "confidence": 0.0},
            "iocs": {}
        }
        
        # Run analysis steps
        try:
            report['hashes'] = hash_analysis.get_hashes(sample_path)
        except Exception as e:
            print(f"Hash analysis error: {e}", file=sys.stderr)
            
        try:
            report['pe_info'] = pe_analysis.analyze_pe(sample_path)
        except Exception as e:
            print(f"PE analysis error: {e}", file=sys.stderr)
            
        try:
            report['strings'] = string_analysis.extract_indicators(sample_path)
        except Exception as e:
            print(f"String analysis error: {e}", file=sys.stderr)
            
        try:
            report['entropy'] = entropy.calculate_file_entropy(sample_path)
        except Exception as e:
            print(f"Entropy analysis error: {e}", file=sys.stderr)
            
        try:
            rules_dir = os.path.join(project_root, "yara_rules")
            report['yara_matches'] = yara_scan.scan_with_yara(sample_path, rules_dir)
        except Exception as e:
            print(f"YARA scan error: {e}", file=sys.stderr)
            
        try:
            features = feature_extractor.extract_features(sample_path, report)
            model_path = os.path.join(project_root, "models", "malware_model.pkl")
            report['ml_prediction'] = ml_predict.get_prediction(model_path, features)
        except Exception as e:
            print(f"ML prediction error: {e}", file=sys.stderr)
            
        try:
            if 'all_strings' in report.get('strings', {}):
                report['iocs'] = ioc.extract_iocs(report['strings']['all_strings'])
        except Exception as e:
            print(f"IOC extraction error: {e}", file=sys.stderr)
        
        return report
        
    except Exception as e:
        raise e

def save_scan_to_database(scan_id, filename, report_data):
    """Save scan results to database."""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO scans 
        (scan_id, original_filename, stored_filename, file_size, md5, sha1, sha256, 
         is_malicious, confidence, entropy, yara_matches)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id,
        filename,
        f"{scan_id}_{filename}",
        report_data.get('file_size', 0),
        report_data.get('hashes', {}).get('md5', ''),
        report_data.get('hashes', {}).get('sha1', ''),
        report_data.get('hashes', {}).get('sha256', ''),
        report_data.get('ml_prediction', {}).get('label') == 'Malicious',
        report_data.get('ml_prediction', {}).get('confidence', 0),
        report_data.get('entropy', 0),
        json.dumps(report_data.get('yara_matches', []))
    ))
    
    iocs = report_data.get('iocs', {})
    for ioc_type, ioc_list in iocs.items():
        if isinstance(ioc_list, list):
            for ioc_value in ioc_list:
                cursor.execute('''
                    INSERT INTO iocs (scan_id, ioc_type, ioc_value)
                    VALUES (?, ?, ?)
                ''', (scan_id, ioc_type, ioc_value))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Home page with upload form."""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM scans')
    total_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE is_malicious = 1')
    malicious_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT * FROM scans ORDER BY upload_time DESC LIMIT 10')
    recent_scans = cursor.fetchall()
    conn.close()
    
    stats = {
        'total_scans': total_scans,
        'malicious_count': malicious_count,
        'clean_count': total_scans - malicious_count
    }
    
    return render_template('index.html', stats=stats, recent_scans=recent_scans)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and initiate analysis."""
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    if not allowed_file(file.filename):
        flash(f'File type not allowed', 'error')
        return redirect(url_for('index'))
    
    scan_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    stored_filename = f"{scan_id}_{original_filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    
    file.save(filepath)
    
    try:
        report_data = run_analysis(filepath)
        report_data['file_size'] = os.path.getsize(filepath)
        report_data['scan_id'] = scan_id
        report_data['original_filename'] = original_filename
        report_data['upload_time'] = datetime.now().isoformat()
        
        report_filename = f"{scan_id}_report.json"
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        save_scan_to_database(scan_id, original_filename, report_data)
        
        flash('Analysis completed successfully!', 'success')
        return redirect(url_for('view_report', scan_id=scan_id))
        
    except Exception as e:
        flash(f'Error during analysis: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/report/<scan_id>')
def view_report(scan_id):
    """Display detailed analysis report."""
    report_filename = f"{scan_id}_report.json"
    report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
    
    if not os.path.exists(report_path):
        flash('Report not found', 'error')
        return redirect(url_for('index'))
    
    with open(report_path, 'r') as f:
        report_data = json.load(f)
    
    return render_template('report.html', report=report_data)

@app.route('/api/scans')
def api_scans():
    """API endpoint for recent scans."""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY upload_time DESC LIMIT 50')
    scans = cursor.fetchall()
    conn.close()
    
    scan_list = []
    for scan in scans:
        scan_list.append({
            'id': scan[0],
            'scan_id': scan[1],
            'filename': scan[2],
            'md5': scan[5],
            'sha256': scan[7],
            'is_malicious': bool(scan[8]),
            'confidence': scan[9],
            'upload_time': scan[12]
        })
    
    return jsonify(scan_list)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
    os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)
