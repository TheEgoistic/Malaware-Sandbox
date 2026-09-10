import os
import subprocess
import json
import uuid
import sqlite3
import sys
import signal
import atexit
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from werkzeug.utils import secure_filename
import hashlib

# LXD Container Management
LXD_CONTAINER_NAME = "malware-analyzer-sandbox"
lxd_container_created = False
# In app.py, set this to skip LXD
SKIP_LXD = True

if not SKIP_LXD:
    create_lxd_container()

def create_lxd_container():
    """Create LXD container for malware analysis"""
    global lxd_container_created
    
    print("\n" + "="*60)
    print("SETTING UP LXD CONTAINER")
    print("="*60)
    
    try:
        # Check if LXD is available
        result = subprocess.run(['lxc', 'list'], capture_output=True, text=True)
        if result.returncode != 0:
            print("⚠ LXD not available, running directly")
            return False
        
        # Delete old container if exists
        print("[1] Cleaning up old containers...")
        subprocess.run(['lxc', 'delete', LXD_CONTAINER_NAME, '--force'], 
                      capture_output=True, text=True)
        
        # Create new container
        print("[2] Creating new LXD container...")
        result = subprocess.run(['lxc', 'launch', 'ubuntu:22.04', LXD_CONTAINER_NAME],
                               capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"⚠ Could not create container: {result.stderr}")
            return False
        
        print(f"✓ Container '{LXD_CONTAINER_NAME}' created")
        
        # Wait for container to be ready
        print("[3] Waiting for container to initialize...")
        subprocess.run(['sleep', '5'])
        
        # Install necessary tools
        print("[4] Installing analysis tools in container...")
        subprocess.run(['lxc', 'exec', LXD_CONTAINER_NAME, '--', 
                       'apt-get', 'update'], capture_output=True, text=True)
        subprocess.run(['lxc', 'exec', LXD_CONTAINER_NAME, '--', 
                       'apt-get', 'install', '-y', 'python3', 'python3-pip', 'binutils'],
                       capture_output=True, text=True)
        
        print("✓ Tools installed")
        lxd_container_created = True
        print("="*60)
        print("LXD CONTAINER READY")
        print("="*60 + "\n")
        return True
        
    except Exception as e:
        print(f"⚠ Error creating LXD container: {e}")
        return False

def delete_lxd_container():
    """Delete LXD container on shutdown"""
    global lxd_container_created
    
    if not lxd_container_created:
        return
    
    print("\n" + "="*60)
    print("CLEANING UP LXD CONTAINER")
    print("="*60)
    
    try:
        # Stop container
        print("[1] Stopping container...")
        subprocess.run(['lxc', 'stop', LXD_CONTAINER_NAME], 
                      capture_output=True, text=True)
        
        # Delete container
        print("[2] Deleting container...")
        subprocess.run(['lxc', 'delete', LXD_CONTAINER_NAME, '--force'],
                      capture_output=True, text=True)
        
        print(f"✓ Container '{LXD_CONTAINER_NAME}' deleted")
        print("="*60 + "\n")
    except Exception as e:
        print(f"⚠ Error deleting container: {e}")

def run_analysis_in_lxd(sample_path):
    """Run analysis in LXD container"""
    if not lxd_container_created:
        print("⚠ LXD container not available, running directly")
        return run_analysis_direct(sample_path)
    
    try:
        # Get filename
        filename = os.path.basename(sample_path)
        container_file = f"/root/{filename}"
        
        # Push file to container
        print(f"Pushing file to LXD container...")
        subprocess.run(['lxc', 'file', 'push', sample_path, 
                       f'{LXD_CONTAINER_NAME}{container_file}'],
                       capture_output=True, text=True)
        
        # Create analysis script in container
        analysis_script = '''
import hashlib
import json
import os
import sys
import math
from collections import Counter

def get_hashes(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256': sha256.hexdigest()}

def get_entropy(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data:
        return 0
    freq = Counter(data)
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

filepath = sys.argv[1]
report = {
    'filename': os.path.basename(filepath),
    'hashes': get_hashes(filepath),
    'entropy': get_entropy(filepath),
    'size': os.path.getsize(filepath),
    'analysis_environment': 'LXD Container'
}
print(json.dumps(report))
'''
        
        # Write script to temp file
        script_path = '/tmp/lxd_analysis.py'
        with open(script_path, 'w') as f:
            f.write(analysis_script)
        
        # Push script to container
        subprocess.run(['lxc', 'file', 'push', script_path, 
                       f'{LXD_CONTAINER_NAME}/root/analyze.py'],
                       capture_output=True, text=True)
        
        # Run analysis in container
        print("Running analysis in LXD container...")
        result = subprocess.run(['lxc', 'exec', LXD_CONTAINER_NAME, '--',
                                'python3', '/root/analyze.py', container_file],
                               capture_output=True, text=True)
        
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"LXD analysis failed: {result.stderr}")
            return run_analysis_direct(sample_path)
            
    except Exception as e:
        print(f"Error in LXD analysis: {e}")
        return run_analysis_direct(sample_path)

def run_analysis_direct(sample_path):
    """Run analysis directly (fallback)"""
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_root)
        
        from analysis import hash_analysis, pe_analysis, string_analysis, entropy, yara_scan, feature_extractor, ml_predict, ioc
        
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

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['REPORT_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'malware_sandbox.db')
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production-2024'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'js', 'vbs', 'ps1', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_database():
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

def save_scan_to_database(scan_id, filename, report_data):
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
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    if not allowed_file(file.filename):
        flash('File type not allowed', 'error')
        return redirect(url_for('index'))
    
    scan_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    stored_filename = f"{scan_id}_{original_filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    
    file.save(filepath)
    
    try:
        # Run analysis in LXD container
        report_data = run_analysis_in_lxd(filepath)
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
    # Create directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
    os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
    
    # Initialize database
    init_database()
    
    # Create LXD container
    create_lxd_container()
    
    # Register cleanup on exit
    atexit.register(delete_lxd_container)
    signal.signal(signal.SIGTERM, lambda s, f: (delete_lxd_container(), exit(0)))
    signal.signal(signal.SIGINT, lambda s, f: (delete_lxd_container(), exit(0)))
    
    # Start Flask
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        delete_lxd_container()
