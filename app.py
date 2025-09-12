from flask import Flask, request, jsonify, render_template, send_file
import os
import uuid
import json
from datetime import datetime
import logging
import subprocess
import shutil
import traceback

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sbom_tool.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DATABASE_PATH'] = 'sbom_analysis.db'
app.config['REPORT_FOLDER'] = 'static/reports'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

# Check required tools
def check_tools():
    tools = {'grype': False, 'dependency-check': False}

    # Check Grype
    try:
        result = subprocess.run(['grype', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            tools['grype'] = True
            logger.info(f"✅ Grype found: {result.stdout.strip()}")
    except Exception:
        logger.warning("⚠️ Grype not installed")

    # Check OWASP Dependency-Check
    if shutil.which('dependency-check'):
        tools['dependency-check'] = True
        logger.info("✅ OWASP Dependency-Check found")

    return tools

available_tools = check_tools()

# Grype version check endpoint
@app.route("/grype-version")
def grype_version():
    try:
        output = subprocess.check_output(["grype", "--version"])
        return jsonify({"grype_version": output.decode("utf-8").strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =======================
# Mock SBOM processing
# =======================
@app.route('/')
def index():
    return render_template('index.html', tools=available_tools)

@app.route('/upload', methods=['POST'])
def upload_sbom():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    logger.info(f"File uploaded: {filename}")

    # Mock SBOM parsing and scanning
    sbom_data = {"format": "CycloneDX", "components": [{"name": "python", "version": "3.9"}]}
    vulnerabilities = [{"cve_id": "CVE-2021-3449", "severity": "High"}]

    # Generate report
    report_dir = os.path.join(app.config['REPORT_FOLDER'], file_id)
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, 'report.json')
    with open(report_path, 'w') as f:
        json.dump({"components": sbom_data['components'], "vulnerabilities": vulnerabilities}, f)

    return jsonify({
        'success': True,
        'file_id': file_id,
        'components': len(sbom_data['components']),
        'vulnerabilities': len(vulnerabilities)
    })

@app.route('/report/<file_id>/<format_type>')
def download_report(file_id, format_type):
    report_path = os.path.join(app.config['REPORT_FOLDER'], file_id, f'report.{format_type}')
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404
    return send_file(report_path, as_attachment=True, download_name=f'sbom_report_{file_id}.{format_type}')

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'tools': available_tools,
        'database_exists': os.path.exists(app.config['DATABASE_PATH'])
    })

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("🚀 Starting CERT-In SBOM Compliance Tool")
    app.run(host='0.0.0.0', port=5000, debug=True)
