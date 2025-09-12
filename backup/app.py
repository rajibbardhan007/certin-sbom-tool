from flask import Flask, request, jsonify, render_template, send_file
import os
import uuid
import json
from datetime import datetime
import logging
import subprocess
import shutil
import sqlite3
from typing import Dict, List, Any

# Configure logging
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

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

# Check for required tools
def check_tools():
    tools = {'grype': False, 'dependency-check': False}
    
    # Check Grype
    try:
        result = subprocess.run(['grype', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            tools['grype'] = True
            logger.info(f"✅ Grype found: {result.stdout.strip()}")
    except (FileNotFoundError, subprocess.SubprocessError):
        logger.warning("⚠️ Grype not installed")
    
    # Check OWASP Dependency-Check
    try:
        possible_paths = [
            'dependency-check.sh', 'dependency-check',
            '/usr/bin/dependency-check.sh', '/usr/local/bin/dependency-check.sh'
        ]
        for path in possible_paths:
            if shutil.which(path):
                tools['dependency-check'] = True
                logger.info(f"✅ OWASP Dependency-Check found at: {path}")
                break
    except Exception as e:
        logger.warning(f"⚠️ OWASP Dependency-Check not found: {e}")
    
    return tools

# Check tools at startup
available_tools = check_tools()

# Mock implementations first to avoid import errors
class SBOMComponent:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return self.__dict__

class Vulnerability:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return self.__dict__

class SBOMAnalysis:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return {
            'file_id': getattr(self, 'file_id', ''),
            'original_format': getattr(self, 'original_format', ''),
            'components': [comp.to_dict() for comp in getattr(self, 'components', [])],
            'vulnerabilities': [vuln.to_dict() for vuln in getattr(self, 'vulnerabilities', [])],
            'analysis_date': getattr(self, 'analysis_date', ''),
            'metadata': getattr(self, 'metadata', {}),
            'scanner_used': getattr(self, 'scanner_used', 'Unknown')
        }

# Try to import actual implementations
try:
    from sbom_parser import parse_sbom
    from vulnerability_scanner import VulnerabilityScanner
    from certin_enricher import CERTInEnricher
    from report_generator import ReportGenerator
    from database import SBOMDatabase
    
    # Re-import models to override mocks
    from models import SBOMComponent, Vulnerability, SBOMAnalysis
    
    scanner = VulnerabilityScanner(available_tools)
    enricher = CERTInEnricher('component_mapping.csv')
    report_generator = ReportGenerator()
    db = SBOMDatabase(app.config['DATABASE_PATH'])
    
    logger.info("✅ All modules imported successfully")
    
except ImportError as e:
    logger.error(f"❌ Failed to import modules: {e}")
    
    # Mock implementations
    class MockParser:
        def parse_sbom(self, file_path):
            return {
                'format': 'CycloneDX',
                'components': [{
                    'name': 'python', 'version': '3.9.0', 'type': 'library',
                    'description': 'Python programming language',
                    'purl': 'pkg:pypi/python@3.9.0'
                }],
                'metadata': {}
            }
    
    class MockScanner:
        def scan_sbom(self, sbom_data, file_path):
            return [{
                'cve_id': 'CVE-2021-3449', 'severity': 'High', 'cvss_score': 7.5,
                'description': 'Sample vulnerability', 'fixed_versions': ['3.9.1'],
                'component_name': 'python', 'component_version': '3.9.0',
                'vex_status': 'Under Investigation', 'scanner': 'Mock'
            }]
    
    class MockEnricher:
        def enrich_components(self, components, vulnerabilities=None):
            for component in components:
                component.update({
                    'supplier': 'Python Software Foundation', 'origin': 'Open-Source',
                    'release_date': '2020-10-05', 'eol_date': '2025-10-05',
                    'criticality': 'High', 'usage_restrictions': 'None',
                    'comments': 'Python programming language',
                    'executable_property': 'No', 'archive_property': 'No',
                    'structured_property': 'Library',
                    'unique_identifier': component.get('purl', ''),
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'patch_status': 'Patch available' if vulnerabilities else 'Unknown'
                })
            return components
    
    class MockReportGenerator:
        def generate_json_report(self, analysis):
            return json.dumps({'status': 'success', 'components': len(analysis.components)})
        
        def generate_html_report(self, analysis):
            return f"<html><body><h1>Report for {analysis.file_id}</h1></body></html>"
        
        def generate_csaf_report(self, analysis):
            return json.dumps({'status': 'csaf_report'})
        
        def generate_pdf_report(self, analysis, file_path):
            with open(file_path, 'w') as f:
                f.write("PDF Report Content")
            return file_path
    
    class MockDB:
        def save_analysis(self, analysis):
            logger.info(f"Mock save analysis: {analysis.file_id}")
        
        def get_analysis(self, file_id):
            return None
        
        def get_all_analyses(self):
            return []
    
    parse_sbom = MockParser().parse_sbom
    scanner = MockScanner()
    enricher = MockEnricher()
    report_generator = MockReportGenerator()
    db = MockDB()

# Route handlers
@app.route('/')
def index():
    try:
        analyses = db.get_all_analyses()
        return render_template('index.html', analyses=analyses, tools=available_tools)
    except Exception as e:
        logger.error(f"Error loading index: {e}")
        return render_template('index.html', analyses=[], tools=available_tools)

@app.route('/upload', methods=['POST'])
def upload_sbom():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith(('.json', '.xml')):
        return jsonify({'error': 'Only JSON and XML files supported'}), 400
    
    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(file_path)
        logger.info(f"📄 File uploaded: {filename}")
        
        # Parse SBOM
        sbom_data = parse_sbom(file_path)
        if not isinstance(sbom_data, dict) or 'components' not in sbom_data:
            raise ValueError("Invalid SBOM format")
        
        logger.info(f"✅ Parsed {len(sbom_data.get('components', []))} components")
        
        # Scan vulnerabilities
        vulnerabilities = scanner.scan_sbom(sbom_data, file_path)
        logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities")
        
        # Enrich components
        enriched_components = enricher.enrich_components(sbom_data['components'], vulnerabilities)
        logger.info(f"✅ Enriched {len(enriched_components)} components")
        
        # Create objects
        components = [SBOMComponent(**comp) for comp in enriched_components]
        vuln_objects = [Vulnerability(**vuln) for vuln in vulnerabilities]
        
        analysis = SBOMAnalysis(
            file_id=file_id,
            original_format=sbom_data.get('format', 'Unknown'),
            components=components,
            vulnerabilities=vuln_objects,
            analysis_date=datetime.utcnow().isoformat(),
            metadata=sbom_data.get('metadata', {}),
            scanner_used=getattr(scanner, 'scanner_used', 'Unknown')
        )
        
        # Save to database
        db.save_analysis(analysis)
        logger.info("💾 Analysis saved to database")
        
        # Generate reports
        report_dir = os.path.join(app.config['REPORT_FOLDER'], file_id)
        os.makedirs(report_dir, exist_ok=True)
        
        reports = {
            'json': report_generator.generate_json_report(analysis),
            'html': report_generator.generate_html_report(analysis),
            'csaf': report_generator.generate_csaf_report(analysis)
        }
        
        for format, content in reports.items():
            with open(os.path.join(report_dir, f'report.{format}'), 'w') as f:
                f.write(content)
        
        report_generator.generate_pdf_report(analysis, os.path.join(report_dir, 'report.pdf'))
        logger.info("📊 Reports generated successfully")
        
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        
        return jsonify({
            'message': 'SBOM analyzed successfully',
            'file_id': file_id,
            'components': len(components),
            'vulnerabilities': len(vulnerabilities)
        })
        
    except Exception as e:
        logger.error(f"❌ ERROR: {str(e)}", exc_info=True)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
        return jsonify({'error': f'Failed to process SBOM: {str(e)}'}), 500

@app.route('/analysis/<file_id>')
def analysis_results(file_id):
    try:
        analysis = db.get_analysis(file_id)
        if not analysis:
            return render_template('error.html', error='Analysis not found'), 404
        
        return render_template('results.html', analysis=analysis.to_dict())
    
    except Exception as e:
        logger.error(f"Error loading analysis {file_id}: {e}")
        return render_template('error.html', error='Failed to load analysis'), 500

@app.route('/report/<file_id>/<format_type>')
def download_report(file_id, format_type):
    try:
        report_path = os.path.join(app.config['REPORT_FOLDER'], file_id, f'report.{format_type}')
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report not found'}), 404
        
        download_name = f'sbom_report_{file_id}.{format_type}'
        return send_file(report_path, as_attachment=True, download_name=download_name)
    
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({'error': 'Failed to download report'}), 500

# Additional routes and error handlers
@app.route('/api/analyses')
def list_analyses():
    try:
        analyses = db.get_all_analyses()
        return jsonify(analyses)
    except Exception as e:
        return jsonify({'error': 'Failed to list analyses'}), 500

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'tools': available_tools,
        'database': os.path.exists(app.config['DATABASE_PATH'])
    })

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("🚀 Starting CERT-In SBOM Compliance Tool")
    app.run(host='0.0.0.0', port=5000, debug=True)
