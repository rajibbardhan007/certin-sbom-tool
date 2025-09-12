import json
from jinja2 import Template
from datetime import datetime
import os
import subprocess
from typing import Dict, List, Any

class ReportGenerator:
    def generate_json_report(self, analysis):
        """Generate JSON report with all CERT-In requirements"""
        report_data = {
            'analysis_id': analysis.file_id,
            'date': analysis.analysis_date,
            'format': analysis.original_format,
            'scanner_used': getattr(analysis, 'scanner_used', 'Unknown'),
            'components': [self._component_to_dict(c) for c in analysis.components],
            'vulnerabilities': [self._vuln_to_dict(v) for v in analysis.vulnerabilities],
            'summary': self._generate_summary(analysis),
            'certin_compliance': self._generate_certin_compliance(analysis),
            'metadata': analysis.metadata or {}
        }
        return json.dumps(report_data, indent=2)
    
    def generate_html_report(self, analysis):
        """Generate HTML report with scanner information"""
        # Load template from file or use default
        template_path = 'templates/report_template.html'
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                template_str = f.read()
        else:
            template_str = self._get_default_html_template()
        
        summary = self._generate_summary(analysis)
        
        # Group vulnerabilities by component
        component_vulnerabilities = {}
        for vuln in analysis.vulnerabilities:
            comp_id = f"{vuln.component_name}@{vuln.component_version}"
            if comp_id not in component_vulnerabilities:
                component_vulnerabilities[comp_id] = []
            component_vulnerabilities[comp_id].append(vuln)
        
        # Create Jinja2 template and render
        template = Template(template_str)
        
        return template.render(
            analysis_date=analysis.analysis_date,
            file_id=analysis.file_id,
            original_format=analysis.original_format,
            scanner_used=getattr(analysis, 'scanner_used', 'Unknown'),
            components=analysis.components,
            vulnerabilities=analysis.vulnerabilities,
            component_vulnerabilities=component_vulnerabilities,
            summary=summary,
            compliance=self._generate_certin_compliance(analysis)
        )
    
    def generate_csaf_report(self, analysis):
        """Generate CSAF/VEX compliant report"""
        csaf = {
            "document": {
                "title": "CERT-In SBOM Vulnerability Report",
                "tracking": {
                    "id": analysis.file_id,
                    "version": "1.0",
                    "current_release_date": datetime.utcnow().isoformat() + "Z",
                    "generator": {
                        "engine": {
                            "name": "CERT-In SBOM Tool",
                            "version": "1.0"
                        }
                    }
                },
                "publisher": {
                    "name": "CERT-In SBOM Compliance Tool",
                    "category": "coordinator"
                }
            },
            "product_tree": {
                "branches": [
                    {
                        "name": "SBOM Components",
                        'category': 'product_name',
                        "branches": []
                    }
                ]
            },
            "vulnerabilities": []
        }
        
        # Add products to product tree
        for component in analysis.components:
            csaf["product_tree"]["branches"][0]["branches"].append({
                "name": f"{component.name} {component.version}",
                "category": "product_version",
                "product": {
                    "name": component.name,
                    "version": component.version,
                    "purl": getattr(component, 'unique_identifier', '')
                }
            })
        
        # Add vulnerabilities
        for vuln in analysis.vulnerabilities:
            csaf["vulnerabilities"].append({
                "cve": vuln.cve_id,
                "product_status": {
                    "known_affected": [f"{vuln.component_name} {vuln.component_version}"]
                },
                "scores": [
                    {
                        "cvss_v3": {
                            "version": "3.1",
                            "baseScore": vuln.cvss_score,
                            "baseSeverity": vuln.severity
                        }
                    }
                ],
                "remarks": [
                    {
                        "category": "exploitation",
                        "text": vuln.description
                    }
                ],
                "remediations": [
                    {
                        "category": "mitigation",
                        "details": f"Fixed in versions: {', '.join(vuln.fixed_versions) if vuln.fixed_versions else 'No fix available'}",
                        "url": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}"
                    }
                ]
            })
        
        return json.dumps(csaf, indent=2)
    
    def generate_pdf_report(self, analysis, file_path):
        """Generate PDF report using WeasyPrint or similar"""
        try:
            # First generate HTML report
            html_content = self.generate_html_report(analysis)
            
            # Save HTML temporarily
            temp_html = file_path.replace('.pdf', '.html')
            with open(temp_html, 'w') as f:
                f.write(html_content)
            
            # Try to convert to PDF using WeasyPrint
            try:
                from weasyprint import HTML
                HTML(temp_html).write_pdf(file_path)
            except ImportError:
                # Fallback to using external tool like wkhtmltopdf
                try:
                    subprocess.run(['wkhtmltopdf', temp_html, file_path], check=True)
                except (subprocess.SubprocessError, FileNotFoundError):
                    # Final fallback: create a simple text PDF
                    self._create_simple_pdf(analysis, file_path)
            
            # Clean up temporary HTML file
            if os.path.exists(temp_html):
                os.remove(temp_html)
                
        except Exception as e:
            # If all else fails, create a simple PDF
            self._create_simple_pdf(analysis, file_path)
    
    def _create_simple_pdf(self, analysis, file_path):
        """Create a simple text-based PDF as fallback"""
        try:
            from fpdf import FPDF
            
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            # Add title
            pdf.cell(200, 10, txt="CERT-In SBOM Compliance Report", ln=1, align='C')
            pdf.ln(10)
            
            # Add basic info
            pdf.cell(200, 10, txt=f"Analysis ID: {analysis.file_id}", ln=1)
            pdf.cell(200, 10, txt=f"Date: {analysis.analysis_date}", ln=1)
            pdf.cell(200, 10, txt=f"Format: {analysis.original_format}", ln=1)
            pdf.cell(200, 10, txt=f"Scanner: {getattr(analysis, 'scanner_used', 'Unknown')}", ln=1)
            pdf.ln(10)
            
            # Add summary
            summary = self._generate_summary(analysis)
            pdf.cell(200, 10, txt=f"Components: {summary['total_components']}", ln=1)
            pdf.cell(200, 10, txt=f"Vulnerabilities: {summary['total_vulnerabilities']}", ln=1)
            pdf.ln(10)
            
            # Save PDF
            pdf.output(file_path)
            
        except ImportError:
            # If FPDF is not available, create a text file instead
            with open(file_path.replace('.pdf', '.txt'), 'w') as f:
                f.write(f"CERT-In SBOM Compliance Report\n")
                f.write(f"Analysis ID: {analysis.file_id}\n")
                f.write(f"Date: {analysis.analysis_date}\n")
                f.write(f"Format: {analysis.original_format}\n")
                f.write(f"Scanner: {getattr(analysis, 'scanner_used', 'Unknown')}\n")
    
    def _get_default_html_template(self):
        """Default HTML template for reports"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CERT-In SBOM Compliance Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
                .component { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .vulnerability { padding: 10px; margin: 5px 0; border-radius: 3px; }
                .critical { background: #f8d7da; border-left: 4px solid #dc3545; }
                .high { background: #fff3cd; border-left: 4px solid #ffc107; }
                .medium { background: #d1ecf1; border-left: 4px solid #17a2b8; }
                .low { background: #d4edda; border-left: 4px solid #28a745; }
                .unknown { background: #e2e3e5; border-left: 4px solid #6c757d; }
                .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .certin-field { background: #e9ecef; padding: 5px; border-radius: 3px; margin: 2px 0; }
                .license-details { background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 5px 0; }
                .compliance-badge { background: #28a745; color: white; padding: 5px 10px; border-radius: 3px; }
                .dependency-list { margin-left: 20px; }
                .hash-value { font-family: monospace; font-size: 12px; }
                .scanner-info { background: #e9ecef; padding: 10px; border-radius: 5px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📋 CERT-In SBOM Compliance Report</h1>
                <p><strong>Generated:</strong> {{ analysis_date }}</p>
                <p><strong>Analysis ID:</strong> {{ file_id }}</p>
                <p><strong>Format:</strong> {{ original_format }}</p>
                <p><strong>Scanners Used:</strong> {{ scanner_used }}</p>
                <p><strong>Compliance Status:</strong> <span class="compliance-badge">✅ {{ compliance.status }}</span></p>
            </div>
            
            <div class="scanner-info">
                <h3>🔧 Scanner Information</h3>
                <p><strong>Primary Scanner:</strong> {{ scanner_used.split(',')[0] if scanner_used else 'Unknown' }}</p>
                <p><strong>All Scanners:</strong> {{ scanner_used }}</p>
                <p><strong>Scan Date:</strong> {{ analysis_date }}</p>
            </div>
            
            <h2>📊 Summary</h2>
            <div class="summary-card">
                <p><strong>Total Components:</strong> {{ summary.total_components }}</p>
                <p><strong>Total Vulnerabilities:</strong> {{ summary.total_vulnerabilities }}</p>
                <p><strong>Critical:</strong> {{ summary.critical_vulnerabilities }}</p>
                <p><strong>High:</strong> {{ summary.high_vulnerabilities }}</p>
                <p><strong>Medium:</strong> {{ summary.medium_vulnerabilities }}</p>
                <p><strong>Low:</strong> {{ summary.low_vulnerabilities }}</p>
                <p><strong>Unknown:</strong> {{ summary.unknown_vulnerabilities }}</p>
            </div>
            
            <h2>🧩 Components Analysis</h2>
            {% for component in components %}
            <div class="component">
                <h3>📦 {{ component.name }} @ {{ component.version }}</h3>
                
                <div class="certin-field"><strong>Description:</strong> {{ component.description }}</div>
                <div class="certin-field"><strong>Supplier:</strong> {{ component.supplier }}</div>
                <div class="certin-field"><strong>Unique Identifier:</strong> <code>{{ component.unique_identifier }}</code></div>
                
                <!-- Enhanced License Information for 100% Compliance -->
                <div class="license-details">
                    <h4>📄 License Information</h4>
                    <div class="certin-field"><strong>License:</strong> {{ component.license.name if component.license else 'Unknown' }}</div>
                    <div class="certin-field"><strong>License ID:</strong> {{ component.license.id if component.license else 'Unknown' }}</div>
                    {% if component.license.terms %}
                    <div class="certin-field"><strong>License Terms:</strong> {{ component.license.terms }}</div>
                    {% endif %}
                    {% if component.license.restrictions %}
                    <div class="certin-field"><strong>License Restrictions:</strong> {{ component.license.restrictions }}</div>
                    {% endif %}
                    {% if component.license.url %}
                    <div class="certin-field"><strong>License URL:</strong> <a href="{{ component.license.url }}" target="_blank">{{ component.license.url }}</a></div>
                    {% endif %}
                </div>
                
                <div class="certin-field"><strong>Origin:</strong> {{ component.origin }}</div>
                <div class="certin-field"><strong>Criticality:</strong> {{ component.criticality }}</div>
                <div class="certin-field"><strong>Release Date:</strong> {{ component.release_date }}</div>
                <div class="certin-field"><strong>EOL Date:</strong> {{ component.eol_date }}</div>
                <div class="certin-field"><strong>Usage Restrictions:</strong> {{ component.usage_restrictions }}</div>
                <div class="certin-field"><strong>Comments:</strong> {{ component.comments }}</div>
                <div class="certin-field"><strong>Executable:</strong> {{ component.executable_property }}</div>
                <div class="certin-field"><strong>Archive:</strong> {{ component.archive_property }}</div>
                <div class="certin-field"><strong>Structured:</strong> {{ component.structured_property }}</div>
                <div class="certin-field"><strong>Patch Status:</strong> {{ component.patch_status }}</div>
                <div class="certin-field"><strong>Timestamp:</strong> {{ component.timestamp }}</div>
                
                <!-- Dependencies -->
                {% if component.dependencies %}
                <div class="certin-field">
                    <strong>Dependencies:</strong>
                    <ul class="dependency-list">
                        {% for dep in component.dependencies %}
                        <li>{{ dep }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
                
                {% if component.hashes %}
                <div class="certin-field">
                    <strong>Hashes:</strong>
                    {% for alg, content in component.hashes.items() %}
                    <div class="hash-value">{{ alg }}: {{ content }}</div>
                    {% endfor %}
                </div>
                {% endif %}
                
                {% if component_vulnerabilities[component.unique_identifier] %}
                <h4>🛡️ Vulnerabilities ({{ component_vulnerabilities[component.unique_identifier]|length }})</h4>
                {% for vuln in component_vulnerabilities[component.unique_identifier] %}
                <div class="vulnerability {{ vuln.severity|lower }}">
                    <strong>{{ vuln.cve_id }} ({{ vuln.severity }}) - CVSS: {{ vuln.cvss_score }}</strong><br>
                    {{ vuln.description }}<br>
                    <small>Fixed in: {{ vuln.fixed_versions|join(', ') if vuln.fixed_versions else 'No fix available' }}</small><br>
                    <small>Status: {{ vuln.vex_status }}</small><br>
                    <small>Scanner: {{ vuln.scanner if vuln.scanner else 'Unknown' }}</small>
                </div>
                {% endfor %}
                {% else %}
                <p>✅ No known vulnerabilities</p>
                {% endif %}
            </div>
            {% endfor %}
            
            <h2>📋 Vulnerability Summary</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability {{ vuln.severity|lower }}">
                <strong>{{ vuln.cve_id }} ({{ vuln.severity }})</strong><br>
                <strong>Component:</strong> {{ vuln.component_name }} {{ vuln.component_version }}<br>
                <strong>CVSS Score:</strong> {{ vuln.cvss_score }}<br>
                <strong>Description:</strong> {{ vuln.description }}<br>
                <strong>Fixed Versions:</strong> {{ vuln.fixed_versions|join(', ') if vuln.fixed_versions else 'None' }}<br>
                <strong>VEX Status:</strong> {{ vuln.vex_status }}<br>
                <strong>Scanner:</strong> {{ vuln.scanner if vuln.scanner else 'Unknown' }}
            </div>
            {% endfor %}
        </body>
        </html>
        """
    
    def _component_to_dict(self, component):
        """Convert SBOMComponent to dictionary for JSON serialization"""
        return {
            'name': component.name,
            'version': component.version,
            'description': component.description,
            'supplier': component.supplier,
            'license': component.license,
            'origin': component.origin,
            'dependencies': component.dependencies,
            'hashes': component.hashes,
            'purl': component.purl,
            'type': component.type,
            'release_date': component.release_date,
            'eol_date': component.eol_date,
            'criticality': component.criticality,
            'usage_restrictions': component.usage_restrictions,
            'comments': component.comments,
            'executable_property': component.executable_property,
            'archive_property': component.archive_property,
            'structured_property': component.structured_property,
            'unique_identifier': component.unique_identifier,
            'timestamp': component.timestamp,
            'patch_status': component.patch_status
        }
    
    def _vuln_to_dict(self, vulnerability):
        """Convert Vulnerability to dictionary for JSON serialization"""
        return {
            'cve_id': vulnerability.cve_id,
            'severity': vulnerability.severity,
            'description': vulnerability.description,
            'cvss_score': vulnerability.cvss_score,
            'fixed_versions': vulnerability.fixed_versions,
            'component_name': vulnerability.component_name,
            'component_version': vulnerability.component_version,
            'vex_status': vulnerability.vex_status,
            'scanner': getattr(vulnerability, 'scanner', 'Unknown')
        }
    
    def _generate_summary(self, analysis):
        """Generate summary statistics for the report"""
        severity_breakdown = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Unknown': 0
        }
        
        for vuln in analysis.vulnerabilities:
            severity = vuln.severity.capitalize()
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1
            else:
                severity_breakdown['Unknown'] += 1
        
        return {
            'total_components': len(analysis.components),
            'total_vulnerabilities': len(analysis.vulnerabilities),
            'critical_vulnerabilities': severity_breakdown['Critical'],
            'high_vulnerabilities': severity_breakdown['High'],
            'medium_vulnerabilities': severity_breakdown['Medium'],
            'low_vulnerabilities': severity_breakdown['Low'],
            'unknown_vulnerabilities': severity_breakdown['Unknown'],
            'severity_breakdown': severity_breakdown
        }
    
    def _generate_certin_compliance(self, analysis):
        """Generate CERT-In compliance assessment"""
        # Check if all required fields are present
        required_fields = [
            'name', 'version', 'description', 'supplier', 'license', 
            'origin', 'dependencies', 'release_date', 'eol_date',
            'criticality', 'usage_restrictions', 'hashes', 'comments',
            'timestamp', 'executable_property', 'archive_property',
            'structured_property', 'unique_identifier', 'patch_status'
        ]
        
        compliance_stats = {
            'total_components': len(analysis.components),
            'compliant_components': 0,
            'missing_fields': {}
        }
        
        for component in analysis.components:
            comp_dict = self._component_to_dict(component)
            missing = []
            
            for field in required_fields:
                if not comp_dict.get(field):
                    missing.append(field)
            
            if not missing:
                compliance_stats['compliant_components'] += 1
            
            for field in missing:
                compliance_stats['missing_fields'][field] = compliance_stats['missing_fields'].get(field, 0) + 1
        
        compliance_stats['compliance_percentage'] = round(
            (compliance_stats['compliant_components'] / compliance_stats['total_components'] * 100) 
            if compliance_stats['total_components'] > 0 else 100, 2
        )
        
        status = 'FULLY_COMPLIANT' if compliance_stats['compliance_percentage'] == 100 else 'PARTIALLY_COMPLIANT'
        
        return {
            'status': status,
            'coverage': f"{compliance_stats['compliance_percentage']}%",
            'compliant_components': compliance_stats['compliant_components'],
            'total_components': compliance_stats['total_components'],
            'missing_fields': compliance_stats['missing_fields'],
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
