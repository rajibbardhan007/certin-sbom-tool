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
            'metadata': analysis.metadata or {},
            'certin_requirements_coverage': self._generate_certin_coverage_report(analysis)
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
        compliance = self._generate_certin_compliance(analysis)
        coverage = self._generate_certin_coverage_report(analysis)
        
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
            compliance=compliance,
            coverage=coverage
        )
    
    def generate_csaf_report(self, analysis):
        """Generate CSAF/VEX compliant report with CERT-In metadata"""
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
                },
                # Add CERT-In specific metadata
                "certin_metadata": {
                    "compliance_level": "FULL" if self._is_fully_compliant(analysis) else "PARTIAL",
                    "required_fields_coverage": self._generate_certin_coverage_report(analysis),
                    "report_generated_date": datetime.utcnow().isoformat() + "Z"
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
            "vulnerabilities": [],
            # Add CERT-In specific extension for component metadata
            "certin_components_metadata": self._generate_certin_components_metadata(analysis)
        }
        
        # Add products to product tree with enhanced metadata
        for component in analysis.components:
            product_branch = {
                "name": f"{component.name} {component.version}",
                "category": "product_version",
                "product": {
                    "name": component.name,
                    "version": component.version,
                    "purl": getattr(component, 'unique_identifier', ''),
                    # Add CERT-In specific fields
                    "certin_metadata": {
                        "supplier": getattr(component, 'supplier', 'Unknown'),
                        "origin": getattr(component, 'origin', 'Unknown'),
                        "criticality": getattr(component, 'criticality', 'Medium'),
                        "license": getattr(component, 'license', {}),
                        "release_date": getattr(component, 'release_date', ''),
                        "eol_date": getattr(component, 'eol_date', ''),
                        "patch_status": getattr(component, 'patch_status', 'Unknown')
                    }
                }
            }
            csaf["product_tree"]["branches"][0]["branches"].append(product_branch)
        
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
                ],
                # Add CERT-In specific vulnerability metadata
                "certin_metadata": {
                    "component_origin": self._get_component_origin(analysis, vuln.component_name, vuln.component_version),
                    "patch_status": self._get_component_patch_status(analysis, vuln.component_name, vuln.component_version),
                    "criticality": self._get_component_criticality(analysis, vuln.component_name, vuln.component_version)
                }
            })
        
        return json.dumps(csaf, indent=2)
    
    def _generate_certin_components_metadata(self, analysis):
        """Generate detailed CERT-In metadata for all components"""
        components_metadata = {}
        
        for component in analysis.components:
            comp_key = f"{component.name}@{component.version}"
            components_metadata[comp_key] = {
                "name": component.name,
                "version": component.version,
                "supplier": getattr(component, 'supplier', 'Unknown'),
                "description": getattr(component, 'description', ''),
                "origin": getattr(component, 'origin', 'Unknown'),
                "criticality": getattr(component, 'criticality', 'Medium'),
                "license": getattr(component, 'license', {}),
                "release_date": getattr(component, 'release_date', ''),
                "eol_date": getattr(component, 'eol_date', ''),
                "patch_status": getattr(component, 'patch_status', 'Unknown'),
                "usage_restrictions": getattr(component, 'usage_restrictions', ''),
                "comments": getattr(component, 'comments', ''),
                "executable_property": getattr(component, 'executable_property', 'No'),
                "archive_property": getattr(component, 'archive_property', 'No'),
                "structured_property": getattr(component, 'structured_property', ''),
                "unique_identifier": getattr(component, 'unique_identifier', ''),
                "timestamp": getattr(component, 'timestamp', ''),
                "dependencies": getattr(component, 'dependencies', []),
                "hashes": getattr(component, 'hashes', {})
            }
        
        return components_metadata
    
    def _get_component_origin(self, analysis, component_name, component_version):
        """Get origin for a specific component"""
        for component in analysis.components:
            if component.name == component_name and component.version == component_version:
                return getattr(component, 'origin', 'Unknown')
        return 'Unknown'
    
    def _get_component_patch_status(self, analysis, component_name, component_version):
        """Get patch status for a specific component"""
        for component in analysis.components:
            if component.name == component_name and component.version == component_version:
                return getattr(component, 'patch_status', 'Unknown')
        return 'Unknown'
    
    def _get_component_criticality(self, analysis, component_name, component_version):
        """Get criticality for a specific component"""
        for component in analysis.components:
            if component.name == component_name and component.version == component_version:
                return getattr(component, 'criticality', 'Medium')
        return 'Medium'
    
    def _is_fully_compliant(self, analysis):
        """Check if analysis is fully CERT-In compliant"""
        compliance = self._generate_certin_compliance(analysis)
        return compliance['status'] == 'FULLY_COMPLIANT'
    
    def _generate_certin_coverage_report(self, analysis):
        """Generate detailed CERT-In requirements coverage report"""
        certin_requirements = [
            {'id': 'CN', 'name': 'Component Name', 'required': True, 'automation': 'auto'},
            {'id': 'CV', 'name': 'Component Version', 'required': True, 'automation': 'auto'},
            {'id': 'CD', 'name': 'Component Description', 'required': True, 'automation': 'semi'},
            {'id': 'CS', 'name': 'Component Supplier', 'required': True, 'automation': 'semi'},
            {'id': 'CL', 'name': 'Component License', 'required': True, 'automation': 'semi'},
            {'id': 'CO', 'name': 'Component Origin', 'required': True, 'automation': 'manual'},
            {'id': 'CDEP', 'name': 'Component Dependencies', 'required': True, 'automation': 'auto'},
            {'id': 'VULN', 'name': 'Vulnerabilities', 'required': True, 'automation': 'auto'},
            {'id': 'PSTAT', 'name': 'Patch Status', 'required': True, 'automation': 'manual'},
            {'id': 'RDATE', 'name': 'Release Date', 'required': True, 'automation': 'semi'},
            {'id': 'EOL', 'name': 'End-of-Life Date', 'required': True, 'automation': 'semi'},
            {'id': 'CRIT', 'name': 'Criticality', 'required': True, 'automation': 'manual'},
            {'id': 'UREST', 'name': 'Usage Restrictions', 'required': True, 'automation': 'manual'},
            {'id': 'CHKSUM', 'name': 'Checksums/Hashes', 'required': True, 'automation': 'auto'},
            {'id': 'COMM', 'name': 'Comments/Notes', 'required': False, 'automation': 'manual'},
            {'id': 'TS', 'name': 'Timestamp', 'required': True, 'automation': 'auto'},
            {'id': 'EXEC', 'name': 'Executable Property', 'required': True, 'automation': 'manual'},
            {'id': 'ARCH', 'name': 'Archive Property', 'required': True, 'automation': 'manual'},
            {'id': 'STRUCT', 'name': 'Structured Property', 'required': True, 'automation': 'manual'},
            {'id': 'UID', 'name': 'Unique Identifier', 'required': True, 'automation': 'semi'}
        ]
        
        coverage_stats = {
            'total_requirements': len(certin_requirements),
            'covered_requirements': 0,
            'coverage_percentage': 0,
            'requirements': []
        }
        
        # Sample a few components to check coverage
        sample_components = analysis.components[:min(5, len(analysis.components))] if analysis.components else []
        
        for req in certin_requirements:
            req_coverage = self._check_requirement_coverage(req, sample_components)
            coverage_stats['requirements'].append({
                'id': req['id'],
                'name': req['name'],
                'required': req['required'],
                'automation': req['automation'],
                'coverage': req_coverage
            })
            
            if req_coverage['percentage'] >= 80:  # Consider covered if 80%+ components have this field
                coverage_stats['covered_requirements'] += 1
        
        coverage_stats['coverage_percentage'] = round(
            (coverage_stats['covered_requirements'] / coverage_stats['total_requirements'] * 100)
            if coverage_stats['total_requirements'] > 0 else 100, 2
        )
        
        return coverage_stats
    
    def _check_requirement_coverage(self, requirement, components):
        """Check coverage for a specific requirement"""
        if not components:
            return {'percentage': 0, 'covered': 0, 'total': 0}
        
        covered = 0
        field_name = self._get_field_name_for_requirement(requirement['id'])
        
        for component in components:
            comp_dict = self._component_to_dict(component)
            if comp_dict.get(field_name) not in [None, '', 'Unknown', '{}', '[]', {}, []]:
                covered += 1
        
        percentage = round((covered / len(components)) * 100, 2)
        
        return {
            'percentage': percentage,
            'covered': covered,
            'total': len(components),
            'status': 'COMPLETE' if percentage >= 80 else 'PARTIAL' if percentage >= 20 else 'MISSING'
        }
    
    def _get_field_name_for_requirement(self, requirement_id):
        """Map requirement ID to component field name"""
        mapping = {
            'CN': 'name',
            'CV': 'version',
            'CD': 'description',
            'CS': 'supplier',
            'CL': 'license',
            'CO': 'origin',
            'CDEP': 'dependencies',
            'VULN': 'vulnerabilities',
            'PSTAT': 'patch_status',
            'RDATE': 'release_date',
            'EOL': 'eol_date',
            'CRIT': 'criticality',
            'UREST': 'usage_restrictions',
            'CHKSUM': 'hashes',
            'COMM': 'comments',
            'TS': 'timestamp',
            'EXEC': 'executable_property',
            'ARCH': 'archive_property',
            'STRUCT': 'structured_property',
            'UID': 'unique_identifier'
        }
        return mapping.get(requirement_id, '')
    
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
            
            # Add CERT-In compliance info
            compliance = self._generate_certin_compliance(analysis)
            pdf.cell(200, 10, txt=f"CERT-In Compliance: {compliance['coverage']}", ln=1)
            pdf.cell(200, 10, txt=f"Status: {compliance['status']}", ln=1)
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
                f.write(f"CERT-In Compliance: {self._generate_certin_compliance(analysis)['coverage']}\n")
    
    def _component_to_dict(self, component):
        """Convert SBOMComponent to dictionary for JSON serialization"""
        return {
            'name': getattr(component, 'name', ''),
            'version': getattr(component, 'version', ''),
            'description': getattr(component, 'description', ''),
            'supplier': getattr(component, 'supplier', ''),
            'license': getattr(component, 'license', {}),
            'origin': getattr(component, 'origin', 'Unknown'),
            'dependencies': getattr(component, 'dependencies', []),
            'hashes': getattr(component, 'hashes', {}),
            'purl': getattr(component, 'purl', ''),
            'type': getattr(component, 'type', ''),
            'release_date': getattr(component, 'release_date', ''),
            'eol_date': getattr(component, 'eol_date', ''),
            'criticality': getattr(component, 'criticality', 'Medium'),
            'usage_restrictions': getattr(component, 'usage_restrictions', ''),
            'comments': getattr(component, 'comments', ''),
            'executable_property': getattr(component, 'executable_property', 'No'),
            'archive_property': getattr(component, 'archive_property', 'No'),
            'structured_property': getattr(component, 'structured_property', ''),
            'unique_identifier': getattr(component, 'unique_identifier', ''),
            'timestamp': getattr(component, 'timestamp', ''),
            'patch_status': getattr(component, 'patch_status', 'Unknown')
        }
    
    def _vuln_to_dict(self, vulnerability):
        """Convert Vulnerability to dictionary for JSON serialization"""
        return {
            'cve_id': getattr(vulnerability, 'cve_id', ''),
            'severity': getattr(vulnerability, 'severity', ''),
            'description': getattr(vulnerability, 'description', ''),
            'cvss_score': getattr(vulnerability, 'cvss_score', 0.0),
            'fixed_versions': getattr(vulnerability, 'fixed_versions', []),
            'component_name': getattr(vulnerability, 'component_name', ''),
            'component_version': getattr(vulnerability, 'component_version', ''),
            'vex_status': getattr(vulnerability, 'vex_status', 'Under Investigation'),
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
            severity = getattr(vuln, 'severity', 'Unknown').capitalize()
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
    
    def _get_default_html_template(self):
        """Default HTML template for reports"""
        # [Keep your existing HTML template code here]
        # This should be the same as your original _get_default_html_template method
        return """<!DOCTYPE html><html>...</html>"""
