import sqlite3
import json
from datetime import datetime
from models import SBOMComponent, Vulnerability, SBOMAnalysis
import logging

logger = logging.getLogger(__name__)

class SBOMDatabase:
    def __init__(self, db_path='sbom_analysis.db'):
        self.db_path = db_path
        self.init_db()
        self.update_db_schema()  # Add schema update check
    
    def update_db_schema(self):
        """Update database schema to add missing columns"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if scanner_used column exists
            cursor.execute("PRAGMA table_info(sbom_analyses)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'scanner_used' not in columns:
                cursor.execute('ALTER TABLE sbom_analyses ADD COLUMN scanner_used TEXT')
                logger.info("✅ Added scanner_used column to sbom_analyses table")
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error updating database schema: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sbom_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT UNIQUE,
                original_format TEXT,
                analysis_date TEXT,
                metadata TEXT,
                scanner_used TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                name TEXT,
                version TEXT,
                description TEXT,
                supplier TEXT,
                license TEXT,
                dependencies TEXT,
                hashes TEXT,
                purl TEXT,
                type TEXT,
                release_date TEXT,
                eol_date TEXT,
                criticality TEXT,
                usage_restrictions TEXT,
                comments TEXT,
                executable_property TEXT,
                archive_property TEXT,
                structured_property TEXT,
                unique_identifier TEXT,
                timestamp TEXT,
                origin TEXT,
                patch_status TEXT,
                FOREIGN KEY (analysis_id) REFERENCES sbom_analyses (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                cvss_score REAL,
                fixed_versions TEXT,
                component_name TEXT,
                component_version TEXT,
                vex_status TEXT,
                scanner TEXT,
                FOREIGN KEY (analysis_id) REFERENCES sbom_analyses (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def save_analysis(self, analysis: SBOMAnalysis):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO sbom_analyses (file_id, original_format, analysis_date, metadata, scanner_used)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                analysis.file_id, 
                analysis.original_format, 
                analysis.analysis_date, 
                json.dumps(analysis.metadata) if analysis.metadata else None,
                getattr(analysis, 'scanner_used', 'Unknown')
            ))
            
            analysis_id = cursor.lastrowid
            
            for component in analysis.components:
                cursor.execute('''
                    INSERT INTO components (
                        analysis_id, name, version, description, supplier, license,
                        dependencies, hashes, purl, type, release_date, eol_date,
                        criticality, usage_restrictions, comments, executable_property,
                        archive_property, structured_property, unique_identifier, timestamp,
                        origin, patch_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis_id, component.name, component.version, component.description,
                    component.supplier, json.dumps(component.license) if component.license else None,
                    json.dumps(component.dependencies) if component.dependencies else None,
                    json.dumps(component.hashes) if component.hashes else None,
                    component.purl, component.type, component.release_date, component.eol_date,
                    component.criticality, component.usage_restrictions, component.comments,
                    component.executable_property, component.archive_property,
                    component.structured_property, component.unique_identifier,
                    component.timestamp, component.origin, component.patch_status
                ))
            
            for vuln in analysis.vulnerabilities:
                cursor.execute('''
                    INSERT INTO vulnerabilities (
                        analysis_id, cve_id, severity, description, cvss_score,
                        fixed_versions, component_name, component_version, vex_status, scanner
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis_id, vuln.cve_id, vuln.severity, vuln.description,
                    vuln.cvss_score, json.dumps(vuln.fixed_versions),
                    vuln.component_name, vuln.component_version, vuln.vex_status,
                    getattr(vuln, 'scanner', 'Unknown')
                ))
            
            conn.commit()
            logger.info(f"Analysis {analysis.file_id} saved to database")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error saving analysis to database: {e}")
            raise
        finally:
            conn.close()
    
    def get_analysis(self, file_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM sbom_analyses WHERE file_id = ?', (file_id,))
            analysis_row = cursor.fetchone()
            
            if not analysis_row:
                return None
            
            cursor.execute('SELECT * FROM components WHERE analysis_id = ?', (analysis_row['id'],))
            component_rows = cursor.fetchall()
            components = []
            for row in component_rows:
                components.append(SBOMComponent(
                    name=row['name'], version=row['version'], description=row['description'],
                    supplier=row['supplier'], 
                    license=json.loads(row['license']) if row['license'] else None,
                    dependencies=json.loads(row['dependencies']) if row['dependencies'] else None,
                    hashes=json.loads(row['hashes']) if row['hashes'] else None,
                    purl=row['purl'], type=row['type'], release_date=row['release_date'], 
                    eol_date=row['eol_date'], criticality=row['criticality'], 
                    usage_restrictions=row['usage_restrictions'], comments=row['comments'],
                    executable_property=row['executable_property'], archive_property=row['archive_property'],
                    structured_property=row['structured_property'], unique_identifier=row['unique_identifier'],
                    timestamp=row['timestamp'], origin=row['origin'], patch_status=row['patch_status']
                ))
            
            cursor.execute('SELECT * FROM vulnerabilities WHERE analysis_id = ?', (analysis_row['id'],))
            vuln_rows = cursor.fetchall()
            vulnerabilities = []
            for row in vuln_rows:
                vulnerabilities.append(Vulnerability(
                    cve_id=row['cve_id'], severity=row['severity'], description=row['description'],
                    cvss_score=row['cvss_score'], 
                    fixed_versions=json.loads(row['fixed_versions']),
                    component_name=row['component_name'], component_version=row['component_version'],
                    vex_status=row['vex_status'], scanner=row['scanner']
                ))
            
            analysis = SBOMAnalysis(
                file_id=analysis_row['file_id'],
                original_format=analysis_row['original_format'],
                components=components,
                vulnerabilities=vulnerabilities,
                analysis_date=analysis_row['analysis_date'],
                metadata=json.loads(analysis_row['metadata']) if analysis_row['metadata'] else None,
                scanner_used=analysis_row['scanner_used']
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error retrieving analysis {file_id}: {e}")
            return None
        finally:
            conn.close()
    
    def get_all_analyses(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT file_id, original_format, analysis_date, scanner_used FROM sbom_analyses ORDER BY analysis_date DESC')
            analyses = cursor.fetchall()
            
            return [dict(analysis) for analysis in analyses]
            
        except Exception as e:
            logger.error(f"Error retrieving analyses: {e}")
            return []
        finally:
            conn.close()
