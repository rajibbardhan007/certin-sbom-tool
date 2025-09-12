import sqlite3
import json
from datetime import datetime
import logging
import traceback

logger = logging.getLogger(__name__)

class SBOMDatabase:
    def __init__(self, db_path='sbom_analysis.db'):
        self.db_path = db_path
        self.init_db()
        self.update_db_schema()
    
    def update_db_schema(self):
        """Update database schema to add missing columns"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check and update components table
            cursor.execute("PRAGMA table_info(components)")
            component_columns = [column[1] for column in cursor.fetchall()]
            
            missing_component_columns = [
                ('origin', 'TEXT'),
                ('patch_status', 'TEXT'),
                ('criticality', 'TEXT'),
                ('usage_restrictions', 'TEXT'),
                ('comments', 'TEXT'),
                ('executable_property', 'TEXT'),
                ('archive_property', 'TEXT'),
                ('structured_property', 'TEXT'),
                ('unique_identifier', 'TEXT'),
                ('timestamp', 'TEXT'),
                ('release_date', 'TEXT'),
                ('eol_date', 'TEXT')
            ]
            
            for column_name, column_type in missing_component_columns:
                if column_name not in component_columns:
                    cursor.execute(f'ALTER TABLE components ADD COLUMN {column_name} {column_type}')
                    logger.info(f"✅ Added {column_name} column to components table")
            
            # Check and update analyses table
            cursor.execute("PRAGMA table_info(sbom_analyses)")
            analysis_columns = [column[1] for column in cursor.fetchall()]
            
            if 'metadata' not in analysis_columns:
                cursor.execute('ALTER TABLE sbom_analyses ADD COLUMN metadata TEXT')
                logger.info("✅ Added metadata column to sbom_analyses table")
            
            if 'scanner_used' not in analysis_columns:
                cursor.execute('ALTER TABLE sbom_analyses ADD COLUMN scanner_used TEXT')
                logger.info("✅ Added scanner_used column to sbom_analyses table")
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error updating database schema: {e}")
            logger.error(traceback.format_exc())
            conn.rollback()
        finally:
            conn.close()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create analyses table
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
        
        # Create components table with ALL required CERT-In fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
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
                FOREIGN KEY (analysis_id) REFERENCES sbom_analyses (id) ON DELETE CASCADE
            )
        ''')
        
        # Create vulnerabilities table
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
                FOREIGN KEY (analysis_id) REFERENCES sbom_analyses (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def save_analysis(self, analysis):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Safely access analysis attributes with detailed logging
            file_id = getattr(analysis, 'file_id', '')
            original_format = getattr(analysis, 'original_format', '')
            analysis_date = getattr(analysis, 'analysis_date', '')
            metadata = getattr(analysis, 'metadata', {})
            scanner_used = getattr(analysis, 'scanner_used', 'Unknown')
            components = getattr(analysis, 'components', [])
            vulnerabilities = getattr(analysis, 'vulnerabilities', [])
            
            logger.info(f"💾 Starting to save analysis {file_id} with {len(components)} components and {len(vulnerabilities)} vulnerabilities")
            
            # Save analysis metadata
            cursor.execute('''
                INSERT OR REPLACE INTO sbom_analyses (file_id, original_format, analysis_date, metadata, scanner_used)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                file_id, 
                original_format, 
                analysis_date, 
                json.dumps(metadata) if metadata else '{}',
                scanner_used
            ))
            
            analysis_id = cursor.lastrowid
            
            # Save components with detailed error handling
            for i, component in enumerate(components):
                try:
                    # Get all attributes with safe defaults
                    comp_data = {
                        'name': getattr(component, 'name', f'unknown_{i}'),
                        'version': getattr(component, 'version', 'unknown'),
                        'description': getattr(component, 'description', ''),
                        'supplier': getattr(component, 'supplier', ''),
                        'license': getattr(component, 'license', {}),
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
                        'unique_identifier': getattr(component, 'unique_identifier', f'pkg:unknown/unknown/unknown_{i}@unknown'),
                        'timestamp': getattr(component, 'timestamp', ''),
                        'origin': getattr(component, 'origin', 'Unknown'),
                        'patch_status': getattr(component, 'patch_status', 'Unknown')
                    }
                    
                    cursor.execute('''
                        INSERT INTO components (
                            analysis_id, name, version, description, supplier, license,
                            dependencies, hashes, purl, type, release_date, eol_date,
                            criticality, usage_restrictions, comments, executable_property,
                            archive_property, structured_property, unique_identifier, timestamp,
                            origin, patch_status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        analysis_id, 
                        comp_data['name'],
                        comp_data['version'],
                        comp_data['description'],
                        comp_data['supplier'],
                        json.dumps(comp_data['license']) if comp_data['license'] else '{}',
                        json.dumps(comp_data['dependencies']) if comp_data['dependencies'] else '[]',
                        json.dumps(comp_data['hashes']) if comp_data['hashes'] else '{}',
                        comp_data['purl'],
                        comp_data['type'],
                        comp_data['release_date'],
                        comp_data['eol_date'],
                        comp_data['criticality'],
                        comp_data['usage_restrictions'],
                        comp_data['comments'],
                        comp_data['executable_property'],
                        comp_data['archive_property'],
                        comp_data['structured_property'],
                        comp_data['unique_identifier'],
                        comp_data['timestamp'],
                        comp_data['origin'],
                        comp_data['patch_status']
                    ))
                    
                except Exception as comp_error:
                    logger.error(f"❌ Error saving component {i}: {comp_error}")
                    logger.error(f"Component data: {comp_data}")
                    logger.error(traceback.format_exc())
                    continue
            
            # Save vulnerabilities
            for vuln in vulnerabilities:
                try:
                    vuln_data = {
                        'cve_id': getattr(vuln, 'cve_id', ''),
                        'severity': getattr(vuln, 'severity', 'Unknown'),
                        'description': getattr(vuln, 'description', ''),
                        'cvss_score': float(getattr(vuln, 'cvss_score', 0.0)),
                        'fixed_versions': getattr(vuln, 'fixed_versions', []),
                        'component_name': getattr(vuln, 'component_name', ''),
                        'component_version': getattr(vuln, 'component_version', ''),
                        'vex_status': getattr(vuln, 'vex_status', 'Under Investigation'),
                        'scanner': getattr(vuln, 'scanner', 'Unknown')
                    }
                    
                    cursor.execute('''
                        INSERT INTO vulnerabilities (
                            analysis_id, cve_id, severity, description, cvss_score,
                            fixed_versions, component_name, component_version, vex_status, scanner
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        analysis_id, 
                        vuln_data['cve_id'],
                        vuln_data['severity'],
                        vuln_data['description'],
                        vuln_data['cvss_score'],
                        json.dumps(vuln_data['fixed_versions']),
                        vuln_data['component_name'],
                        vuln_data['component_version'],
                        vuln_data['vex_status'],
                        vuln_data['scanner']
                    ))
                    
                except Exception as vuln_error:
                    logger.error(f"❌ Error saving vulnerability: {vuln_error}")
                    logger.error(f"Vulnerability data: {vuln_data}")
                    logger.error(traceback.format_exc())
                    continue
            
            conn.commit()
            logger.info(f"✅ Analysis {file_id} successfully saved to database")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"❌ Critical error saving analysis to database: {e}")
            logger.error(traceback.format_exc())
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
                logger.warning(f"Analysis {file_id} not found in database")
                return None
            
            cursor.execute('SELECT * FROM components WHERE analysis_id = ?', (analysis_row['id'],))
            component_rows = cursor.fetchall()
            components = []
            for row in component_rows:
                try:
                    components.append({
                        'name': row['name'], 'version': row['version'], 'description': row['description'],
                        'supplier': row['supplier'], 
                        'license': json.loads(row['license']) if row['license'] and row['license'] != '{}' else {},
                        'dependencies': json.loads(row['dependencies']) if row['dependencies'] and row['dependencies'] != '[]' else [],
                        'hashes': json.loads(row['hashes']) if row['hashes'] and row['hashes'] != '{}' else {},
                        'purl': row['purl'], 'type': row['type'], 'release_date': row['release_date'], 
                        'eol_date': row['eol_date'], 'criticality': row['criticality'], 
                        'usage_restrictions': row['usage_restrictions'], 'comments': row['comments'],
                        'executable_property': row['executable_property'], 'archive_property': row['archive_property'],
                        'structured_property': row['structured_property'], 'unique_identifier': row['unique_identifier'],
                        'timestamp': row['timestamp'], 'origin': row['origin'], 'patch_status': row['patch_status']
                    })
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error for component {row['name']}: {e}")
                    continue
            
            cursor.execute('SELECT * FROM vulnerabilities WHERE analysis_id = ?', (analysis_row['id'],))
            vuln_rows = cursor.fetchall()
            vulnerabilities = []
            for row in vuln_rows:
                try:
                    vulnerabilities.append({
                        'cve_id': row['cve_id'], 'severity': row['severity'], 'description': row['description'],
                        'cvss_score': row['cvss_score'], 
                        'fixed_versions': json.loads(row['fixed_versions']) if row['fixed_versions'] and row['fixed_versions'] != '[]' else [],
                        'component_name': row['component_name'], 'component_version': row['component_version'],
                        'vex_status': row['vex_status'], 'scanner': row['scanner']
                    })
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error for vulnerability {row['cve_id']}: {e}")
                    continue
            
            analysis = {
                'file_id': analysis_row['file_id'],
                'original_format': analysis_row['original_format'],
                'components': components,
                'vulnerabilities': vulnerabilities,
                'analysis_date': analysis_row['analysis_date'],
                'metadata': json.loads(analysis_row['metadata']) if analysis_row['metadata'] and analysis_row['metadata'] != '{}' else {},
                'scanner_used': analysis_row['scanner_used']
            }
            
            logger.info(f"✅ Successfully retrieved analysis {file_id} from database")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Error retrieving analysis {file_id}: {e}")
            logger.error(traceback.format_exc())
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
            logger.error(traceback.format_exc())
            return []
        finally:
            conn.close()

    def delete_analysis(self, file_id):
        """Delete an analysis from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM sbom_analyses WHERE file_id = ?', (file_id,))
            conn.commit()
            logger.info(f"Deleted analysis {file_id} from database")
            return True
        except Exception as e:
            logger.error(f"Error deleting analysis {file_id}: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
