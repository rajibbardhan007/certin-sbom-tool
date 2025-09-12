import csv
from datetime import datetime
import requests
import os
import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class CERTInEnricher:
    def __init__(self, mapping_csv=None):
        self.mapping_data = {}
        self.known_licenses = self.load_known_licenses()
        if mapping_csv and os.path.exists(mapping_csv):
            self.load_mapping_data(mapping_csv)
        else:
            logger.warning(f"Mapping file {mapping_csv} not found, using default values")
    
    def load_known_licenses(self):
        """Load a comprehensive list of known licenses with terms and restrictions"""
        return {
            'Apache-2.0': {
                'name': 'Apache License 2.0',
                'url': 'https://www.apache.org/licenses/LICENSE-2.0',
                'terms': 'Permissive commercial license, allows modification, distribution, and sublicensing',
                'restrictions': 'Must include copyright notice, state changes, no trademark use without permission'
            },
            'MIT': {
                'name': 'MIT License',
                'url': 'https://opensource.org/licenses/MIT',
                'terms': 'Very permissive license, allows commercial use, modification, distribution',
                'restrictions': 'Must include original copyright and license notice'
            },
            'GPL-2.0': {
                'name': 'GNU General Public License v2.0',
                'url': 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html',
                'terms': 'Copyleft license, requires source code disclosure for distributed modifications',
                'restrictions': 'Derivative works must be licensed under GPL-2.0'
            },
            'GPL-3.0': {
                'name': 'GNU General Public License v3.0',
                'url': 'https://www.gnu.org/licenses/gpl-3.0.en.html',
                'terms': 'Copyleft license with patent provisions and additional user freedoms',
                'restrictions': 'Derivative works must be licensed under GPL-3.0'
            },
            'BSD-3-Clause': {
                'name': 'BSD 3-Clause License',
                'url': 'https://opensource.org/licenses/BSD-3-Clause',
                'terms': 'Permissive license with attribution requirement',
                'restrictions': 'Must include copyright notice, disclaimer, and cannot use contributors names for endorsement'
            },
            'BSD-2-Clause': {
                'name': 'BSD 2-Clause License',
                'url': 'https://opensource.org/licenses/BSD-2-Clause',
                'terms': 'Permissive license with simplified attribution requirement',
                'restrictions': 'Must include copyright notice and disclaimer'
            },
            'LGPL-2.1': {
                'name': 'GNU Lesser General Public License v2.1',
                'url': 'https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html',
                'terms': 'Copyleft license for libraries, allows linking with proprietary software',
                'restrictions': 'Modifications to library must be licensed under LGPL'
            },
            'LGPL-3.0': {
                'name': 'GNU Lesser General Public License v3.0',
                'url': 'https://www.gnu.org/licenses/lgpl-3.0.en.html',
                'terms': 'Copyleft license for libraries with additional protections',
                'restrictions': 'Modifications to library must be licensed under LGPL'
            },
            'MPL-2.0': {
                'name': 'Mozilla Public License 2.0',
                'url': 'https://www.mozilla.org/en-US/MPL/2.0/',
                'terms': 'Weak copyleft license, allows combining with proprietary code',
                'restrictions': 'Modifications to MPL-licensed files must remain under MPL'
            },
            'EPL-2.0': {
                'name': 'Eclipse Public License 2.0',
                'url': 'https://www.eclipse.org/legal/epl-2.0/',
                'terms': 'Weak copyleft license commonly used for Eclipse projects',
                'restrictions': 'Modifications must be disclosed, patent grants included'
            },
            'AGPL-3.0': {
                'name': 'GNU Affero General Public License v3.0',
                'url': 'https://www.gnu.org/licenses/agpl-3.0.en.html',
                'terms': 'Strong copyleft requiring source disclosure for network services',
                'restrictions': 'Derivative works must be licensed under AGPL, source must be available to users'
            }
        }
    
    def load_mapping_data(self, csv_file):
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    key = f"{row['name']}@{row['version']}"
                    self.mapping_data[key] = row
            logger.info(f"Loaded {len(self.mapping_data)} component mappings")
        except Exception as e:
            logger.error(f"Error loading mapping file: {e}")
    
    def enrich_components(self, components, vulnerabilities=None):
        """Enrich all components with CERT-In metadata"""
        enriched_components = []
        
        for component in components:
            enriched = self.enrich_component(component, vulnerabilities)
            enriched_components.append(enriched)
        
        return enriched_components
    
    def enrich_component(self, component, vulnerabilities=None):
        """Enrich a single component with CERT-In metadata"""
        enriched = component.copy()
        
        # Add automated fields
        enriched['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Generate unique identifier if not present
        if not enriched.get('unique_identifier'):
            enriched['unique_identifier'] = self.generate_unique_identifier(component)
        
        # Get from mapping data
        map_key = f"{component.get('name', '')}@{component.get('version', '')}"
        if map_key in self.mapping_data:
            mapping = self.mapping_data[map_key]
            
            # Enhanced enrichment with all CERT-In fields
            enrichment_data = {
                'description': mapping.get('description', component.get('description', '')),
                'supplier': mapping.get('supplier', component.get('supplier', '')),
                'license': {
                    'id': mapping.get('license_name', ''),
                    'name': mapping.get('license_name', ''),
                    'url': mapping.get('license_url', ''),
                    'terms': mapping.get('license_terms', ''),
                    'restrictions': mapping.get('license_restrictions', '')
                } if mapping.get('license_name') else component.get('license', {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}),
                'release_date': mapping.get('release_date', ''),
                'eol_date': mapping.get('eol_date', ''),
                'criticality': mapping.get('criticality', 'Medium'),
                'usage_restrictions': mapping.get('usage_restrictions', ''),
                'comments': mapping.get('comments', ''),
                'executable_property': mapping.get('executable', 'No'),
                'archive_property': mapping.get('archive', 'No'),
                'structured_property': mapping.get('structured', ''),
                'patch_status': mapping.get('patch_status', 'Unknown'),
                'origin': mapping.get('origin', 'Unknown'),
                'dependencies': self.parse_dependencies(mapping.get('dependencies', ''))
            }
            
            # Update the enriched data
            enriched.update(enrichment_data)
        else:
            # Apply defaults with educated guesses
            default_data = {
                'description': component.get('description', ''),
                'supplier': component.get('supplier', ''),
                'license': component.get('license', {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}),
                'release_date': '',
                'eol_date': '',
                'criticality': 'Medium',
                'usage_restrictions': '',
                'comments': '',
                'executable_property': 'No',
                'archive_property': 'No',
                'structured_property': '',
                'patch_status': 'Unknown',
                'origin': 'Unknown',
                'dependencies': component.get('dependencies', [])
            }
            
            # Update the enriched data
            enriched.update(default_data)
        
        # Enhance license information
        enriched = self.enhance_license_info(enriched)
        
        # Add component-specific vulnerabilities
        if vulnerabilities:
            comp_vulns = [v for v in vulnerabilities 
                         if v.get('component_name') == component.get('name') 
                         and v.get('component_version') == component.get('version')]
            enriched['vulnerabilities'] = comp_vulns
            enriched['patch_status'] = self.determine_patch_status(comp_vulns)
        
        # Calculate hashes if missing
        if not enriched.get('hashes'):
            enriched['hashes'] = self.calculate_hashes(component)
        
        # Try to fetch EOL date if missing
        if not enriched.get('eol_date'):
            enriched['eol_date'] = self.fetch_eol_date(
                enriched.get('name', ''), 
                enriched.get('version', '')
            )
        
        # Try to fetch release date if missing
        if not enriched.get('release_date'):
            enriched['release_date'] = self.fetch_release_date(
                enriched.get('name', ''), 
                enriched.get('version', '')
            )
        
        # Filter out any extra fields that SBOMComponent doesn't expect
        return self.filter_component_fields(enriched)
    
    def filter_component_fields(self, component_data):
        """Filter component data to only include valid SBOMComponent fields"""
        valid_fields = {
            'name', 'version', 'description', 'supplier', 'license', 
            'dependencies', 'hashes', 'purl', 'type', 'release_date',
            'eol_date', 'criticality', 'usage_restrictions', 'comments',
            'executable_property', 'archive_property', 'structured_property',
            'unique_identifier', 'timestamp', 'origin', 'patch_status'
        }
        
        return {k: v for k, v in component_data.items() if k in valid_fields}
    
    def generate_unique_identifier(self, component: Dict) -> str:
        """Generate CERT-In compliant unique identifier"""
        purl = component.get('purl', '')
        if purl:
            return purl
        
        # Construct identifier from available data
        name = component.get('name', 'unknown')
        version = component.get('version', 'unknown')
        supplier = component.get('supplier', 'unknown')
        
        # Use supplier as namespace if available
        namespace = self.normalize_namespace(supplier) if supplier else 'unknown'
        
        return f"pkg:supplier/{namespace}/{name}@{version}"
    
    def normalize_namespace(self, namespace: str) -> str:
        """Normalize namespace for unique identifier"""
        return re.sub(r'[^a-zA-Z0-9]', '', namespace.lower())
    
    def fuzzy_match_component(self, component_name: str) -> Dict:
        """Fuzzy match component by name (ignoring version)"""
        name_lower = component_name.lower()
        for key in self.mapping_data.keys():
            map_name = key.split('@')[0].lower()
            if map_name in name_lower or name_lower in map_name:
                return self.mapping_data[key]
        return None
    
    def enhance_license_info(self, component: Dict) -> Dict:
        """Enhance license information with known license data"""
        license_id = component.get('license', {}).get('id', '')
        
        if license_id and license_id in self.known_licenses:
            known_license = self.known_licenses[license_id]
            component['license'] = {
                'id': license_id,
                'name': known_license['name'],
                'url': known_license['url'],
                'terms': component.get('license', {}).get('terms', '') or known_license['terms'],
                'restrictions': component.get('license', {}).get('restrictions', '') or known_license['restrictions']
            }
        
        return component
    
    def parse_dependencies(self, dependencies_str: str) -> List[str]:
        """Parse dependencies string into list"""
        if not dependencies_str:
            return []
        return [dep.strip() for dep in dependencies_str.split(',') if dep.strip()]
    
    def determine_patch_status(self, vulnerabilities: List[Dict]) -> str:
        """Determine patch status based on vulnerabilities"""
        if not vulnerabilities:
            return "No known vulnerabilities"
        
        # Check if any vulnerabilities have fixes available
        has_fixes = any(vuln.get('fixed_versions') for vuln in vulnerabilities)
        if has_fixes:
            return "Patch available"
        
        # Check for high severity vulnerabilities
        high_severity = any(vuln.get('severity') in ['Critical', 'High'] for vuln in vulnerabilities)
        if high_severity:
            return "Requires immediate attention"
        
        return "Under investigation"
    
    def calculate_hashes(self, component: Dict) -> Dict[str, str]:
        """Calculate hashes for component if not provided"""
        # In a real implementation, this would calculate hashes of the actual component files
        # For now, return empty as this would require access to the actual component files
        return component.get('hashes', {})
    
    def fetch_eol_date(self, component_name: str, version: str) -> str:
        """Fetch EOL date from endoflife.date API"""
        if not component_name or not version:
            return ''
        
        try:
            # Clean component name for API
            clean_name = component_name.lower().replace(' ', '-')
            response = requests.get(
                f"https://endoflife.date/api/{clean_name}/{version}.json",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('eol', '') or ''
        except requests.RequestException:
            pass
        except Exception as e:
            logger.warning(f"Error fetching EOL date for {component_name}: {e}")
        
        return ''
    
    def fetch_release_date(self, component_name: str, version: str) -> str:
        """Fetch release date from various sources"""
        # This would typically query package registries or other APIs
        # For now, return empty as this requires specific implementation
        return ''

# Global enricher instance
enricher = CERTInEnricher('component_mapping.csv')
