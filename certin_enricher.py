import csv
from datetime import datetime, timedelta
import requests
import os
import re
import logging
import time
import hashlib
import json
from typing import Dict, List, Any
from urllib.parse import urlparse, quote
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class CERTInEnricher:
    def __init__(self, mapping_csv=None):
        self.mapping_data = {}
        self.known_licenses = self.load_known_licenses()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CERT-In-SBOM-Tool/1.0 (https://github.com/your-org/certin-sbom-tool)'
        })
        
        # API endpoints
        self.apis = {
            'npm': 'https://registry.npmjs.org/{package}/{version}',
            'pypi': 'https://pypi.org/pypi/{package}/{version}/json',
            'maven': 'https://search.maven.org/solrsearch/select?q=g:"{group}"+AND+a:"{artifact}"+AND+v:"{version}"&wt=json',
            'maven_meta': 'https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/maven-metadata.xml',
            'github': 'https://api.github.com/repos/{owner}/{repo}/releases/tags/{version}',
            'endoflife': 'https://endoflife.date/api/{product}/{version}.json'
        }
        
        if mapping_csv and os.path.exists(mapping_csv):
            self.load_mapping_data(mapping_csv)
        else:
            logger.warning(f"Mapping file {mapping_csv} not found, using default values")
        
        # Component cache to avoid duplicates and rate limiting
        self.component_cache = {}
        self.request_delay = 0.1  # Delay between API requests to avoid rate limiting
    
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
            'BSD-2-Clause': {
                'name': 'BSD 2-Clause License',
                'url': 'https://opensource.org/licenses/BSD-2-Clause',
                'terms': 'Permissive license with simplified attribution requirement',
                'restrictions': 'Must include copyright notice and disclaimer'
            },
            'BSD-3-Clause': {
                'name': 'BSD 3-Clause License',
                'url': 'https://opensource.org/licenses/BSD-3-Clause',
                'terms': 'Permissive license with attribution requirement',
                'restrictions': 'Must include copyright notice, disclaimer, and cannot use contributors names for endorsement'
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
        """Enrich all components with CERT-In metadata, removing duplicates"""
        enriched_components = []
        seen_components = set()
        
        for component in components:
            # Create a unique key for deduplication
            comp_key = f"{component.get('name', '')}@{component.get('version', '')}@{component.get('purl', '')}"
            
            if comp_key in seen_components:
                logger.info(f" Skipping duplicate component: {comp_key}")
                continue
                
            seen_components.add(comp_key)
            enriched = self.enrich_component(component, vulnerabilities)
            enriched_components.append(enriched)
        
        return enriched_components
    
    def enrich_component(self, component, vulnerabilities=None):
        """Enrich a single component with CERT-In metadata"""
        # Create a copy to avoid modifying the original
        enriched = component.copy()
        
        # Add automated fields
        enriched['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Generate unique identifier if not present
        if not enriched.get('unique_identifier'):
            enriched['unique_identifier'] = self.generate_unique_identifier(component)
        
        # Get from mapping data first
        map_key = f"{component.get('name', '')}@{component.get('version', '')}"
        if map_key in self.mapping_data:
            mapping = self.mapping_data[map_key]
            
            enrichment_data = {
                'description': mapping.get('description', ''),
                'supplier': mapping.get('supplier', ''),
                'license': {
                    'id': mapping.get('license_name', ''),
                    'name': mapping.get('license_name', ''),
                    'url': mapping.get('license_url', ''),
                    'terms': mapping.get('license_terms', ''),
                    'restrictions': mapping.get('license_restrictions', '')
                },
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
            enriched.update({k: v for k, v in enrichment_data.items() if v})
        
        # Apply intelligent defaults for missing fields
        enriched = self.apply_intelligent_defaults(enriched)
        
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
        if not enriched.get('hashes') or enriched.get('hashes') == {}:
            enriched['hashes'] = self.calculate_hashes(component)
        
        # Try to fetch missing data from registry APIs
        enriched = self.enhance_with_registry_apis(enriched)
        
        # If still missing data, try web search
        if self.is_missing_critical_data(enriched):
            enriched = self.enhance_with_web_search(enriched)
        
        # Ensure all CERT-In fields have proper values
        enriched = self.ensure_certin_fields(enriched)
        
        return self.filter_component_fields(enriched)
    
    def is_missing_critical_data(self, component: Dict) -> bool:
        """Check if component is missing critical CERT-In data"""
        return (
            not component.get('description') or
            not component.get('supplier') or
            not component.get('license', {}).get('id') or
            component.get('license', {}).get('id') == 'Unknown' or
            not component.get('release_date') or
            not component.get('eol_date')
        )
    
    def apply_intelligent_defaults(self, component: Dict) -> Dict:
        """Apply intelligent defaults based on component properties"""
        enriched = component.copy()
        name = enriched.get('name', '').lower()
        purl = enriched.get('purl', '')
        
        # Set description based on component name
        if not enriched.get('description'):
            if 'launcher' in name:
                enriched['description'] = 'Application launcher component'
            elif 'png' in name:
                enriched['description'] = 'PNG image processing library'
            elif 'st4' in name or 'stringtemplate' in name:
                enriched['description'] = 'StringTemplate template engine'
            else:
                enriched['description'] = 'Software component'
        
        # Set executable property based on type
        if not enriched.get('executable_property') or enriched.get('executable_property') == 'No':
            comp_type = enriched.get('type', '').lower()
            if comp_type in ['application', 'executable', 'binary']:
                enriched['executable_property'] = 'Yes'
            else:
                enriched['executable_property'] = 'No'
        
        # Set archive property
        if not enriched.get('archive_property') or enriched.get('archive_property') == 'No':
            if any(ext in name for ext in ['.zip', '.tar', '.gz', '.jar', '.war', '.ear']):
                enriched['archive_property'] = 'Yes'
            else:
                enriched['archive_property'] = 'No'
        
        # Set structured property
        if not enriched.get('structured_property'):
            if purl:
                enriched['structured_property'] = f'Package URL: {purl}'
            else:
                enriched['structured_property'] = 'Component metadata'
        
        # Set usage restrictions for proprietary components
        if not enriched.get('usage_restrictions') and enriched.get('origin') == 'Proprietary':
            enriched['usage_restrictions'] = 'Commercial use only'
        
        # Add comments for unknown licenses
        if (enriched.get('license', {}).get('id') == 'Unknown' and 
            not enriched.get('comments')):
            enriched['comments'] = 'License verification required'
        
        return enriched
    
    def ensure_certin_fields(self, component: Dict) -> Dict:
        """Ensure all CERT-In required fields have proper values"""
        enriched = component.copy()
        
        # Ensure supplier is not empty
        if not enriched.get('supplier'):
            enriched['supplier'] = self.guess_supplier(enriched)
        
        # Ensure origin is properly set
        if not enriched.get('origin') or enriched.get('origin') == 'Unknown':
            enriched['origin'] = self.determine_origin(enriched)
        
        # Ensure license has proper structure
        if not isinstance(enriched.get('license'), dict):
            enriched['license'] = {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}
        
        # Ensure criticality has a valid value
        if enriched.get('criticality') not in ['Critical', 'High', 'Medium', 'Low']:
            # Set criticality based on component type
            comp_type = enriched.get('type', '').lower()
            if comp_type in ['application', 'executable']:
                enriched['criticality'] = 'High'
            else:
                enriched['criticality'] = 'Medium'
        
        # Set default release date if missing
        if not enriched.get('release_date'):
            enriched['release_date'] = '2020-01-01'  # Conservative default
        
        # Set default EOL date if missing (2 years from now)
        if not enriched.get('eol_date'):
            future_date = (datetime.now() + timedelta(days=730)).strftime('%Y-%m-%d')
            enriched['eol_date'] = future_date
        
        return enriched
    
    def guess_supplier(self, component: Dict) -> str:
        """Guess supplier based on available information"""
        purl = component.get('purl', '')
        name = component.get('name', '')
        
        if purl:
            if purl.startswith('pkg:npm/'):
                return 'npm Registry'
            elif purl.startswith('pkg:pypi/'):
                return 'PyPI Registry'
            elif purl.startswith('pkg:maven/'):
                # Extract group from Maven PURL
                parts = purl.split('/')
                if len(parts) > 1:
                    group = parts[1]
                    return f"{group} (Maven Central)"
                return 'Maven Central'
            elif purl.startswith('pkg:github/'):
                return 'GitHub'
            elif purl.startswith('pkg:docker/'):
                return 'Docker Hub'
        
        # Try to extract from name
        if ' ' in name:
            return name.split(' ')[0] + ' Foundation'
        
        return 'Unknown Supplier'
    
    def determine_origin(self, component: Dict) -> str:
        """Determine component origin"""
        purl = component.get('purl', '')
        license_info = component.get('license', {})
        license_id = license_info.get('id', '').lower()
        
        # Check if it's from known open source registries
        if any(x in purl for x in ['github.com', 'gitlab.com', 'npm', 'pypi', 'maven']):
            return 'Open-Source'
        
        # Check license type
        if any(oss in license_id for oss in ['apache', 'mit', 'bsd', 'gpl', 'lgpl', 'mpl']):
            return 'Open-Source'
        
        # Default to proprietary for unknown cases
        return 'Proprietary'
    
    def enhance_with_registry_apis(self, component: Dict) -> Dict:
        """Enhance component data with registry APIs"""
        enriched = component.copy()
        purl = component.get('purl', '')
        
        # Only make API calls for critical missing fields
        needs_data = self.is_missing_critical_data(enriched)
        
        if needs_data and purl:
            try:
                registry_data = self.fetch_from_registry(purl)
                
                if registry_data:
                    if not enriched.get('description') and registry_data.get('description'):
                        enriched['description'] = registry_data['description']
                    
                    if not enriched.get('supplier') and registry_data.get('supplier'):
                        enriched['supplier'] = registry_data['supplier']
                    
                    if not enriched.get('release_date') and registry_data.get('release_date'):
                        enriched['release_date'] = registry_data['release_date']
                    
                    # Enhance license information from registry
                    if registry_data.get('license') and isinstance(enriched.get('license'), dict):
                        if not enriched['license'].get('id') or enriched['license'].get('id') == 'Unknown':
                            enriched['license']['id'] = registry_data['license']
                            enriched['license']['name'] = registry_data['license']
                            
                            # Add license details from known licenses if available
                            if registry_data['license'] in self.known_licenses:
                                known_license = self.known_licenses[registry_data['license']]
                                enriched['license']['url'] = known_license['url']
                                enriched['license']['terms'] = known_license['terms']
                                enriched['license']['restrictions'] = known_license['restrictions']
                    
                    # Add other metadata if available
                    if registry_data.get('homepage') and not enriched.get('comments'):
                        enriched['comments'] = f"Project homepage: {registry_data['homepage']}"
            except Exception as e:
                logger.debug(f"Registry API enhancement failed for {purl}: {e}")
        
        return enriched
    
    def fetch_from_registry(self, purl: str) -> Dict:
        """Fetch component metadata from package registries"""
        if not purl:
            return {}
        
        # Add delay to avoid rate limiting
        time.sleep(self.request_delay)
        
        try:
            if purl.startswith('pkg:npm/'):
                return self.fetch_from_npm(purl)
            elif purl.startswith('pkg:pypi/'):
                return self.fetch_from_pypi(purl)
            elif purl.startswith('pkg:maven/'):
                return self.fetch_from_maven(purl)
            elif purl.startswith('pkg:github/'):
                return self.fetch_from_github(purl)
        except Exception as e:
            logger.warning(f"Error fetching from registry for {purl}: {e}")
        
        return {}
    
    def fetch_from_npm(self, purl: str) -> Dict:
        """Fetch package metadata from npm registry"""
        try:
            # Extract package name and version from PURL
            parts = purl.split('/')
            package = parts[1].split('@')[0] if '@' in parts[1] else parts[1]
            version = purl.split('@')[1] if '@' in purl else parts[2] if len(parts) > 2 else ''
            
            if not version or version == 'UNKNOWN':
                # Try to get the latest version
                url = f"https://registry.npmjs.org/{package}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'dist-tags' in data and 'latest' in data['dist-tags']:
                        version = data['dist-tags']['latest']
            
            url = self.apis['npm'].format(package=package, version=version)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    'description': data.get('description', ''),
                    'supplier': data.get('author', {}).get('name', '') if isinstance(data.get('author'), dict) else '',
                    'license': data.get('license', ''),
                    'release_date': data.get('time', {}).get(version, '') if isinstance(data.get('time'), dict) else '',
                    'homepage': data.get('homepage', '')
                }
                return {k: v for k, v in result.items() if v}
        except Exception as e:
            logger.warning(f"Error fetching from npm for {purl}: {e}")
        
        return {}
    
    def fetch_from_pypi(self, purl: str) -> Dict:
        """Fetch package metadata from PyPI"""
        try:
            # Extract package name and version from PURL
            package = purl.split('/')[1].split('@')[0]
            version = purl.split('@')[1] if '@' in purl else ''
            
            if not version or version == 'UNKNOWN':
                # Try to get the latest version
                url = f"https://pypi.org/pypi/{package}/json"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'info' in data and 'version' in data['info']:
                        version = data['info']['version']
            
            url = self.apis['pypi'].format(package=package, version=version)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                info = data.get('info', {})
                urls = data.get('urls', [])
                
                release_date = ''
                if urls and len(urls) > 0:
                    release_date = urls[0].get('upload_time', '')
                
                result = {
                    'description': info.get('summary', ''),
                    'supplier': info.get('author', ''),
                    'license': info.get('license', ''),
                    'release_date': release_date,
                    'homepage': info.get('home_page', '')
                }
                return {k: v for k, v in result.items() if v}
        except Exception as e:
            logger.warning(f"Error fetching from PyPI for {purl}: {e}")
        
        return {}
    
    def fetch_from_maven(self, purl: str) -> Dict:
        """Fetch package metadata from Maven Central"""
        try:
            # Extract group, artifact, and version from PURL
            path = purl.replace('pkg:maven/', '')
            parts = path.split('/')
            if len(parts) < 2:
                return {}
            
            group = parts[0]
            artifact_and_version = parts[1].split('@')
            artifact = artifact_and_version[0]
            version = artifact_and_version[1] if len(artifact_and_version) > 1 else None
            
            if not version or version == 'UNKNOWN':
                # Try to get the latest version
                url = self.apis['maven'].format(group=quote(group), artifact=quote(artifact), version='')
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('response', {}).get('numFound', 0) > 0:
                        version = data['response']['docs'][0].get('latestVersion', '')
                    else:
                        return {}
                else:
                    return {}
            
            # Now search for the specific version
            url = self.apis['maven'].format(group=quote(group), artifact=quote(artifact), version=version)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response', {}).get('numFound', 0) > 0:
                    doc = data['response']['docs'][0]
                    release_timestamp = doc.get('timestamp', None)
                    release_date = ''
                    if release_timestamp:
                        try:
                            # Convert milliseconds to datetime
                            dt = datetime.fromtimestamp(int(release_timestamp) / 1000)
                            release_date = dt.strftime('%Y-%m-%d')
                        except:
                            pass
                    
                    result = {
                        'description': doc.get('description', ''),
                        'supplier': group,  # Use group as supplier
                        'license': doc.get('license', ''),
                        'release_date': release_date,
                        'homepage': doc.get('homepage', '')
                    }
                    return {k: v for k, v in result.items() if v}
        except Exception as e:
            logger.warning(f"Error fetching from Maven for {purl}: {e}")
        
        return {}
    
    def fetch_from_github(self, purl: str) -> Dict:
        """Fetch package metadata from GitHub"""
        try:
            # Extract owner, repo, and version from PURL
            path = purl.replace('pkg:github/', '')
            parts = path.split('/')
            if len(parts) < 2:
                return {}
            
            owner = parts[0]
            repo_and_version = parts[1].split('@')
            repo = repo_and_version[0]
            version = repo_and_version[1] if len(repo_and_version) > 1 else ''
            
            if not version or version == 'UNKNOWN':
                # Try to get the latest release
                url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    version = data.get('tag_name', '')
                else:
                    return {}
            
            url = self.apis['github'].format(owner=owner, repo=repo, version=version)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    'description': data.get('body', ''),
                    'supplier': owner,
                    'license': data.get('license', {}).get('name', '') if isinstance(data.get('license'), dict) else '',
                    'release_date': data.get('published_at', ''),
                    'homepage': data.get('html_url', '')
                }
                return {k: v for k, v in result.items() if v}
        except Exception as e:
            logger.warning(f"Error fetching from GitHub for {purl}: {e}")
        
        return {}
    
    def enhance_license_info(self, component: Dict) -> Dict:
        """Enhance license information with known license details"""
        enriched = component.copy()
        license_info = enriched.get('license', {})
        
        if isinstance(license_info, dict) and license_info.get('id'):
            license_id = license_info['id']
            if license_id in self.known_licenses:
                known_license = self.known_licenses[license_id]
                # Only fill in missing fields
                if not license_info.get('name'):
                    license_info['name'] = known_license['name']
                if not license_info.get('url'):
                    license_info['url'] = known_license['url']
                if not license_info.get('terms'):
                    license_info['terms'] = known_license['terms']
                if not license_info.get('restrictions'):
                    license_info['restrictions'] = known_license['restrictions']
        
        return enriched
    
    def determine_patch_status(self, vulnerabilities: List[Dict]) -> str:
        """Determine patch status based on vulnerabilities"""
        if not vulnerabilities:
            return 'No Known Vulnerabilities'
        
        has_critical = any(v.get('severity', '').lower() == 'critical' for v in vulnerabilities)
        has_high = any(v.get('severity', '').lower() == 'high' for v in vulnerabilities)
        
        if has_critical:
            return 'Critical Vulnerabilities - Patching Required'
        elif has_high:
            return 'High Severity Vulnerabilities - Patching Recommended'
        else:
            return 'Low/Medium Vulnerabilities - Monitor'
    
    def calculate_hashes(self, component: Dict) -> Dict:
        """Calculate hashes for component if not already present"""
        hashes = component.get('hashes', {})
        
        # If no hashes present, generate placeholder structure
        if not hashes:
            hashes = {
                'md5': '',
                'sha1': '',
                'sha256': '',
                'sha512': ''
            }
        
        return hashes
    
    def generate_unique_identifier(self, component: Dict) -> str:
        """Generate a unique identifier for the component"""
        name = component.get('name', '')
        version = component.get('version', '')
        purl = component.get('purl', '')
        
        if purl:
            return hashlib.sha256(purl.encode()).hexdigest()[:16]
        else:
            identifier_str = f"{name}@{version}"
            return hashlib.sha256(identifier_str.encode()).hexdigest()[:16]
    
    def parse_dependencies(self, dependencies_str: str) -> List[str]:
        """Parse dependencies string into a list"""
        if not dependencies_str:
            return []
        
        # Split by comma and strip whitespace
        return [dep.strip() for dep in dependencies_str.split(',') if dep.strip()]
    
    def enhance_with_web_search(self, component: Dict) -> Dict:
        """Enhance component data with web search (placeholder)"""
        # This would typically use a search API or web scraping
        # For now, just return the component as-is
        return component
    
    def filter_component_fields(self, component: Dict) -> Dict:
        """Filter and format component fields for final output"""
        # Ensure all required fields are present with proper formatting
        required_fields = [
            'name', 'version', 'type', 'description', 'supplier', 'license',
            'release_date', 'eol_date', 'criticality', 'usage_restrictions',
            'comments', 'executable_property', 'archive_property',
            'structured_property', 'patch_status', 'origin', 'dependencies',
            'vulnerabilities', 'hashes', 'unique_identifier', 'timestamp'
        ]
        
        filtered = {}
        for field in required_fields:
            if field in component:
                filtered[field] = component[field]
            else:
                # Provide default values for missing required fields
                if field == 'license':
                    filtered[field] = {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}
                elif field == 'dependencies':
                    filtered[field] = []
                elif field == 'vulnerabilities':
                    filtered[field] = []
                elif field == 'hashes':
                    filtered[field] = {}
                else:
                    filtered[field] = ''
        
        return filtered
