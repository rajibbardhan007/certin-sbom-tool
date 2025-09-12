import json
import xml.etree.ElementTree as ET
from datetime import datetime
import hashlib
import os
import logging

logger = logging.getLogger(__name__)

def parse_sbom(file_path):
    try:
        if file_path.endswith('.json'):
            return parse_json_sbom(file_path)
        elif file_path.endswith('.xml'):
            return parse_xml_sbom(file_path)
        else:
            raise ValueError("Unsupported file format. Please upload JSON or XML.")
    except Exception as e:
        logger.error(f"Error parsing SBOM file: {e}")
        raise ValueError(f"Failed to parse SBOM file: {str(e)}")

def parse_json_sbom(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
            return parse_cyclonedx_json(data, file_path)
        elif 'spdxVersion' in data:
            return parse_spdx_json(data, file_path)
        else:
            # Try to detect format by structure
            if 'components' in data:
                return parse_cyclonedx_json(data, file_path)
            elif 'packages' in data:
                return parse_spdx_json(data, file_path)
            else:
                raise ValueError("Unknown JSON SBOM format")
    except Exception as e:
        logger.error(f"Error parsing JSON SBOM: {e}")
        raise

def parse_cyclonedx_json(data, file_path):
    try:
        components = []
        
        for component in data.get('components', []):
            # Extract CERT-In properties from component properties
            properties = extract_properties(component.get('properties', []))
            
            comp_data = {
                'name': component.get('name', ''),
                'version': component.get('version', ''),
                'description': component.get('description', ''),
                'supplier': component.get('supplier', {}).get('name', '') if isinstance(component.get('supplier'), dict) else component.get('supplier', ''),
                'license': extract_license_info(component),
                'dependencies': extract_dependencies(component, data),
                'hashes': extract_hashes(component),
                'purl': component.get('purl', ''),
                'type': component.get('type', ''),
                # CERT-In specific fields from properties
                'origin': properties.get('certin:origin', ''),
                'patch_status': properties.get('certin:patchStatus', 'Unknown'),
                'release_date': properties.get('certin:releaseDate', ''),
                'eol_date': properties.get('certin:eolDate', ''),
                'criticality': properties.get('certin:criticality', 'Medium'),
                'usage_restrictions': properties.get('certin:usageRestrictions', ''),
                'comments': properties.get('certin:comments', ''),
                'executable_property': properties.get('certin:executableProperty', 'No'),
                'archive_property': properties.get('certin:archiveProperty', 'No'),
                'structured_property': properties.get('certin:structuredProperty', ''),
                'unique_identifier': generate_unique_identifier(component, properties),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            components.append(comp_data)
        
        return {
            'format': 'CycloneDX',
            'components': components,
            'metadata': extract_metadata(data)
        }
    except Exception as e:
        logger.error(f"Error parsing CycloneDX JSON: {e}")
        raise

def parse_spdx_json(data, file_path):
    try:
        components = []
        
        for package in data.get('packages', []):
            # Extract CERT-In properties from package annotations
            properties = extract_spdx_properties(package)
            
            comp_data = {
                'name': package.get('name', ''),
                'version': package.get('versionInfo', ''),
                'description': package.get('description', ''),
                'supplier': extract_spdx_supplier(package),
                'license': extract_spdx_license(package),
                'hashes': extract_spdx_hashes(package),
                'purl': extract_spdx_purl(package),
                'type': package.get('primaryPackagePurpose', ''),
                # CERT-In specific fields
                'origin': properties.get('origin', ''),
                'patch_status': properties.get('patchStatus', 'Unknown'),
                'release_date': properties.get('releaseDate', ''),
                'eol_date': properties.get('eolDate', ''),
                'criticality': properties.get('criticality', 'Medium'),
                'usage_restrictions': properties.get('usageRestrictions', ''),
                'comments': properties.get('comments', ''),
                'executable_property': properties.get('executableProperty', 'No'),
                'archive_property': properties.get('archiveProperty', 'No'),
                'structured_property': properties.get('structuredProperty', ''),
                'unique_identifier': generate_spdx_identifier(package, properties),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'dependencies': extract_spdx_dependencies(package, data)
            }
            components.append(comp_data)
        
        return {
            'format': 'SPDX',
            'components': components,
            'metadata': {
                'created': data.get('creationInfo', {}).get('created', '')
            }
        }
    except Exception as e:
        logger.error(f"Error parsing SPDX JSON: {e}")
        raise

def extract_properties(properties_list):
    """Extract CERT-In properties from CycloneDX properties"""
    certin_properties = {}
    if properties_list and isinstance(properties_list, list):
        for prop in properties_list:
            if isinstance(prop, dict) and prop.get('name', '').startswith('certin:'):
                key = prop['name'].replace('certin:', '')
                certin_properties[key] = prop.get('value', '')
    return certin_properties

def extract_spdx_properties(package):
    """Extract CERT-In properties from SPDX package"""
    properties = {}
    # Check external references for CERT-In properties
    for ref in package.get('externalRefs', []):
        if ref.get('referenceType') == 'certin':
            # Parse certin properties from reference locator
            pass
    return properties

def generate_unique_identifier(component, properties):
    """Generate CERT-In compliant unique identifier"""
    purl = component.get('purl', '')
    if purl:
        return purl
    
    # Fallback: Construct identifier from available data
    name = component.get('name', 'unknown')
    version = component.get('version', 'unknown')
    supplier = properties.get('supplier', 'unknown')
    
    # Use supplier as namespace if available
    namespace = supplier.lower().replace(' ', '') if supplier else 'unknown'
    
    return f"pkg:supplier/{namespace}/{name}@{version}"

def generate_spdx_identifier(package, properties):
    """Generate unique identifier for SPDX components"""
    purl = extract_spdx_purl(package)
    if purl:
        return purl
    
    name = package.get('name', 'unknown')
    version = package.get('versionInfo', 'unknown')
    supplier = extract_spdx_supplier(package)
    namespace = supplier.lower().replace(' ', '') if supplier else 'unknown'
    
    return f"pkg:supplier/{namespace}/{name}@{version}"

def extract_license_info(component):
    licenses = component.get('licenses', [])
    if licenses and isinstance(licenses, list) and len(licenses) > 0:
        license_data = licenses[0].get('license', {})
        if isinstance(license_data, dict):
            return {
                'id': license_data.get('id', ''),
                'name': license_data.get('name', ''),
                'url': license_data.get('url', ''),
                'terms': extract_license_terms(license_data),
                'restrictions': extract_license_restrictions(license_data)
            }
    return {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}

def extract_license_terms(license_data):
    """Extract license terms from license data"""
    if not isinstance(license_data, dict):
        return ""
        
    # This would typically come from a license database
    license_id = license_data.get('id', '').lower()
    if 'apache' in license_id:
        return "Permissive commercial license, allows modification, distribution, and sublicensing"
    elif 'mit' in license_id:
        return "Very permissive license, allows commercial use, modification, distribution"
    elif 'gpl' in license_id:
        return "Copyleft license, requires source code disclosure for distributed modifications"
    return "License terms not specified"

def extract_license_restrictions(license_data):
    """Extract license restrictions from license data"""
    if not isinstance(license_data, dict):
        return ""
        
    license_id = license_data.get('id', '').lower()
    if 'apache' in license_id:
        return "Must include copyright notice, state changes, no trademark use without permission"
    elif 'mit' in license_id:
        return "Must include original copyright and license notice"
    elif 'gpl' in license_id:
        return "Derivative works must be licensed under same terms"
    return "No specific restrictions identified"

def extract_hashes(component):
    hashes = {}
    for hash_obj in component.get('hashes', []):
        if isinstance(hash_obj, dict):
            hashes[hash_obj.get('alg', '')] = hash_obj.get('content', '')
    return hashes

def extract_dependencies(component, data):
    dependencies = []
    component_ref = component.get('bom-ref', '')
    
    for dependency in data.get('dependencies', []):
        if isinstance(dependency, dict) and dependency.get('ref') == component_ref:
            for dep_ref in dependency.get('dependsOn', []):
                # Find the dependent component
                for comp in data.get('components', []):
                    if isinstance(comp, dict) and comp.get('bom-ref') == dep_ref:
                        dependencies.append(f"{comp.get('name', '')}@{comp.get('version', '')}")
                        break
            break
    
    return dependencies

def extract_metadata(data):
    metadata = data.get('metadata', {})
    if not isinstance(metadata, dict):
        metadata = {}
        
    return {
        'timestamp': metadata.get('timestamp', ''),
        'tools': [tool.get('name', '') for tool in metadata.get('tools', []) if isinstance(tool, dict)]
    }

def extract_spdx_supplier(package):
    supplier = package.get('supplier', '')
    if supplier:
        return supplier
    originator = package.get('originator', '')
    if originator:
        return originator
    return 'Unknown'

def extract_spdx_license(package):
    license_declared = package.get('licenseDeclared', '')
    if license_declared:
        return {
            'id': license_declared, 
            'name': license_declared, 
            'url': '',
            'terms': extract_license_terms({'id': license_declared}),
            'restrictions': extract_license_restrictions({'id': license_declared})
        }
    return {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}

def extract_spdx_hashes(package):
    hashes = {}
    for checksum in package.get('checksums', []):
        if isinstance(checksum, dict):
            hashes[checksum.get('algorithm', '')] = checksum.get('checksumValue', '')
    return hashes

def extract_spdx_purl(package):
    external_refs = package.get('externalRefs', [])
    for ref in external_refs:
        if isinstance(ref, dict) and ref.get('referenceType') == 'purl':
            return ref.get('referenceLocator', '')
    return ''

def extract_spdx_dependencies(package, data):
    """Extract dependencies from SPDX relationships"""
    dependencies = []
    package_id = package.get('SPDXID', '')
    
    for relationship in data.get('relationships', []):
        if (isinstance(relationship, dict) and 
            relationship.get('relationshipType') == 'DEPENDS_ON' and 
            relationship.get('spdxElementId') == package_id):
            related_id = relationship.get('relatedSpdxElement', '')
            # Find the related package
            for pkg in data.get('packages', []):
                if isinstance(pkg, dict) and pkg.get('SPDXID') == related_id:
                    dependencies.append(f"{pkg.get('name', '')}@{pkg.get('versionInfo', '')}")
                    break
    
    return dependencies

# XML parsing functions
def parse_xml_sbom(file_path):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        if 'cyclonedx' in root.tag:
            return parse_cyclonedx_xml(root, file_path)
        else:
            raise ValueError("Unsupported XML SBOM format")
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
        raise ValueError("Invalid XML file")
    except Exception as e:
        logger.error(f"Error parsing XML SBOM: {e}")
        raise

def parse_cyclonedx_xml(root, file_path):
    try:
        components = []
        ns = {'cdx': 'http://cyclonedx.org/schema/bom/1.4'}
        
        for comp_elem in root.findall('.//cdx:component', ns):
            # Extract properties
            properties = extract_xml_properties(comp_elem, ns)
            
            comp_data = {
                'name': comp_elem.findtext('cdx:name', '', ns) or '',
                'version': comp_elem.findtext('cdx:version', '', ns) or '',
                'description': comp_elem.findtext('cdx:description', '', ns) or '',
                'supplier': comp_elem.findtext('cdx:supplier/cdx:name', '', ns) or '',
                'license': extract_xml_license(comp_elem, ns),
                'hashes': extract_xml_hashes(comp_elem, ns),
                'purl': comp_elem.findtext('cdx:purl', '', ns) or '',
                'type': comp_elem.get('type', ''),
                # CERT-In specific fields
                'origin': properties.get('origin', ''),
                'patch_status': properties.get('patchStatus', 'Unknown'),
                'release_date': properties.get('releaseDate', ''),
                'eol_date': properties.get('eolDate', ''),
                'criticality': properties.get('criticality', 'Medium'),
                'usage_restrictions': properties.get('usageRestrictions', ''),
                'comments': properties.get('comments', ''),
                'executable_property': properties.get('executableProperty', 'No'),
                'archive_property': properties.get('archiveProperty', 'No'),
                'structured_property': properties.get('structuredProperty', ''),
                'unique_identifier': generate_xml_identifier(comp_elem, properties, ns),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'dependencies': extract_xml_dependencies(comp_elem, root, ns)
            }
            components.append(comp_data)
        
        return {
            'format': 'CycloneDX',
            'components': components,
            'metadata': {}
        }
    except Exception as e:
        logger.error(f"Error parsing CycloneDX XML: {e}")
        raise

def extract_xml_properties(comp_elem, ns):
    """Extract properties from XML component"""
    properties = {}
    for prop_elem in comp_elem.findall('cdx:properties/cdx:property', ns):
        name = prop_elem.findtext('cdx:name', '', ns)
        value = prop_elem.findtext('cdx:value', '', ns)
        if name and name.startswith('certin:'):
            key = name.replace('certin:', '')
            properties[key] = value
    return properties

def extract_xml_license(comp_elem, ns):
    license_elem = comp_elem.find('cdx:licenses/cdx:license', ns)
    if license_elem is not None:
        license_id = license_elem.findtext('cdx:id', '', ns) or ''
        license_name = license_elem.findtext('cdx:name', '', ns) or ''
        return {
            'id': license_id,
            'name': license_name,
            'url': license_elem.findtext('cdx:url', '', ns) or '',
            'terms': extract_license_terms({'id': license_id}),
            'restrictions': extract_license_restrictions({'id': license_id})
        }
    return {'id': 'Unknown', 'name': 'Unknown', 'url': '', 'terms': '', 'restrictions': ''}

def extract_xml_hashes(comp_elem, ns):
    hashes = {}
    for hash_elem in comp_elem.findall('cdx:hashes/cdx:hash', ns):
        alg = hash_elem.get('alg', '')
        content = hash_elem.text or ''
        if alg and content:
            hashes[alg] = content
    return hashes

def generate_xml_identifier(comp_elem, properties, ns):
    """Generate unique identifier for XML components"""
    purl = comp_elem.findtext('cdx:purl', '', ns) or ''
    if purl:
        return purl
    
    name = comp_elem.findtext('cdx:name', '', ns) or 'unknown'
    version = comp_elem.findtext('cdx:version', '', ns) or 'unknown'
    supplier = comp_elem.findtext('cdx:supplier/cdx:name', '', ns) or properties.get('supplier', 'unknown')
    namespace = supplier.lower().replace(' ', '') if supplier else 'unknown'
    
    return f"pkg:supplier/{namespace}/{name}@{version}"

def extract_xml_dependencies(comp_elem, root, ns):
    """Extract dependencies from XML"""
    dependencies = []
    comp_ref = comp_elem.get('bom-ref', '')
    
    for dep_elem in root.findall('.//cdx:dependency', ns):
        if dep_elem.get('ref') == comp_ref:
            for dep_ref_elem in dep_elem.findall('cdx:dependency', ns):
                dep_ref = dep_ref_elem.get('ref', '')
                # Find the component with this ref
                for comp in root.findall('.//cdx:component', ns):
                    if comp.get('bom-ref') == dep_ref:
                        name = comp.findtext('cdx:name', '', ns) or ''
                        version = comp.findtext('cdx:version', '', ns) or ''
                        dependencies.append(f"{name}@{version}")
                        break
            break
    
    return dependencies
