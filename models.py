from dataclasses import dataclass, field
from typing import List, Dict, Any
from datetime import datetime

@dataclass
class SBOMComponent:
    name: str = ""
    version: str = ""
    description: str = ""
    supplier: str = ""
    license: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)
    purl: str = ""
    type: str = ""
    release_date: str = ""
    eol_date: str = ""
    criticality: str = "Medium"
    usage_restrictions: str = ""
    comments: str = ""
    executable_property: str = "No"
    archive_property: str = "No"
    structured_property: str = ""
    unique_identifier: str = ""
    timestamp: str = ""
    origin: str = "Unknown"
    patch_status: str = "Unknown"
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return {field: getattr(self, field, "") for field in [
            'name', 'version', 'description', 'supplier', 'license', 'dependencies',
            'hashes', 'purl', 'type', 'release_date', 'eol_date', 'criticality',
            'usage_restrictions', 'comments', 'executable_property', 'archive_property',
            'structured_property', 'unique_identifier', 'timestamp', 'origin', 'patch_status'
        ]}

@dataclass
class Vulnerability:
    cve_id: str = ""
    severity: str = ""
    description: str = ""
    cvss_score: float = 0.0
    fixed_versions: List[str] = field(default_factory=list)
    component_name: str = ""
    component_version: str = ""
    vex_status: str = "Under Investigation"
    scanner: str = "Unknown"
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return {field: getattr(self, field, "") for field in [
            'cve_id', 'severity', 'description', 'cvss_score', 'fixed_versions',
            'component_name', 'component_version', 'vex_status', 'scanner'
        ]}

@dataclass
class SBOMAnalysis:
    file_id: str = ""
    original_format: str = ""
    components: List[SBOMComponent] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    analysis_date: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    scanner_used: str = "Unknown"
    
    def __init__(self, **kwargs):
        # Initialize default values
        self.file_id = kwargs.get('file_id', "")
        self.original_format = kwargs.get('original_format', "")
        self.components = kwargs.get('components', [])
        self.vulnerabilities = kwargs.get('vulnerabilities', [])
        self.analysis_date = kwargs.get('analysis_date', "")
        self.metadata = kwargs.get('metadata', {})
        self.scanner_used = kwargs.get('scanner_used', "Unknown")
    
    def to_dict(self):
        return {
            'file_id': self.file_id,
            'original_format': self.original_format,
            'components': [comp.to_dict() for comp in self.components],
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'analysis_date': self.analysis_date,
            'metadata': self.metadata,
            'scanner_used': self.scanner_used
        }
