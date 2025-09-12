#!/bin/bash

# CERT-In SBOM Tool Installation Script
echo "Installing CERT-In SBOM Compliance Tool dependencies..."

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install flask==2.3.3 requests==2.31.0 jinja2==3.1.2 python-magic==0.4.27 fpdf==1.7.2 weasyprint==58.0

# Install system dependencies for WeasyPrint (if on Ubuntu/Debian)
if command -v apt-get &> /dev/null; then
    echo "Installing system dependencies for WeasyPrint..."
    sudo apt-get update
    sudo apt-get install -y build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
fi

# Install Grype
if ! command -v grype &> /dev/null; then
    echo "Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
else
    echo "Grype is already installed: $(grype --version)"
fi

# Install OWASP Dependency-Check
if ! command -v dependency-check.sh &> /dev/null; then
    echo "Installing OWASP Dependency-Check..."
    # Download the latest version
    LATEST_VERSION=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: $LATEST_VERSION"
    
    # Create temp directory for download
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download and extract
    wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/${LATEST_VERSION}/dependency-check-${LATEST_VERSION:1}-release.zip"
    unzip -q "dependency-check-${LATEST_VERSION:1}-release.zip"
    
    # Move to opt directory and create symlink
    sudo mv dependency-check /opt/
    sudo ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh
    
    # Cleanup
    cd -
    rm -rf "$TEMP_DIR"
    
    echo "Dependency-Check installed to /opt/dependency-check/"
else
    echo "Dependency-Check is already installed: $(dependency-check.sh --version)"
fi

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p static/uploads static/reports templates

# Create sample component mapping file if it doesn't exist
if [ ! -f "component_mapping.csv" ]; then
    echo "Creating sample component_mapping.csv..."
    cat > component_mapping.csv << EOL
name,version,origin,patch_status,release_date,eol_date,criticality,usage_restrictions,comments,executable,archive,structured,license_name,license_url,license_terms,license_restrictions,supplier,dependencies
Apache Tomcat,9.0.71,Open-Source,Patched in 9.0.72,2023-04-12,2026-12-31,Critical,No export outside India,Production web server,Yes,No,JAR file structure,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive commercial license,Must include copyright notice,Apache Software Foundation,commons-logging:1.2,commons-io:2.11.0
log4j-core,2.14.1,Open-Source,Requires upgrade to 2.17.0,2021-01-15,2024-01-01,Critical,None,Contains Log4Shell vulnerability,No,No,Library,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive open source license,Must include original copyright,Apache Software Foundation,slf4j-api:1.7.32
spring-core,5.3.18,Open-Source,Current version,2022-03-15,2025-03-15,High,None,Core framework component,No,No,Library,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive license with patent grant,Spring-specific trademark restrictions apply,VMware,spring-beans:5.3.18,spring-context:5.3.18
EOL
fi

# Create sample templates if they don't exist
if [ ! -f "templates/index.html" ]; then
    echo "Creating sample index.html..."
    cat > templates/index.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CERT-In SBOM Compliance Tool</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-12">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h2 class="mb-0"><i class="fas fa-shield-alt me-2"></i>CERT-In SBOM Compliance Tool</h2>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-upload me-2"></i>Upload SBOM File</h5>
                                    </div>
                                    <div class="card-body">
                                        <form id="uploadForm" enctype="multipart/form-data">
                                            <div class="mb-3">
                                                <label for="sbomFile" class="form-label">Select SBOM file (JSON/XML)</label>
                                                <input class="form-control" type="file" id="sbomFile" name="file" accept=".json,.xml" required>
                                                <div class="form-text">Supports CycloneDX and SPDX formats</div>
                                            </div>
                                            <button type="submit" class="btn btn-primary">
                                                <i class="fas fa-cloud-upload-alt me-2"></i>Upload and Analyze
                                            </button>
                                        </form>
                                        <div id="uploadStatus" class="mt-3"></div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i>Tool Status</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="mb-3">
                                            <strong>Available Scanners:</strong>
                                            <ul class="list-group mt-2">
                                                <li class="list-group-item">
                                                    <i class="fas fa-{{ 'check-circle text-success' if tools.grype else 'times-circle text-danger' }} me-2"></i>
                                                    Grype
                                                </li>
                                                <li class="list-group-item">
                                                    <i class="fas fa-{{ 'check-circle text-success' if tools.dependency-check else 'times-circle text-danger' }} me-2"></i>
                                                    OWASP Dependency-Check
                                                </li>
                                            </ul>
                                        </div>
                                        <div class="alert alert-info">
                                            <i class="fas fa-lightbulb me-2"></i>
                                            <strong>Tip:</strong> Use sample SBOM files to test the tool
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        {% if analyses %}
                        <div class="mt-4">
                            <h4><i class="fas fa-history me-2"></i>Recent Analyses</h4>
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>File ID</th>
                                            <th>Format</th>
                                            <th>Date</th>
                                            <th>Scanner</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for analysis in analyses %}
                                        <tr>
                                            <td><code>{{ analysis.file_id[:8] }}...</code></td>
                                            <td>{{ analysis.original_format }}</td>
                                            <td>{{ analysis.analysis_date }}</td>
                                            <td>{{ analysis.scanner_used }}</td>
                                            <td>
                                                <a href="/analysis/{{ analysis.file_id }}" class="btn btn-sm btn-outline-primary">
                                                    <i class="fas fa-eye me-1"></i>View
                                                </a>
                                            </td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData();
            const fileInput = document.getElementById('sbomFile');
            formData.append('file', fileInput.files[0]);
            
            const statusDiv = document.getElementById('uploadStatus');
            statusDiv.innerHTML = `
                <div class="alert alert-info">
                    <div class="spinner-border spinner-border-sm me-2" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    Uploading and analyzing SBOM file...
                </div>
            `;
            
            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    statusDiv.innerHTML = `
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle me-2"></i>
                            ${data.message} Found ${data.components} components and ${data.vulnerabilities} vulnerabilities.
                        </div>
                    `;
                    // Redirect to results page after short delay
                    setTimeout(() => {
                        window.location.href = `/analysis/${data.file_id}`;
                    }, 2000);
                } else {
                    statusDiv.innerHTML = `
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle me-2"></i>
                            Error: ${data.error}
                        </div>
                    `;
                }
            } catch (error) {
                statusDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle me-2"></i>
                        Upload failed: ${error.message}
                    </div>
                `;
            }
        });
    </script>
</body>
</html>
EOL
fi

if [ ! -f "templates/results.html" ]; then
    echo "Creating sample results.html..."
    cat > templates/results.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Analysis Results - CERT-In Tool</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .vulnerability { padding: 10px; margin: 5px 0; border-radius: 3px; border-left: 4px solid; }
        .critical { background: #f8d7da; border-left-color: #dc3545; }
        .high { background: #fff3cd; border-left-color: #ffc107; }
        .medium { background: #d1ecf1; border-left-color: #17a2b8; }
        .low { background: #d4edda; border-left-color: #28a745; }
        .unknown { background: #e2e3e5; border-left-color: #6c757d; }
        .certin-field { background: #e9ecef; padding: 5px; border-radius: 3px; margin: 2px 0; }
        .component-card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
        .license-details { background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 5px 0; }
        .scanner-badge { background: #6f42c1; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1><i class="fas fa-file-alt me-2"></i>CERT-In SBOM Compliance Report</h1>
            <a href="/" class="btn btn-outline-primary">
                <i class="fas fa-arrow-left me-2"></i>Back to Upload
            </a>
        </div>

        {% if analysis %}
        <!-- Summary Section -->
        <div class="card shadow mb-4">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i>Analysis Summary</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3>{{ analysis.components|length }}</h3>
                                <p class="text-muted">Components</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3>{{ analysis.vulnerabilities|length }}</h3>
                                <p class="text-muted">Vulnerabilities</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3><span class="scanner-badge">{{ analysis.scanner_used }}</span></h3>
                                <p class="text-muted">Scanner Used</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h3>{{ analysis.analysis_date[:10] }}</h3>
                                <p class="text-muted">Analysis Date</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="mt-3">
                    <div class="certin-field"><strong>Report Generated:</strong> {{ analysis.analysis_date }}</div>
                    <div class="certin-field"><strong>Analysis ID:</strong> <code>{{ analysis.file_id }}</code></div>
                    <div class="certin-field"><strong>SBOM Format:</strong> {{ analysis.original_format }}</div>
                    <div class="certin-field"><strong>Scanner Used:</strong> {{ analysis.scanner_used }}</div>
                    
                    <!-- Vulnerability Breakdown -->
                    {% set severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0} %}
                    {% for vuln in analysis.vulnerabilities %}
                        {% set severity = vuln.severity %}
                        {% if severity in severity_counts %}
                            {% set _ = severity_counts.update({severity: severity_counts[severity] + 1}) %}
                        {% else %}
                            {% set _ = severity_counts.update({'Unknown': severity_counts['Unknown'] + 1}) %}
                        {% endif %}
                    {% endfor %}
                    
                    <div class="certin-field">
                        <strong>Vulnerability Summary:</strong><br>
                        Critical: {{ severity_counts.Critical }} | 
                        High: {{ severity_counts.High }} | 
                        Medium: {{ severity_counts.Medium }} | 
                        Low: {{ severity_counts.Low }} | 
                        Unknown: {{ severity_counts.Unknown }}
                    </div>
                </div>
            </div>
        </div>

        <!-- Components Table -->
        <div class="card shadow mb-4">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-cubes me-2"></i>Components Overview ({{ analysis.components|length }})</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Component</th>
                                <th>Version</th>
                                <th>Supplier</th>
                                <th>License</th>
                                <th>Criticality</th>
                                <th>Vulnerabilities</th>
                                <th>Origin</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for component in analysis.components %}
                            <tr>
                                <td><strong>{{ component.name }}</strong></td>
                                <td>{{ component.version }}</td>
                                <td>{{ component.supplier }}</td>
                                <td>{{ component.license.name if component.license else 'Unknown' }}</td>
                                <td>
                                    <span class="badge bg-{% if component.criticality == 'Critical' %}danger{% elif component.criticality == 'High' %}warning{% elif component.criticality == 'Medium' %}info{% else %}secondary{% endif %}">
                                        {{ component.criticality }}
                                    </span>
                                </td>
                                <td>
                                    {% set comp_vulns = [] %}
                                    {% for vuln in analysis.vulnerabilities %}
                                        {% if vuln.component_name == component.name and vuln.component_version == component.version %}
                                            {% set _ = comp_vulns.append(vuln) %}
                                        {% endif %}
                                    {% endfor %}
                                    <span class="badge bg-{% if comp_vulns|length > 0 %}danger{% else %}success{% endif %}">
                                        {{ comp_vulns|length }}
                                    </span>
                                </td>
                                <td>{{ component.origin }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Detailed Component Analysis -->
        <div class="card shadow mb-4">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-list-alt me-2"></i>Detailed Component Analysis</h5>
            </div>
            <div class="card-body">
                {% for component in analysis.components %}
                <div class="component-card mb-4">
                    <h4>📦 {{ component.name }} @ {{ component.version }}</h4>
                    
                    <!-- Basic Information -->
                    <div class="row">
                        <div class="col-md-6">
                            <div class="certin-field"><strong>Description:</strong> {{ component.description }}</div>
                            <div class="certin-field"><strong>Supplier:</strong> {{ component.supplier }}</div>
                            <div class="certin-field"><strong>Origin:</strong> {{ component.origin }}</div>
                            <div class="certin-field"><strong>Criticality:</strong> 
                                <span class="badge bg-{% if component.criticality == 'Critical' %}danger{% elif component.criticality == 'High' %}warning{% elif component.criticality == 'Medium' %}info{% else %}secondary{% endif %}">
                                    {{ component.criticality }}
                                </span>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="certin-field"><strong>Release Date:</strong> {{ component.release_date }}</div>
                            <div class="certin-field"><strong>EOL Date:</strong> {{ component.eol_date }}</div>
                            <div class="certin-field"><strong>Patch Status:</strong> {{ component.patch_status }}</div>
                            <div class="certin-field"><strong>Unique ID:</strong> <code>{{ component.unique_identifier }}</code></div>
                        </div>
                    </div>

                    <!-- License Details -->
                    <div class="license-details mt-3">
                        <h6>📄 License Information</h6>
                        <div class="certin-field"><strong>License:</strong> {{ component.license.name if component.license else 'Unknown' }}</div>
                        {% if component.license and component.license.terms %}
                        <div class="certin-field"><strong>License Terms:</strong> {{ component.license.terms }}</div>
                        {% endif %}
                        {% if component.license and component.license.restrictions %}
                        <div class="certin-field"><strong>License Restrictions:</strong> {{ component.license.restrictions }}</div>
                        {% endif %}
                        {% if component.license and component.license.url %}
                        <div class="certin-field"><strong>License URL:</strong> <a href="{{ component.license.url }}" target="_blank">{{ component.license.url }}</a></div>
                        {% endif %}
                    </div>

                    <!-- Usage and Properties -->
                    <div class="row mt-3">
                        <div class="col-md-6">
                            <div class="certin-field"><strong>Usage Restrictions:</strong> {{ component.usage_restrictions }}</div>
                            <div class="certin-field"><strong>Comments:</strong> {{ component.comments }}</div>
                        </div>
                        <div class="col-md-6">
                            <div class="certin-field"><strong>Executable:</strong> {{ component.executable_property }}</div>
                            <div class="certin-field"><strong>Archive:</strong> {{ component.archive_property }}</div>
                            <div class="certin-field"><strong>Structured:</strong> {{ component.structured_property }}</div>
                        </div>
                    </div>

                    <!-- Dependencies -->
                    {% if component.dependencies %}
                    <div class="certin-field mt-3">
                        <strong>Dependencies:</strong>
                        <ul class="mb-0">
                            {% for dep in component.dependencies %}
                            <li>{{ dep }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}

                    <!-- Hashes -->
                    {% if component.hashes %}
                    <div class="certin-field mt-3">
                        <strong>Integrity Hashes:</strong>
                        {% for alg, content in component.hashes.items() %}
                        <div>{{ alg }}: <code>{{ content }}</code></div>
                        {% endfor %}
                    </div>
                    {% endif %}

                    <!-- Vulnerabilities -->
                    {% set comp_vulns = [] %}
                    {% for vuln in analysis.vulnerabilities %}
                        {% if vuln.component_name == component.name and vuln.component_version == component.version %}
                            {% set _ = comp_vulns.append(vuln) %}
                        {% endif %}
                    {% endfor %}
                    
                    {% if comp_vulns %}
                    <div class="mt-3">
                        <h5>🛡️ Vulnerabilities ({{ comp_vulns|length }})</h5>
                        {% for vuln in comp_vulns %}
                        <div class="vulnerability {{ vuln.severity|lower }}">
                            <strong>{{ vuln.cve_id }} ({{ vuln.severity }}) - CVSS Score: {{ vuln.cvss_score }}</strong>
                            <span class="scanner-badge">{{ vuln.scanner if vuln.scanner else 'Unknown' }}</span>
                            <br>
                            <strong>Description:</strong> {{ vuln.description }}<br>
                            <strong>Fixed Versions:</strong> {{ vuln.fixed_versions|join(', ') if vuln.fixed_versions else 'None' }}<br>
                            <strong>Status:</strong> {{ vuln.vex_status }}
                        </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="alert alert-success mt-3">
                        <i class="fas fa-check-circle me-2"></i>
                        ✅ No known vulnerabilities for this component
                    </div>
                    {% endif %}
                </div>
                <hr>
                {% endfor %}
            </div>
        </div>

        <!-- All Vulnerabilities Table -->
        {% if analysis.vulnerabilities %}
        <div class="card shadow mb-4">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-bug me-2"></i>All Vulnerabilities ({{ analysis.vulnerabilities|length }})</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Severity</th>
                                <th>Component</th>
                                <th>CVSS Score</th>
                                <th>Status</th>
                                <th>Scanner</th>
                                <th>Fixed Versions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for vuln in analysis.vulnerabilities %}
                            <tr>
                                <td><strong>{{ vuln.cve_id }}</strong></td>
                                <td>
                                    <span class="badge bg-{% if vuln.severity == 'Critical' %}danger{% elif vuln.severity == 'High' %}warning{% elif vuln.severity == 'Medium' %}info{% elif vuln.severity == 'Low' %}success{% else %}secondary{% endif %}">
                                        {{ vuln.severity }}
                                    </span>
                                </td>
                                <td>{{ vuln.component_name }}@{{ vuln.component_version }}</td>
                                <td>{{ vuln.cvss_score }}</td>
                                <td>{{ vuln.vex_status }}</td>
                                <td>{{ vuln.scanner if vuln.scanner else 'Unknown' }}</td>
                                <td>{{ vuln.fixed_versions|join(', ') if vuln.fixed_versions else 'None' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Report Download -->
        <div class="card shadow">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-download me-2"></i>Export Reports</h5>
            </div>
            <div class="card-body text-center">
                <div class="btn-group">
                    <a href="/report/{{ analysis.file_id }}/json" class="btn btn-outline-primary">
                        <i class="fas fa-file-code me-2"></i>JSON Report
                    </a>
                    <a href="/report/{{ analysis.file_id }}/html" class="btn btn-outline-secondary">
                        <i class="fas fa-file-alt me-2"></i>HTML Report
                    </a>
                    <a href="/report/{{ analysis.file_id }}/csaf" class="btn btn-outline-info">
                        <i class="fas fa-file-contract me-2"></i>CSAF Report
                    </a>
                    <a href="/report/{{ analysis.file_id }}/pdf" class="btn btn-outline-danger">
                        <i class="fas fa-file-pdf me-2"></i>PDF Report
                    </a>
                </div>
                <p class="mt-3 text-muted">Download machine-readable reports for compliance auditing</p>
            </div>
        </div>

        {% else %}
        <div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle me-2"></i>
            Analysis not found! The analysis may have been deleted or the ID is invalid.
        </div>
        {% endif %}
    </div>
</body>
</html>
EOL
fi

echo "Installation complete!"
echo "To start the tool: source .venv/bin/activate && python app.py"
