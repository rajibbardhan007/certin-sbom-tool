# Create necessary directories
mkdir -p config templates static/uploads static/reports

# Create sample component mapping
cat > component_mapping.csv << 'EOL'
name,version,origin,patch_status,release_date,eol_date,criticality,usage_restrictions,comments,executable,archive,structured,license_name,license_url,license_terms,license_restrictions,supplier,dependencies
Apache Tomcat,9.0.71,Open-Source,Patched in 9.0.72,2023-04-12,2026-12-31,Critical,No export outside India,Production web server,Yes,No,JAR file structure,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive commercial license,Must include copyright notice,Apache Software Foundation,commons-logging:1.2,commons-io:2.11.0
log4j-core,2.14.1,Open-Source,Requires upgrade to 2.17.0,2021-01-15,2024-01-01,Critical,None,Contains Log4Shell vulnerability,No,No,Library,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive open source license,Must include original copyright,Apache Software Foundation,slf4j-api:1.7.32
spring-core,5.3.18,Open-Source,Current version,2022-03-15,2025-03-15,High,None,Core framework component,No,No,Library,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive license with patent grant,Spring-specific trademark restrictions apply,VMware,spring-beans:5.3.18,spring-context:5.3.18
EOL

# Create Grype config
cat > config/grype_config.yaml << 'EOL'
# Grype configuration for CERT-In SBOM Tool
check-for-app-update: false
db:
  auto-update: true
  ca-cert: ""
  update-url: "https://toolbox-data.anchore.io/grype/databases/"
  max-allowed-built-age: "336h" # 2 weeks
log:
  level: "warn"
  structured: false
  file: ""
output: "json"
scope: "Squashed"
file: ""
only-fixed: false
only-notfixed: false
add-cpes-if-none: true
by-cve: false
source:
  name: ""
  version: ""
  type: ""
  registry: ""
platform: ""
exclude:
  - path: "**/test/**"
  - path: "**/tests/**"
  - path: "**/node_modules/**"
  - path: "**/vendor/**"
  - path: "**/.*/**"
EOL

# Create Dependency-Check wrapper script
cat > config/dependency-check.sh << 'EOL'
#!/bin/bash
# Wrapper script for OWASP Dependency-Check with CERT-In specific configuration

# Default configuration
DEFAULT_OPTS=(
    "--format" "JSON"
    "--enableExperimental"
    "--disableAssembly"
    "--disableRetireJS"
    "--disableNodeJS"
    "--disableNodeAudit"
    "--disableNexus"
    "--disableCentral"
    "--disableNuspec"
    "--disableAutoconf"
    "--disableOpenSSL"
    "--disablePyDist"
    "--disablePyPkg"
    "--disableRubygems"
    "--disableCocoapods"
    "--disableSwift"
    "--disableArchive"
    "--failOnCVSS" "0"
)

# Find the actual dependency-check script
find_dependency_check() {
    local paths=(
        "/opt/dependency-check/bin/dependency-check.sh"
        "/usr/local/bin/dependency-check.sh"
        "/usr/bin/dependency-check.sh"
        "$(which dependency-check.sh 2>/dev/null)"
        "dependency-check.sh"
    )
    
    for path in "${paths[@]}":
        if [ -f "$path" ] && [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    echo "ERROR: dependency-check.sh not found" >&2
    return 1
}

# Main execution
main() {
    local dc_path
    dc_path=$(find_dependency_check)
    if [ $? -ne 0 ]; then
        echo "$dc_path"
        exit 1
    fi
    
    # Execute with default options and any user-provided options
    exec "$dc_path" "${DEFAULT_OPTS[@]}" "$@"
}

# Run main function
main "$@"
EOL

chmod +x config/dependency-check.sh
