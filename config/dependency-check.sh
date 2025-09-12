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
