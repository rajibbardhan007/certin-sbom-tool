#!/bin/bash

# CERT-In SBOM Tool Installation Script (Render.com / Linux Ready)
set -e

echo "⚙️  Installing CERT-In SBOM Compliance Tool dependencies..."

# Paths
VENV_DIR=".venv"
DEPENDENCY_CHECK_DIR="/opt/dependency-check"

# 1️⃣ Create virtual environment if not exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# 2️⃣ Activate virtual environment
source "$VENV_DIR/bin/activate"

# 3️⃣ Upgrade pip and install Python dependencies
echo "Installing Python packages..."
pip install --upgrade pip
pip install --no-cache-dir \
    flask==2.3.3 \
    requests==2.31.0 \
    jinja2==3.1.2 \
    python-magic==0.4.27 \
    fpdf==1.7.2 \
    weasyprint==58.0

# 4️⃣ Install system dependencies for WeasyPrint
if command -v apt-get &>/dev/null; then
    echo "Installing system packages for WeasyPrint..."
    apt-get update -qq
    apt-get install -y -qq \
        build-essential python3-dev python3-setuptools python3-wheel python3-cffi \
        libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info unzip wget curl openjdk-11-jdk
fi

# 5️⃣ Install Grype if not present
if ! command -v grype &>/dev/null; then
    echo "Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
else
    echo "Grype already installed: $(grype --version)"
fi

# 6️⃣ Install OWASP Dependency-Check if not present
if [ ! -d "$DEPENDENCY_CHECK_DIR" ]; then
    echo "Installing OWASP Dependency-Check..."
    LATEST_VERSION=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: $LATEST_VERSION"

    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/${LATEST_VERSION}/dependency-check-${LATEST_VERSION:1}-release.zip"
    unzip -q "dependency-check-${LATEST_VERSION:1}-release.zip"
    mv dependency-check "$DEPENDENCY_CHECK_DIR"
    ln -sf "$DEPENDENCY_CHECK_DIR/bin/dependency-check.sh" /usr/local/bin/dependency-check.sh

    cd -
    rm -rf "$TEMP_DIR"
    echo "Dependency-Check installed to $DEPENDENCY_CHECK_DIR"
else
    echo "Dependency-Check already installed: $($DEPENDENCY_CHECK_DIR/bin/dependency-check.sh --version)"
fi

# 7️⃣ Create necessary directories
echo "Creating directories..."
mkdir -p static/uploads static/reports templates

# 8️⃣ Create sample component_mapping.csv if missing
if [ ! -f "component_mapping.csv" ]; then
    echo "Creating sample component_mapping.csv..."
    cat > component_mapping.csv << EOL
name,version,origin,patch_status,release_date,eol_date,criticality,usage_restrictions,comments,executable,archive,structured,license_name,license_url,license_terms,license_restrictions,supplier,dependencies
Apache Tomcat,9.0.71,Open-Source,Patched in 9.0.72,2023-04-12,2026-12-31,Critical,No export outside India,Production web server,Yes,No,JAR file structure,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive commercial license,Must include copyright notice,Apache Software Foundation,commons-logging:1.2,commons-io:2.11.0
log4j-core,2.14.1,Open-Source,Requires upgrade to 2.17.0,2021-01-15,2024-01-01,Critical,None,Contains Log4Shell vulnerability,No,No,Library,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive open source license,Must include original copyright,Apache Software Foundation,slf4j-api:1.7.32
spring-core,5.3.18,Open-Source,Current version,2022-03-15,2025-03-15,High,None,Core framework component,No,No,Library,Apache-2.0,https://www.apache.org/licenses/LICENSE-2.0,Permissive license with patent grant,Spring-specific trademark restrictions apply,VMware,spring-beans:5.3.18,spring-context:5.3.18
EOL
fi

# 9️⃣ Create sample templates if missing
for template in index.html results.html; do
    if [ ! -f "templates/$template" ]; then
        echo "Creating sample templates/$template..."
        cp "templates_sample/$template" "templates/$template" || echo "Please provide $template in templates_sample/"
    fi
done

echo "✅ Installation complete!"
echo "To start the tool: source .venv/bin/activate && python app.py"
