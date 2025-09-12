#!/bin/bash
# setup.sh - Setup script for CERT-In SBOM Tool

echo "Setting up CERT-In SBOM Compliance Tool..."
echo "=========================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p static/uploads
mkdir -p reports

# Create sample component mapping file if it doesn't exist
if [ ! -f "component_mapping.csv" ]; then
    echo "Creating sample component_mapping.csv..."
    echo "component_name,certin_category,criticality,usage_restrictions" > component_mapping.csv
    echo "log4j-core,crypto,High,Restricted" >> component_mapping.csv
    echo "openssl,network,High,Restricted" >> component_mapping.csv
    echo "nginx,web_server,Medium,Allowed" >> component_mapping.csv
fi

# Create sample SBOM file for testing
if [ ! -f "sample_sbom.json" ]; then
    echo "Creating sample_sbom.json..."
    cat > sample_sbom.json << EOF
{
  "format": "SPDX-2.2",
  "components": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "description": "Apache Log4j Core",
      "supplier": "Apache Software Foundation",
      "license": "Apache-2.0",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    },
    {
      "name": "spring-boot",
      "version": "2.5.6",
      "description": "Spring Boot Framework",
      "supplier": "VMware",
      "license": "Apache-2.0",
      "purl": "pkg:maven/org.springframework.boot/spring-boot@2.5.6"
    }
  ],
  "metadata": {
    "tool": "Syft",
    "timestamp": "2023-12-01T10:00:00Z"
  }
}
EOF
fi

echo ""
echo "Setup completed successfully!"
echo "To run the application:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run: python app.py"
echo "3. Open: http://localhost:5000"
echo ""
echo "To deactivate the virtual environment, run: deactivate"
