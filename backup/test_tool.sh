#!/bin/bash
# test_tool.sh

echo "Testing CERT-In SBOM Tool..."

# Activate virtual environment
source .venv/bin/activate

# Check if Python dependencies are installed
echo "Checking Python dependencies..."
python -c "
import flask, requests, jinja2, magic, fpdf, weasyprint
print('✅ All Python dependencies are installed')
"

# Check if tools are available
echo "Checking security tools..."
if command -v grype &> /dev/null; then
    echo "✅ Grype is available: $(grype --version)"
else
    echo "⚠️ Grype is not available"
fi

if command -v dependency-check.sh &> /dev/null; then
    echo "✅ OWASP Dependency-Check is available: $(dependency-check.sh --version)"
else
    echo "⚠️ OWASP Dependency-Check is not available"
fi

# Test the app
echo "Starting test server..."
python app.py &
APP_PID=$!

# Wait for server to start
sleep 3

# Test health endpoint
echo "Testing health endpoint..."
curl -s http://localhost:5000/health | python -m json.tool

# Stop the server
kill $APP_PID

echo "Test completed!"
