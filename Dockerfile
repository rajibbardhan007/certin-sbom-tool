# Base image with Python and OS-level packages
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for WeasyPrint, Grype, etc.
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    wget \
    curl \
    unzip \
    openjdk-11-jdk \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the app code
COPY . /app

# Install Python dependencies
RUN python -m venv .venv
RUN .venv/bin/pip install --upgrade pip
RUN .venv/bin/pip install flask==2.3.3 requests==2.31.0 jinja2==3.1.2 python-magic==0.4.27 fpdf==1.7.2 weasyprint==58.0

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
    && wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/${LATEST_VERSION}/dependency-check-${LATEST_VERSION:1}-release.zip" \
    && unzip "dependency-check-${LATEST_VERSION:1}-release.zip" \
    && mv dependency-check /opt/ \
    && ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh

# Create directories
RUN mkdir -p static/uploads static/reports templates

# Expose Flask port
EXPOSE 10000

# Start the app
CMD [".venv/bin/python", "app.py"]
