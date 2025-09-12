# Use Python slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PATH="/app/.venv/bin:$PATH"

# Copy project files
COPY . .

# Install system dependencies for WeasyPrint, Grype, Dependency-Check
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-cffi \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    curl \
    unzip \
    wget \
    git \
 && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3 -m venv .venv

# Activate venv and install Python dependencies
RUN . .venv/bin/activate && pip install --upgrade pip \
    && pip install flask==2.3.3 requests==2.31.0 jinja2==3.1.2 python-magic==0.4.27 fpdf==1.7.2 weasyprint==58.0

# Install Grype (official script)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
 && TEMP_DIR=$(mktemp -d) \
 && cd "$TEMP_DIR" \
 && wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/${LATEST_VERSION}/dependency-check-${LATEST_VERSION:1}-release.zip" \
 && unzip -q "dependency-check-${LATEST_VERSION:1}-release.zip" \
 && mv dependency-check /opt/ \
 && ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh \
 && cd - && rm -rf "$TEMP_DIR"

# Create necessary directories
RUN mkdir -p static/uploads static/reports templates

# Copy sample component mapping and templates
COPY component_mapping.csv ./component_mapping.csv
COPY templates/ ./templates/

# Expose Flask port
EXPOSE 5000

# Set default command
CMD ["/bin/bash", "-c", ". .venv/bin/activate && python app.py"]
