# Use official Python 3.13 slim image as base
FROM python:3.13-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy requirements file first to leverage Docker caching
COPY requirements.txt .

# Install system dependencies (for WeasyPrint, curl, unzip, Java for Dependency-Check)
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
    openjdk-11-jre-headless \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3 -m venv $VIRTUAL_ENV

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Install Grype (for SBOM vulnerability scanning)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
    && wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/${LATEST_VERSION}/dependency-check-${LATEST_VERSION:1}-release.zip" \
    && unzip -q dependency-check-${LATEST_VERSION:1}-release.zip \
    && mv dependency-check /opt/ \
    && ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh \
    && rm dependency-check-${LATEST_VERSION:1}-release.zip

# Copy the application code
COPY . .

# Expose port for Flask app
EXPOSE 5000

# Create necessary directories
RUN mkdir -p static/uploads static/reports templates

# Set entrypoint
CMD ["bash", "-c", "source /opt/venv/bin/activate && python app.py"]
