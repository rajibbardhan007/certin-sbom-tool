FROM python:3.13-slim

# Install system dependencies for WeasyPrint, Grype, and OWASP Dependency-Check
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    openjdk-17-jre-headless \
    libcairo2 \
    libpango-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check
ENV DC_VERSION 9.0.0
RUN curl -LO https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/dependency-check-${DC_VERSION}-release.zip \
    && unzip dependency-check-${DC_VERSION}-release.zip -d /opt \
    && rm dependency-check-${DC_VERSION}-release.zip \
    && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

# Copy application code
COPY app.py .
COPY templates/ templates/
COPY static/ static/

EXPOSE 5000
CMD ["python", "app.py"]
