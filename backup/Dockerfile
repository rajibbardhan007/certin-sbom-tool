FROM python:3.9-slim

WORKDIR /app

# Install system dependencies including Java for OWASP Dependency-Check
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    default-jre \
    && rm -rf /var/lib/apt/lists/*

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check (optional)
RUN wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.3.1/dependency-check-8.3.1-release.zip \
    && unzip dependency-check-8.3.1-release.zip -d /opt \
    && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check \
    && rm dependency-check-8.3.1-release.zip

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create upload directory
RUN mkdir -p static/uploads

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]

FROM python:3.9-slim

WORKDIR /app

# Install system dependencies including Java for OWASP Dependency-Check
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    default-jre \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check
RUN wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.3.1/dependency-check-8.3.1-release.zip \
    && unzip dependency-check-8.3.1-release.zip -d /opt \
    && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check \
    && rm dependency-check-8.3.1-release.zip

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create upload directory
RUN mkdir -p static/uploads

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]
