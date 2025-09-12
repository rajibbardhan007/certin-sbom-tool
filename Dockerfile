FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /app

COPY requirements.txt .

# Install system packages
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

# Create Python virtual environment
RUN python3 -m venv $VIRTUAL_ENV

# Upgrade pip and install Python packages
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Install Grype (correct way)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OWASP Dependency-Check
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
    && wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/${LATEST_VERSION}/dependency-check-${LATEST_VERSION:1}-release.zip" \
    && unzip -q dependency-check-${LATEST_VERSION:1}-release.zip \
    && mv dependency-check /opt/ \
    && ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh \
    && rm dependency-check-${LATEST_VERSION:1}-release.zip

# Copy application code
COPY . .

EXPOSE 5000

RUN mkdir -p static/uploads static/reports templates

CMD ["bash", "-c", "source /opt/venv/bin/activate && python app.py"]
