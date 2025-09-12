# Use Python 3.13 slim base image
FROM python:3.13-slim

# Set working directory inside the container
WORKDIR /app

# Copy your project files
COPY . /app

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Install Grype (for SBOM vulnerability scanning)
RUN pip install grype

# Expose port if your Flask app uses 5000
EXPOSE 5000

# Default command to run your app
CMD ["python", "app.py"]
