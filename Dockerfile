# docker/Dockerfile
FROM python:3.11-slim

# Install system dependencies for strings and magic
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the necessary analysis modules
COPY analysis/ /app/analysis/
COPY yara_rules/ /app/yara_rules/
COPY models/ /app/models/
COPY docker/analyzer.py /app/analyzer.py

# Create a non-root user for security
RUN useradd -m analyzer
USER analyzer

ENTRYPOINT ["python", "analyzer.py"]
