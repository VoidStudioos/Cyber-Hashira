# Cyber Hashira — Official Production Dockerfile
# Modular Cybersecurity & Penetration Testing Workstation
FROM python:3.11-slim

LABEL maintainer="Cyber Hashira Security Team <security@voidstudioos.com>"
LABEL description="Cyber Hashira - Complete 120-Module Security Workstation with Web UI & Terminal TUI"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=ui/web/app.py \
    PORT=8080 \
    HOST=0.0.0.0

# Install necessary runtime system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    net-tools \
    iputils-ping \
    dnsutils \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    flask \
    flask-cors \
    cryptography \
    rich \
    pytest

# Copy platform source and assets
COPY hashira.py /app/hashira.py
COPY modules/ /app/modules/
COPY registry/ /app/registry/
COPY ui/ /app/ui/
COPY scripts/ /app/scripts/
COPY tests/ /app/tests/

# Pre-verify registry and modules
RUN python3 scripts/package_all_modules.py

# Create output directories for evidence and reports
RUN mkdir -p /app/reports /app/evidence

EXPOSE 8080

# Healthcheck endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Default: Launch Web Security Dashboard
ENTRYPOINT ["python3", "hashira.py"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
