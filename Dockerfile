FROM python:3.12-slim

LABEL maintainer="ThirdKey AI"
LABEL description="AgentScan - AI Agent Network Scanner"
LABEL version="1.0.0"

# Install system dependencies for raw socket support
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcap2-bin \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .
RUN pip install --no-cache-dir -e .

# Grant raw socket capabilities to Python binary
# This allows passive DNS and TLS monitoring without running as root
RUN setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))

# Create non-root user
RUN useradd -m -s /bin/bash agentscan
USER agentscan

# Default: run web dashboard
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090/api/health')" || exit 1

ENTRYPOINT ["python", "-m", "agentscan"]
CMD ["serve", "--port", "9090"]
