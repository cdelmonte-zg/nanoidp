# NanoIDP Dockerfile
# ===================
# A configurable mock Identity Provider for testing OAuth2/OIDC and SAML integrations.

FROM python:3.12-slim

LABEL maintainer="Christian Del Monte"
LABEL description="Lightweight Identity Provider for testing"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY src/ ./src/
COPY config/ ./config/

# Install the package
RUN pip install --no-cache-dir .

# Create keys directory
RUN mkdir -p /app/keys

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV NANOIDP_CONFIG_DIR=/app/config
ENV PORT=8000

# Expose port (default 8000; override PORT env var for non-standard ports)
EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsSL http://localhost:${PORT}/api/health || exit 1

# Run the application (PORT env var is passed to nanoidp; defaults to 8000)
CMD ["sh", "-c", "exec nanoidp --host 0.0.0.0 --port ${PORT}"]
