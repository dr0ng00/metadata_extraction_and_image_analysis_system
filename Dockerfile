# ===============================
# Multi-stage Build for Smaller Image
# ===============================

# Stage 1: Builder stage
FROM python:3.11-slim AS builder

# System dependencies for building Python packages
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies in a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ===============================
# Stage 2: Runtime stage
# ===============================
FROM python:3.11-slim

# ===============================
# Environment Variables
# ===============================
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

# ===============================
# Create Non-root User
# ===============================
RUN groupadd -r forensic && \
    useradd -r -g forensic -u 1000 -m -s /bin/bash forensic && \
    mkdir -p /app /data && \
    chown -R forensic:forensic /app /data

# ===============================
# System Dependencies (OpenCV + Security)
# ===============================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # OpenCV dependencies
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    libglu1-mesa \
    libgtk2.0-0 \
    libgtk-3-0 \
    libgomp1 \
    # Security updates
    ca-certificates \
    # Utilities
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ===============================
# Copy from builder stage
# ===============================
COPY --from=builder /opt/venv /opt/venv

# ===============================
# Working Directory
# ===============================
WORKDIR /app

# ===============================
# Copy Project Files
# ===============================
COPY --chown=forensic:forensic . .

# ===============================
# Create Required Directories
# ===============================
RUN mkdir -p \
    data/output \
    data/reports \
    data/logs \
    data/database \
    data/input \
    data/models \
    && chown -R forensic:forensic /app/data

# ===============================
# Health Check
# ===============================
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import cv2; import numpy; print('Health check passed')" || exit 1

# ===============================
# Switch to Non-root User
# ===============================
USER forensic

# ===============================
# Volume for Persistent Data
# ===============================
VOLUME ["/data"]

# ===============================
# Default Command with Arguments
# ===============================
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]