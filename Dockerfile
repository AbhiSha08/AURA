# ── Base Image ────────────────────────────────────────────────────────────────
# Use a lightweight, official Python slim image to minimize vulnerability surface
# and keep the build size optimized.
FROM python:3.11-slim AS builder

# ── Environment Variables ─────────────────────────────────────────────────────
# Prevent Python from writing pyc files to disk and ensure buffering is disabled
# to stream logs in real-time to Docker stdout/stderr.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── Working Directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Dependencies ──────────────────────────────────────────────────────────────
# Install build dependencies if any compiled wheels are required, then clean up.
# Using --no-cache-dir saves space.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ── Final Secure Stage ────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Streamlit Docker optimization variables
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ENABLE_CORS=false \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    PATH="/home/appuser/.local/bin:${PATH}"

WORKDIR /app

# Create a secure, restricted non-root group and user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /sbin/nologin appuser

# Copy installed Python packages from the builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source code only
# Since .dockerignore is configured, this only copies event_mapper.py, app.py,
# mitre_ingestor.py, and other essential runtime files.
COPY --chown=appuser:appgroup app.py event_mapper.py mitre_ingestor.py ./

# Apply permissions and switch to the secure non-root user
USER appuser

# Expose Streamlit's default port
EXPOSE 8501

# Healthcheck to verify Streamlit dashboard status and responsive health state
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

# Launch the Streamlit dashboard on startup
ENTRYPOINT ["streamlit", "run", "app.py"]
