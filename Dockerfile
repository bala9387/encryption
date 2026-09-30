# Quantrace (PS 26237) — Production Dockerfile for Google Cloud Run & Container Platforms
FROM python:3.11-slim

# Ensure logs appear immediately in Cloud Logging
ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PS26237_HOME=/tmp/ps26237_workspace

WORKDIR /app

# ── 1. OS build tools (needed for liboqs + numpy/opencv) ──────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Build liboqs 0.16.0 (ML-KEM-768 + ML-DSA-65 only, no OpenSSL) ────────
RUN git clone --depth 1 --branch 0.16.0 \
        https://github.com/open-quantum-safe/liboqs /tmp/liboqs_src && \
    cmake -S /tmp/liboqs_src -B /tmp/liboqs_build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=OFF \
        -DOQS_DIST_BUILD=ON \
        "-DOQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65" \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
        -DCMAKE_INSTALL_LIBDIR=lib && \
    cmake --build /tmp/liboqs_build && \
    cmake --install /tmp/liboqs_build && \
    rm -rf /tmp/liboqs_src /tmp/liboqs_build

# Tell liboqs-python where to find the shared library
ENV OQS_INSTALL_PATH=/opt/oqs
ENV LD_LIBRARY_PATH=/opt/oqs/lib:${LD_LIBRARY_PATH}

# ── 3. Python dependencies ────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 4. Application code ───────────────────────────────────────────────────────
COPY . .

# ── 5. Health check (Cloud Run uses this to confirm startup) ─────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

EXPOSE 8080

# ── 6. Gunicorn — 1 worker, 8 threads, 300s timeout for forensic trace ───────
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 8 --timeout 300 --graceful-timeout 30 wsgi:app"]
