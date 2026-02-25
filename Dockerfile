# ══════════════════════════════════════════════════════════
# Mini SIEM — Dockerfile (macOS / Linux)
# ══════════════════════════════════════════════════════════
#
# Build:   docker build -t mini-siem .
# Run:     docker run -p 5000:5000 mini-siem
# Demo:    docker run -p 5000:5000 mini-siem run --demo
# Shell:   docker run -it mini-siem /bin/bash
#
# For persistent DB across container restarts, mount a volume:
#   docker run -p 5000:5000 -v $(pwd)/data:/app/data mini-siem
# ══════════════════════════════════════════════════════════

# ── Base image: slim Python 3.11 on Debian ──
# 'slim' variant is smaller than the default (no dev tools)
FROM python:3.11-slim

# ── Labels (shows up in Docker Desktop / docker inspect) ──
LABEL maintainer="your@email.com"
LABEL description="Mini SIEM — Log Monitor & Alert Tool"
LABEL version="2.0"

# ── Set working directory inside the container ──
WORKDIR /app

# ── Create a non-root user for security ──
# Never run applications as root inside containers
RUN groupadd -r siem && useradd -r -g siem -m siem

# ── Install Python dependencies FIRST ──
# Docker caches layers — by copying requirements.txt before source code,
# the pip install layer is only re-run when requirements.txt changes,
# not every time your code changes. This makes rebuilds much faster.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application source code ──
COPY *.py ./
COPY data/ ./data/ 2>/dev/null || true    # copy threat intel if it exists

# ── Create necessary directories ──
RUN mkdir -p logs data && \
    chown -R siem:siem /app

# ── Switch to non-root user ──
USER siem

# ── Expose the dashboard port ──
EXPOSE 5000

# ── Health check: ping the dashboard every 30s ──
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/login')" || exit 1

# ── Default command: run dashboard in demo mode ──
# Override with: docker run mini-siem run --demo
CMD ["python", "main.py", "dashboard", "--host", "0.0.0.0", "--demo"]
