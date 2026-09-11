# syntax=docker/dockerfile:1
# softXchange Scan Service — Production Dockerfile
# Multi-stage build wrapping pinned secrets-scanner engine

# ── Stage 1: Build Dependencies ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY packages/vendor/wheels /wheels
RUN pip install --no-cache-dir /wheels/secrets_scanner-0.1.0-py3-none-any.whl

COPY apps/scan-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary alembic

# ── Stage 2: Minimal Runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runner

WORKDIR /app

RUN useradd -m -u 10001 -s /bin/bash appuser

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8002

COPY apps/scan-service /app

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8002

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8002/healthz')" || exit 1

CMD ["python", "run.py"]
