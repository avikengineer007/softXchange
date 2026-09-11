# syntax=docker/dockerfile:1
# softXchange Unified Web Frontend — Production Dockerfile
# Minimal multi-stage container serving consolidated marketplace frontend

# ── Stage 1: Build Dependencies ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
    fastapi>=0.110.0 \
    uvicorn[standard]>=0.28.0

# ── Stage 2: Minimal Runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runner

WORKDIR /app

RUN useradd -m -u 10001 -s /bin/bash appuser

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8000

COPY apps/web-unified /app

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["python", "run.py"]
