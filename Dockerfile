# syntax=docker/dockerfile:1
# softXchange — Unified Railway Deployment
# Runs all 7 microservices + Caddy in one container via supervisord

FROM python:3.12-slim AS base

# Install system deps: supervisord, caddy, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    curl \
    debian-archive-keyring \
    apt-transport-https \
    gnupg \
    && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
    && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list \
    && apt-get update && apt-get install -y caddy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install all Python dependencies in one layer
COPY apps/auth-service/requirements.txt      /tmp/req-auth.txt
COPY apps/scan-service/requirements.txt      /tmp/req-scan.txt
COPY apps/listings-service/requirements.txt  /tmp/req-listings.txt
COPY apps/payments-service/requirements.txt  /tmp/req-payments.txt
COPY apps/buyer-assist/requirements.txt      /tmp/req-buyer.txt
COPY apps/seller-assist/requirements.txt     /tmp/req-seller.txt
COPY apps/broker/requirements.txt            /tmp/req-broker.txt
COPY apps/web-unified/requirements.txt       /tmp/req-web.txt

RUN pip install --no-cache-dir \
    -r /tmp/req-auth.txt \
    -r /tmp/req-scan.txt \
    -r /tmp/req-listings.txt \
    -r /tmp/req-payments.txt \
    -r /tmp/req-buyer.txt \
    -r /tmp/req-seller.txt \
    -r /tmp/req-broker.txt \
    -r /tmp/req-web.txt \
    psycopg2-binary>=2.9.9

# Copy all app source code and internal engines
COPY apps/ /app/apps/
COPY packages/ /app/packages/
COPY tokens/ /app/tokens/
COPY ["Secret Scanner engine/", "/app/Secret Scanner engine/"]

# Install internal packages so secrets_scanner, ml_shared, etc. are globally importable
RUN pip install --no-cache-dir "/app/Secret Scanner engine" && \
    pip install --no-cache-dir -e /app/packages/ml-shared

# Ensure supervisor log and run dirs exist
RUN mkdir -p /var/log/supervisor /var/run

# Copy supervisord + caddy configs
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY supervisord.conf /etc/supervisor/conf.d/softxchange.conf
COPY Caddyfile.railway /etc/caddy/Caddyfile
COPY Caddyfile.railway /app/Caddyfile.railway

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose single port (Caddy)
EXPOSE 8080

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
