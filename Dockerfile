# ── Stage 1: build the nuclei binary ─────────────────────────────────────────
FROM golang:1.24-alpine AS nuclei-builder
RUN apk add --no-cache git
ENV GOTOOLCHAIN=auto
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── Stage 2: the actual backend image ────────────────────────────────────────
FROM python:3.11-slim

# nmap = port/service scanning engine used by tasks.py
# git   = needed once, to pull the nuclei-templates repo
# ca-certificates = so nuclei/requests can do TLS to https targets
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Bring the nuclei binary in from the build stage
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei

# Pull the nuclei templates once at build time so scans don't need to
# download them on first run. (Refresh manually with `nuclei -update-templates`
# if you rebuild the image later and want the latest templates.)
RUN nuclei -update-templates -silent || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# tasks.py reads these instead of the old hardcoded /home/maurya-prakash/... paths
ENV NUCLEI_BIN=/usr/local/bin/nuclei
ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
