# Dockerfile para Batman do Cerrado - A Armadura de Contenção (Versão Final)

# --- ESTÁGIO 1: O "Builder" ---
FROM python:3.12-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    nmap \
    dnsutils \
    whois \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install .

# --- ESTÁGIO 2: A Imagem Final ---
FROM python:3.12-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/venv /app/venv
COPY --from=builder /app/config /app/config

# _ALTERADO_: Definimos uma variável de ambiente para que o config.py
# saiba exatamente onde encontrar o arquivo de configuração.
ENV BATMAN_SETTINGS_PATH="/app/config/settings.toml"

ENTRYPOINT ["/bin/bash", "-c", "source /app/venv/bin/activate && batman \"$@\""]
