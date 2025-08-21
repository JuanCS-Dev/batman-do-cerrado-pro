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
# _ALTERADO_: Usamos o caminho explícito do pip do venv
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

# _ALTERADO_: Copiamos o diretório de configuração para a imagem final
# para que o core.config.py possa encontrar o settings.toml.
COPY --from=builder /app/config /app/config

# _ALTERADO_: ENTRYPOINT agora é um script shell para mais controle
# Ele ativa o venv e então executa qualquer comando passado (ou nenhum)
ENTRYPOINT ["/bin/bash", "-c", "source /app/venv/bin/activate && batman \"$@\""]

# _REMOVIDO_: A linha CMD foi removida para permitir o modo interativo puro.
