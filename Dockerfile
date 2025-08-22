# Dockerfile Final de Produção

# Estágio 1: Construir o pacote
FROM python:3.12-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install .

# Estágio 2: Imagem final enxuta
FROM python:3.12-slim-bookworm
WORKDIR /app
# Instala apenas as dependências de sistema necessárias para rodar
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/venv /app/venv

# O ENTRYPOINT que executa nosso programa
ENTRYPOINT ["/app/venv/bin/batman"]
