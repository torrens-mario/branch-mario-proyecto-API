# Dockerfile para Man-in-the-Middle Proxy (Educativo)
FROM python:3.11-slim

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    BACKEND_HOST=backend \
    BACKEND_PORT=8000

# Instalar dependencias del sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        netcat-openbsd \
        curl \
        && rm -rf /var/lib/apt/lists/*

# Crear directorio para capturas
RUN mkdir -p /captures && chmod 777 /captures

# Directorio de trabajo
WORKDIR /app

# Copiar scripts
COPY proxy.py .
COPY capture.sh .
RUN chmod +x capture.sh

# Crear usuario no-root (pero con capacidades NET_ADMIN para tcpdump)
RUN useradd -m -u 1000 mitm-user

# Exponer puerto
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Comando: Iniciar proxy y captura simultáneamente
CMD sh -c "./capture.sh & python proxy.py"

