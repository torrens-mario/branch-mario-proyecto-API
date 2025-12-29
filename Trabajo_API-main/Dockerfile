# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Usuario no-root
RUN useradd -m appuser
WORKDIR /app

# Dependencias del sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código de la aplicación
COPY app ./app
COPY .env.example ./.env.example
COPY scripts ./scripts

# Puerto estandarizado
ENV PORT=8000
EXPOSE 8000

# Usuario no-root
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Comando de inicio
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
