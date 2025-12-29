#!/bin/bash

PROJECT_DIR="agriculture-iot"
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   DESPLIEGUE SEGURO - AGRICULTURE IoT API          ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Verificar que existe .env
if [ ! -f ".env" ]; then
    echo -e "${RED}❌ ERROR: Archivo .env no encontrado${NC}"
    echo -e "${YELLOW}Copiando desde .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}⚠️  IMPORTANTE: Editar .env y cambiar todos los valores${NC}"
    exit 1
fi

# Verificar SECRET_KEY
if grep -q "CHANGE_THIS" .env; then
    echo -e "${RED}❌ ERROR: .env contiene valores por defecto${NC}"
    echo -e "Edite el archivo .env y cambie todos los valores marcados con CHANGE_THIS"
    exit 1
fi

echo -e "\n${GREEN}[1/6] Verificando dependencias...${NC}"
command -v docker >/dev/null 2>&1 || {
    echo -e "${RED}Docker no instalado. Instalando...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
}

echo -e "\n${GREEN}[2/6] Instalando dependencias Python...${NC}"
pip install --upgrade pip --break-system-packages >/dev/null 2>&1
pip install -r requirements.txt --break-system-packages >/dev/null 2>&1

echo -e "\n${GREEN}[3/6] Creando directorios necesarios...${NC}"
mkdir -p logs database reports
touch logs/.gitkeep reports/.gitkeep

echo -e "\n${GREEN}[4/6] Levantando infraestructura principal...${NC}"
docker compose down -v --remove-orphans >/dev/null 2>&1
docker compose up -d --build

echo -e "\n${GREEN}[5/6] Esperando que la API esté lista...${NC}"
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✅ API lista${NC}"
        break
    fi
    echo -e "${YELLOW}Esperando API... ($attempt/$max_attempts)${NC}"
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}❌ ERROR: API no respondió en 60 segundos${NC}"
    docker compose logs api
    exit 1
fi

echo -e "\n${GREEN}[6/6] Levantando módulo IoT...${NC}"
if [ -d "$PROJECT_DIR" ]; then
    cd "$PROJECT_DIR"
    docker compose down -v --remove-orphans >/dev/null 2>&1
    docker compose up -d --build
    cd ..
else
    echo -e "${YELLOW}⚠️  Directorio $PROJECT_DIR no encontrado${NC}"
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}           ✅ DESPLIEGUE COMPLETADO                 ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "🌐 Frontend HTTPS: ${YELLOW}https://localhost${NC}"
echo -e "📡 API Backend:    ${YELLOW}http://localhost:8000${NC}"
echo -e "📖 Documentación:  ${YELLOW}http://localhost:8000/docs${NC}"
echo -e "🔑 Usuario admin:  ${YELLOW}superjefe / P@ssw0rd!${NC}"
echo -e "${BLUE}====================================================${NC}"

# Abrir navegador
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open https://localhost >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    open https://localhost >/dev/null 2>&1 &
fi
