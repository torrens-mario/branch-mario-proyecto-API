#!/bin/bash

# Script para solucionar problema de SECRET_KEY en Docker

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    SOLUCIONADOR DE PROBLEMA SECRET_KEY            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# Verificar que estamos en la raíz del proyecto
if [ ! -f "app/main.py" ]; then
    echo -e "${RED}❌ ERROR: Ejecuta este script desde la raíz del proyecto (Trabajo_API-main/)${NC}"
    exit 1
fi

# 1. Crear/Verificar .env
echo -e "\n${YELLOW}[1/5] Verificando archivo .env...${NC}"

if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creando archivo .env...${NC}"
    
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    
    cat > .env << EOF
# Configuración de la API
SECRET_KEY=${SECRET_KEY}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Base de datos
DATABASE_URL=sqlite:///./database/data.db

# API
API_PORT=8000
ENVIRONMENT=production
DEBUG=False

# CORS
ALLOWED_ORIGINS=https://localhost,https://127.0.0.1,https://localhost:443
EOF
    
    echo -e "${GREEN}✅ Archivo .env creado${NC}"
    echo -e "${GREEN}SECRET_KEY: ${SECRET_KEY}${NC}"
else
    echo -e "${GREEN}✅ Archivo .env existe${NC}"
    
    # Verificar que tiene SECRET_KEY
    if ! grep -q "SECRET_KEY=" .env; then
        echo -e "${RED}❌ .env no tiene SECRET_KEY, añadiendo...${NC}"
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        echo "SECRET_KEY=${SECRET_KEY}" >> .env
    fi
    
    # Verificar que no es el valor por defecto
    if grep -q "SECRET_KEY=CHANGE_THIS" .env; then
        echo -e "${RED}❌ SECRET_KEY tiene valor por defecto, regenerando...${NC}"
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=${SECRET_KEY}/" .env
    fi
fi

# Mostrar SECRET_KEY
CURRENT_SECRET=$(grep "SECRET_KEY=" .env | cut -d'=' -f2)
echo -e "SECRET_KEY actual: ${GREEN}${CURRENT_SECRET}${NC}"

# 2. Actualizar docker-compose.yml
echo -e "\n${YELLOW}[2/5] Actualizando docker-compose.yml...${NC}"

if [ ! -f "agriculture-iot/docker-compose.yml.backup" ]; then
    cp agriculture-iot/docker-compose.yml agriculture-iot/docker-compose.yml.backup
    echo -e "${GREEN}✅ Backup creado${NC}"
fi

# Verificar si ya tiene env_file
if grep -q "env_file:" agriculture-iot/docker-compose.yml; then
    echo -e "${GREEN}✅ docker-compose.yml ya está configurado${NC}"
else
    echo -e "${YELLOW}Añadiendo env_file a docker-compose.yml...${NC}"
    
    # Insertar env_file después de ports
    sed -i '/ports:/a\    env_file:\n      - ../.env' agriculture-iot/docker-compose.yml
    
    echo -e "${GREEN}✅ docker-compose.yml actualizado${NC}"
fi

# 3. Crear directorio database si no existe
echo -e "\n${YELLOW}[3/5] Verificando directorio database...${NC}"
mkdir -p database
touch database/.gitkeep
echo -e "${GREEN}✅ Directorio database listo${NC}"

# 4. Detener y reconstruir contenedores
echo -e "\n${YELLOW}[4/5] Reconstruyendo contenedores...${NC}"

cd agriculture-iot

# Detener todo
docker compose down -v 2>/dev/null

# Reconstruir sin caché
echo -e "${YELLOW}Reconstruyendo imagen (esto puede tardar un minuto)...${NC}"
docker compose build --no-cache asset-api

# Levantar
docker compose up -d

cd ..

# 5. Esperar y verificar
echo -e "\n${YELLOW}[5/5] Esperando que la API inicie...${NC}"

for i in {1..30}; do
    if docker exec asset-api curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✅ API funcionando correctamente${NC}"
        break
    fi
    echo -e "${YELLOW}Esperando... ($i/30)${NC}"
    sleep 2
done

# Verificar resultado
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              VERIFICACIÓN FINAL                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# Test de health
HEALTH=$(curl -s http://localhost:8000/health 2>/dev/null)
if echo "$HEALTH" | grep -q "ok"; then
    echo -e "${GREEN}✅ Health check: OK${NC}"
    echo -e "Respuesta: $HEALTH"
else
    echo -e "${RED}❌ Health check: FALLO${NC}"
    echo -e "\n${YELLOW}Últimos logs de la API:${NC}"
    docker logs asset-api --tail 20
fi

# Test de login
echo -e "\n${YELLOW}Probando login...${NC}"
LOGIN_TEST=$(curl -s -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=superjefe&password=P@ssw0rd!" 2>/dev/null)

if echo "$LOGIN_TEST" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Login: OK (token recibido)${NC}"
else
    echo -e "${RED}❌ Login: FALLO${NC}"
    echo -e "Respuesta: ${LOGIN_TEST:0:200}"
fi

# Resumen
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    RESUMEN                         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}Archivo .env:${NC}"
echo -e "  Ubicación: $(pwd)/.env"
echo -e "  SECRET_KEY: ${CURRENT_SECRET:0:20}..."

echo -e "\n${GREEN}URLs:${NC}"
echo -e "  API Docs:  ${YELLOW}http://localhost:8000/docs${NC}"
echo -e "  Frontend:  ${YELLOW}https://localhost${NC}"

echo -e "\n${GREEN}Comandos útiles:${NC}"
echo -e "  Ver logs:     ${YELLOW}docker logs asset-api -f${NC}"
echo -e "  Reiniciar:    ${YELLOW}docker restart asset-api${NC}"
echo -e "  Diagnóstico:  ${YELLOW}./diagnostico_api.sh${NC}"

echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}\n"