#!/bin/bash

# Script de diagnóstico de la API

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         DIAGNÓSTICO DE LA API                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# 1. Verificar que el contenedor está corriendo
echo -e "\n${YELLOW}[1/6] Verificando contenedor de la API...${NC}"
if docker ps | grep -q "asset-api"; then
    echo -e "${GREEN}✅ Contenedor asset-api está corriendo${NC}"
else
    echo -e "${RED}❌ Contenedor asset-api NO está corriendo${NC}"
    echo -e "${YELLOW}Iniciando contenedor...${NC}"
    cd agriculture-iot && docker compose up -d asset-api && cd ..
    sleep 5
fi

# 2. Verificar puerto 8000
echo -e "\n${YELLOW}[2/6] Verificando puerto 8000...${NC}"
if docker exec asset-api curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API responde en puerto 8000 (interno)${NC}"
else
    echo -e "${RED}❌ API NO responde en puerto interno${NC}"
    echo -e "${YELLOW}Logs del contenedor:${NC}"
    docker logs asset-api --tail 20
fi

if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API accesible desde host en puerto 8000${NC}"
else
    echo -e "${RED}❌ API NO accesible desde host${NC}"
fi

# 3. Verificar endpoint /health
echo -e "\n${YELLOW}[3/6] Probando endpoint /health...${NC}"
HEALTH_RESPONSE=$(curl -s http://localhost:8000/health)
echo -e "Respuesta: ${GREEN}$HEALTH_RESPONSE${NC}"

# 4. Verificar endpoint /auth/login con credenciales de prueba
echo -e "\n${YELLOW}[4/6] Probando endpoint /auth/login...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=superjefe&password=P@ssw0rd!")

echo -e "Respuesta (primeros 200 caracteres):"
echo -e "${GREEN}${LOGIN_RESPONSE:0:200}${NC}"

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Login exitoso - Token recibido${NC}"
else
    echo -e "${RED}❌ Login falló${NC}"
    echo -e "Respuesta completa:"
    echo "$LOGIN_RESPONSE" | jq . 2>/dev/null || echo "$LOGIN_RESPONSE"
fi

# 5. Verificar NGINX
echo -e "\n${YELLOW}[5/6] Verificando NGINX (frontend)...${NC}"
if docker ps | grep -q "agriculture-dashboard"; then
    echo -e "${GREEN}✅ Contenedor NGINX está corriendo${NC}"
    
    # Verificar proxy /api/
    PROXY_TEST=$(curl -sk https://localhost/api/health 2>&1)
    if echo "$PROXY_TEST" | grep -q "ok"; then
        echo -e "${GREEN}✅ Proxy /api/ funciona correctamente${NC}"
    else
        echo -e "${RED}❌ Proxy /api/ NO funciona${NC}"
        echo "Respuesta: $PROXY_TEST"
    fi
else
    echo -e "${RED}❌ Contenedor NGINX NO está corriendo${NC}"
fi

# 6. Verificar logs de errores
echo -e "\n${YELLOW}[6/6] Últimos logs de la API...${NC}"
docker logs asset-api --tail 10

# Resumen
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              RESUMEN DEL DIAGNÓSTICO               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}URLs a probar:${NC}"
echo -e "  API directa:  ${GREEN}http://localhost:8000/docs${NC}"
echo -e "  Frontend:     ${GREEN}https://localhost${NC}"
echo -e "  Health check: ${GREEN}http://localhost:8000/health${NC}"

echo -e "\n${YELLOW}Comandos útiles:${NC}"
echo -e "  Ver logs:     ${GREEN}docker logs asset-api -f${NC}"
echo -e "  Reiniciar:    ${GREEN}docker restart asset-api${NC}"
echo -e "  Shell:        ${GREEN}docker exec -it asset-api /bin/bash${NC}"

echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}\n"