#!/bin/bash
# Script de Verificación de Integridad - Paso 7
# A08:2021 - Software & Data Integrity Failures

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}VERIFICACIÓN DE INTEGRIDAD - PASO 7${NC}"
echo -e "${CYAN}A08:2021 - Software & Data Integrity Failures${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

ERRORS=0

# 1. Verificar pip-audit
echo -e "${YELLOW}1. Escaneando vulnerabilidades en dependencias Python...${NC}"
if command -v pip-audit &> /dev/null; then
    cd backend
    pip-audit -r requirements.txt 2>&1 | tee /tmp/pip-audit.log
    
    if grep -q "No known vulnerabilities found" /tmp/pip-audit.log; then
        echo -e "${GREEN}✓ Sin vulnerabilidades conocidas en dependencias${NC}"
    else
        echo -e "${RED}✗ Se encontraron vulnerabilidades. Revisar output arriba.${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    cd ..
else
    echo -e "${YELLOW}⚠ pip-audit no instalado. Instalando...${NC}"
    pip install pip-audit
    echo -e "${CYAN}→ Ejecute este script nuevamente${NC}"
    exit 1
fi
echo ""

# 2. Verificar SRI de Chart.js
echo -e "${YELLOW}2. Verificando integridad de Chart.js (SRI)...${NC}"
CHART_HASH=$(openssl dgst -sha384 -binary frontend/js/vendor/chart.min.js | openssl base64 -A)
EXPECTED_HASH="e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"

if [ "$CHART_HASH" == "$EXPECTED_HASH" ]; then
    echo -e "${GREEN}✓ Chart.js: Integridad verificada${NC}"
    echo -e "${CYAN}  SHA-384: ${CHART_HASH}${NC}"
else
    echo -e "${RED}✗ Chart.js: Integridad comprometida${NC}"
    echo -e "${RED}  Esperado: ${EXPECTED_HASH}${NC}"
    echo -e "${RED}  Actual:   ${CHART_HASH}${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 3. Verificar checksum de vulnerabilities.json
echo -e "${YELLOW}3. Verificando checksum de vulnerabilities.json...${NC}"
if [ -f "backend/vulnerabilities.json" ]; then
    CURRENT_CHECKSUM=$(sha256sum backend/vulnerabilities.json | awk '{print $1}')
    
    if [ -f "backend/vulnerabilities.json.sha256" ]; then
        STORED_CHECKSUM=$(cat backend/vulnerabilities.json.sha256)
        
        if [ "$CURRENT_CHECKSUM" == "$STORED_CHECKSUM" ]; then
            echo -e "${GREEN}✓ vulnerabilities.json: Integridad verificada${NC}"
            echo -e "${CYAN}  SHA-256: ${CURRENT_CHECKSUM}${NC}"
        else
            echo -e "${RED}✗ vulnerabilities.json: Checksum no coincide${NC}"
            echo -e "${RED}  Almacenado: ${STORED_CHECKSUM}${NC}"
            echo -e "${RED}  Actual:     ${CURRENT_CHECKSUM}${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}⚠ No existe archivo .sha256. Generando...${NC}"
        echo "$CURRENT_CHECKSUM" > backend/vulnerabilities.json.sha256
        echo -e "${GREEN}✓ Checksum generado y guardado${NC}"
    fi
else
    echo -e "${RED}✗ vulnerabilities.json no encontrado${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 4. Verificar digests de Docker images
echo -e "${YELLOW}4. Verificando digests de imágenes Docker...${NC}"
if command -v docker &> /dev/null; then
    echo -e "${CYAN}Imágenes usadas:${NC}"
    docker images --digests | grep -E "python|nginx|alpine" | head -3
    echo -e "${GREEN}✓ Digests listados arriba (verificar manualmente en producción)${NC}"
else
    echo -e "${YELLOW}⚠ Docker no disponible${NC}"
fi
echo ""

# 5. Listar checksums de archivos críticos
echo -e "${YELLOW}5. Generando checksums de archivos críticos...${NC}"
echo -e "${CYAN}Backend:${NC}"
sha256sum backend/main.py | awk '{print "  main.py: " $1}'
sha256sum backend/requirements.txt | awk '{print "  requirements.txt: " $1}'

echo -e "${CYAN}Frontend:${NC}"
sha256sum frontend/dashboard.html | awk '{print "  dashboard.html: " $1}'
sha256sum frontend/js/dashboard.js | awk '{print "  dashboard.js: " $1}'
sha256sum frontend/js/utils.js | awk '{print "  utils.js: " $1}'
echo ""

# Resumen
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ VERIFICACIÓN COMPLETA: Sin problemas detectados${NC}"
    echo -e "${GREEN}  A08:2021 - Software & Data Integrity: ✓ PASS${NC}"
else
    echo -e "${RED}✗ VERIFICACIÓN FALLIDA: ${ERRORS} problema(s) detectado(s)${NC}"
    echo -e "${RED}  A08:2021 - Software & Data Integrity: ✗ FAIL${NC}"
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Para más información, revisar:${NC}"
echo -e "  📖 SBOM.md - Software Bill of Materials completo"
echo -e "  📖 README_PASO7.md - Documentación de seguridad"
echo ""

exit $ERRORS

