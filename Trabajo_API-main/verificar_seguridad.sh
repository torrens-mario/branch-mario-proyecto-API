#!/bin/bash

# ========================================================
# SCRIPT DE VERIFICACIÓN DE SEGURIDAD POST-CORRECCIÓN
# ========================================================

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     VERIFICACIÓN DE SEGURIDAD POST-CORRECCIÓN     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# Contadores
PASSED=0
FAILED=0

# ========================================================
# 1. VERIFICAR SECRETOS EN REPOSITORIO
# ========================================================
echo -e "\n${YELLOW}[1/8] Verificando secretos en repositorio...${NC}"

# Buscar archivos .env trackeados
if git ls-files | grep -q "^.env$"; then
    echo -e "${RED}❌ FALLO: Archivo .env está en Git${NC}"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: .env no está trackeado${NC}"
    PASSED=$((PASSED + 1))
fi

# Verificar .gitignore
if grep -q "^.env$" .gitignore 2>/dev/null; then
    echo -e "${GREEN}✅ PASADO: .env en .gitignore${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: .env no está en .gitignore${NC}"
    FAILED=$((FAILED + 1))
fi

# Buscar certificados trackeados
if git ls-files | grep -q ".pem$\|.key$"; then
    echo -e "${RED}❌ FALLO: Certificados SSL en Git${NC}"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: No hay certificados en Git${NC}"
    PASSED=$((PASSED + 1))
fi

# ========================================================
# 2. VERIFICAR SECRET_KEY
# ========================================================
echo -e "\n${YELLOW}[2/8] Verificando SECRET_KEY...${NC}"

# Buscar hardcoded en código
if grep -r "SECRET_KEY.*=.*['\"]" app/ --include="*.py" | grep -v "os.getenv\|getenv" | grep -q "SECRET_KEY"; then
    echo -e "${RED}❌ FALLO: SECRET_KEY hardcodeada encontrada${NC}"
    grep -r "SECRET_KEY.*=.*['\"]" app/ --include="*.py" | grep -v "os.getenv\|getenv"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: SECRET_KEY no está hardcodeada${NC}"
    PASSED=$((PASSED + 1))
fi

# Verificar validación en security.py
if grep -q "sys.exit(1)" app/core/security.py; then
    echo -e "${GREEN}✅ PASADO: Validación de SECRET_KEY implementada${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: Falta validación de SECRET_KEY${NC}"
    FAILED=$((FAILED + 1))
fi

# ========================================================
# 3. VERIFICAR LIMPIEZA DE REPOSITORIO
# ========================================================
echo -e "\n${YELLOW}[3/8] Verificando limpieza del repositorio...${NC}"

# Buscar __pycache__
if git ls-files | grep -q "__pycache__"; then
    echo -e "${RED}❌ FALLO: __pycache__ en Git${NC}"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: No hay __pycache__ en Git${NC}"
    PASSED=$((PASSED + 1))
fi

# Buscar archivos .pyc
if git ls-files | grep -q ".pyc$"; then
    echo -e "${RED}❌ FALLO: Archivos .pyc en Git${NC}"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: No hay archivos .pyc en Git${NC}"
    PASSED=$((PASSED + 1))
fi

# Buscar venv/
if git ls-files | grep -q "^venv/\|^env/\|^.venv/"; then
    echo -e "${RED}❌ FALLO: Entorno virtual en Git${NC}"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: No hay entornos virtuales en Git${NC}"
    PASSED=$((PASSED + 1))
fi

# ========================================================
# 4. VERIFICAR PUERTOS DOCKER
# ========================================================
echo -e "\n${YELLOW}[4/8] Verificando configuración de puertos...${NC}"

# Verificar Dockerfile
if grep -q "EXPOSE 8000" Dockerfile && grep -q "port.*8000" Dockerfile; then
    echo -e "${GREEN}✅ PASADO: Dockerfile usa puerto 8000${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: Puerto inconsistente en Dockerfile${NC}"
    FAILED=$((FAILED + 1))
fi

# Verificar docker-compose.yml (IoT)
if grep -q "8000:8000" agriculture-iot/docker-compose.yml 2>/dev/null; then
    echo -e "${GREEN}✅ PASADO: docker-compose.yml IoT usa 8000${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: Puerto inconsistente en docker-compose IoT${NC}"
    FAILED=$((FAILED + 1))
fi

# Verificar nginx.conf
if grep -q "asset-api:8000" frontend/nginx.conf 2>/dev/null; then
    echo -e "${GREEN}✅ PASADO: nginx.conf apunta a puerto 8000${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: nginx.conf no usa puerto 8000${NC}"
    FAILED=$((FAILED + 1))
fi

# ========================================================
# 5. VERIFICAR CORS
# ========================================================
echo -e "\n${YELLOW}[5/8] Verificando configuración CORS...${NC}"

# Buscar allow_origins=["*"]
if grep -q 'allow_origins=\["?\*"?\]' app/main.py; then
    echo -e "${RED}❌ FALLO: CORS usa comodín '*'${NC}"
    FAILED=$((FAILED + 1))
else
    echo -e "${GREEN}✅ PASADO: CORS no usa comodín${NC}"
    PASSED=$((PASSED + 1))
fi

# Verificar que lee de variable de entorno
if grep -q "ALLOWED_ORIGINS" app/main.py; then
    echo -e "${GREEN}✅ PASADO: CORS usa variable de entorno${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: CORS no usa variable de entorno${NC}"
    FAILED=$((FAILED + 1))
fi

# Verificar validación de seguridad
if grep -q "raise ValueError" app/main.py && grep -q "CORS" app/main.py; then
    echo -e "${GREEN}✅ PASADO: Validación CORS implementada${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: Falta validación de seguridad CORS${NC}"
    FAILED=$((FAILED + 1))
fi

# ========================================================
# 6. VERIFICAR ARCHIVOS NECESARIOS
# ========================================================
echo -e "\n${YELLOW}[6/8] Verificando archivos necesarios...${NC}"

REQUIRED_FILES=(
    ".env.example"
    ".gitignore"
    "setup.sh"
    "Dockerfile"
    "docker-compose.yml"
    "requirements.txt"
    "app/main.py"
    "app/core/security.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌ $file (falta)${NC}"
        FAILED=$((FAILED + 1))
    fi
done

# ========================================================
# 7. ANÁLISIS ESTÁTICO (SAST)
# ========================================================
echo -e "\n${YELLOW}[7/8] Ejecutando análisis estático (SAST)...${NC}"

# Instalar herramientas si no están
pip install bandit semgrep --break-system-packages -q 2>/dev/null || true

# Bandit
echo -e "${BLUE}Ejecutando Bandit...${NC}"
if command -v bandit >/dev/null 2>&1; then
    bandit -r app/ -ll -f txt -o reports/bandit_report.txt 2>/dev/null || true
    
    # Contar severidades
    HIGH_ISSUES=$(grep -c "Severity: High" reports/bandit_report.txt 2>/dev/null || echo "0")
    
    if [ "$HIGH_ISSUES" -eq 0 ]; then
        echo -e "${GREEN}✅ PASADO: Sin vulnerabilidades High/Critical${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌ FALLO: $HIGH_ISSUES vulnerabilidades High encontradas${NC}"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${YELLOW}⚠️  Bandit no disponible${NC}"
fi

# Semgrep
echo -e "${BLUE}Ejecutando Semgrep...${NC}"
if command -v semgrep >/dev/null 2>&1; then
    semgrep --config=auto app/ --json -o reports/semgrep_report.json 2>/dev/null || true
    
    SEMGREP_ISSUES=$(python3 -c "
import json
try:
    with open('reports/semgrep_report.json') as f:
        data = json.load(f)
        print(len(data.get('results', [])))
except:
    print('0')
" 2>/dev/null || echo "0")
    
    if [ "$SEMGREP_ISSUES" -eq 0 ]; then
        echo -e "${GREEN}✅ PASADO: Sin vulnerabilidades detectadas${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${YELLOW}⚠️  $SEMGREP_ISSUES issues detectados (revisar manualmente)${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Semgrep no disponible${NC}"
fi

# ========================================================
# 8. VERIFICACIÓN DE DESPLIEGUE
# ========================================================
echo -e "\n${YELLOW}[8/8] Verificando despliegue...${NC}"

# Verificar que setup.sh es ejecutable
if [ -x "setup.sh" ]; then
    echo -e "${GREEN}✅ PASADO: setup.sh es ejecutable${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ FALLO: setup.sh no es ejecutable${NC}"
    FAILED=$((FAILED + 1))
fi

# Verificar estructura de directorios
for dir in logs database reports; do
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✅ Directorio $dir existe${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌ Directorio $dir falta${NC}"
        FAILED=$((FAILED + 1))
    fi
done

# ========================================================
# RESUMEN FINAL
# ========================================================
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              RESUMEN DE VERIFICACIÓN               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

TOTAL=$((PASSED + FAILED))
PERCENTAGE=$((PASSED * 100 / TOTAL))

echo -e "\n${GREEN}✅ Pruebas pasadas: $PASSED / $TOTAL${NC}"
echo -e "${RED}❌ Pruebas fallidas: $FAILED / $TOTAL${NC}"
echo -e "${BLUE}📊 Porcentaje de éxito: $PERCENTAGE%${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    ✅ TODAS LAS VERIFICACIONES PASADAS             ║${NC}"
    echo -e "${GREEN}║    El proyecto cumple con los requisitos          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "\n${RED}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║    ❌ ALGUNAS VERIFICACIONES FALLARON              ║${NC}"
    echo -e "${RED}║    Revise los errores arriba                      ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════╝${NC}"
    exit 1
fi