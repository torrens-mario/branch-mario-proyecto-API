#!/bin/bash

# ============================================================================
# SETUP.SH - Configuración e Inicio Completo del Proyecto
# ============================================================================
# Este script configura TODO y arranca TODOS los servicios usando
# el docker-compose de agriculture-iot que incluye:
# - API Backend
# - Frontend Web  
# - Servicios IoT (MQTT, Gateway, Sensores)
# ============================================================================

set -e  # Salir si hay algún error

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         CONFIGURACIÓN E INICIO COMPLETO DEL PROYECTO          ║"
echo "║         Agriculture IoT API - Asset Management                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# DETECTAR VERSIÓN DE DOCKER COMPOSE
# ============================================================================
if docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
    COMPOSE_VERSION="v2 (plugin)"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
    COMPOSE_VERSION="v1 (standalone)"
else
    DOCKER_COMPOSE=""
    COMPOSE_VERSION="no instalado"
fi

# ============================================================================
# 1. VERIFICAR DEPENDENCIAS DEL SISTEMA
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "1️⃣  VERIFICANDO DEPENDENCIAS DEL SISTEMA"
echo "═══════════════════════════════════════════════════════════════"

if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker no está instalado"
    exit 1
fi
echo "  ✅ Docker: $(docker --version)"

if [ -z "$DOCKER_COMPOSE" ]; then
    echo "❌ ERROR: Docker Compose no está instalado"
    exit 1
fi
echo "  ✅ Docker Compose: $COMPOSE_VERSION"

if ! command -v openssl &> /dev/null; then
    echo "❌ ERROR: OpenSSL no está instalado"
    exit 1
fi
echo "  ✅ OpenSSL: $(openssl version)"

if ! command -v python3 &> /dev/null; then
    echo "⚠️  WARNING: Python3 no encontrado"
    PYTHON_AVAILABLE=false
else
    echo "  ✅ Python3: $(python3 --version)"
    PYTHON_AVAILABLE=true
fi

echo ""

# ============================================================================
# 2. CREAR ESTRUCTURA DE DIRECTORIOS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "2️⃣  CREANDO ESTRUCTURA DE DIRECTORIOS"
echo "═══════════════════════════════════════════════════════════════"

mkdir -p database logs frontend/certs agriculture-iot/nginx_certs

echo "  ✅ database/"
echo "  ✅ logs/"
echo "  ✅ frontend/certs/"
echo "  ✅ agriculture-iot/nginx_certs/"
echo ""

# ============================================================================
# 3. CONFIGURAR PERMISOS CORRECTOS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "3️⃣  CONFIGURANDO PERMISOS (CRÍTICO)"
echo "═══════════════════════════════════════════════════════════════"

# Permisos para database y logs (necesitan escritura)
chmod 777 database/ logs/ 2>/dev/null || sudo chmod 777 database/ logs/
touch database/data.db
chmod 666 database/data.db 2>/dev/null || sudo chmod 666 database/data.db

echo "  ✅ Permisos configurados para database/ y logs/"
echo ""

# ============================================================================
# 4. GENERAR CERTIFICADOS SSL/TLS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "4️⃣  GENERANDO CERTIFICADOS SSL/TLS"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -f "frontend/certs/cert.pem" ]; then
    echo "  🔑 Generando certificados para frontend..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout frontend/certs/key.pem \
        -out frontend/certs/cert.pem \
        -subj "/C=ES/ST=Andalusia/L=Malaga/O=Development/CN=localhost" \
        2>/dev/null
    echo "  ✅ Certificados frontend generados"
else
    echo "  ℹ️  Certificados frontend ya existen"
fi

# CRÍTICO: Configurar permisos de certificados del frontend
chmod 644 frontend/certs/key.pem 2>/dev/null || sudo chmod 644 frontend/certs/key.pem
chmod 644 frontend/certs/cert.pem 2>/dev/null || sudo chmod 644 frontend/certs/cert.pem
echo "  ✅ Permisos de certificados frontend configurados"

if [ ! -f "agriculture-iot/nginx_certs/server.crt" ]; then
    echo "  🔑 Generando certificados para servicio IoT..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout agriculture-iot/nginx_certs/server.key \
        -out agriculture-iot/nginx_certs/server.crt \
        -subj "/C=ES/ST=Andalusia/L=Malaga/O=Development/CN=localhost" \
        2>/dev/null
    echo "  ✅ Certificados IoT generados"
else
    echo "  ℹ️  Certificados IoT ya existen"
fi

# CRÍTICO: Configurar permisos de certificados IoT
chmod 644 agriculture-iot/nginx_certs/server.key 2>/dev/null || sudo chmod 644 agriculture-iot/nginx_certs/server.key
chmod 644 agriculture-iot/nginx_certs/server.crt 2>/dev/null || sudo chmod 644 agriculture-iot/nginx_certs/server.crt
echo "  ✅ Permisos de certificados IoT configurados"

echo ""

# ============================================================================
# 5. GENERAR ARCHIVO .env
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "5️⃣  CONFIGURANDO VARIABLES DE ENTORNO (.env)"
echo "═══════════════════════════════════════════════════════════════"

if [ -f ".env" ]; then
    echo "  ℹ️  Archivo .env ya existe (conservando)"
else
    echo "  📝 Creando archivo .env..."
    
    if [ "$PYTHON_AVAILABLE" = true ]; then
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    else
        SECRET_KEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    fi
    
    cat > .env << EOF
# Configuración generada por setup.sh el $(date)
SECRET_KEY=${SECRET_KEY}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
DATABASE_URL=sqlite:///./database/data.db
ALLOWED_ORIGINS=https://localhost,https://127.0.0.1,http://localhost,http://127.0.0.1
ENVIRONMENT=development
API_PORT=8000
LOG_LEVEL=INFO
LOG_FILE=logs/api.log
EOF

    chmod 600 .env
    echo "  ✅ Archivo .env creado"
fi

echo ""

# ============================================================================
# 6. DETENER SERVICIOS ANTERIORES
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "6️⃣  DETENIENDO SERVICIOS ANTERIORES (si existen)"
echo "═══════════════════════════════════════════════════════════════"

# Detener docker-compose de la raíz si existe
$DOCKER_COMPOSE down 2>/dev/null || true

# Detener servicios de agriculture-iot
cd agriculture-iot && $DOCKER_COMPOSE down 2>/dev/null || true && cd ..

echo "  ✅ Servicios anteriores detenidos"
echo ""

# ============================================================================
# 7. CONSTRUIR E INICIAR TODOS LOS SERVICIOS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "7️⃣  CONSTRUYENDO E INICIANDO TODOS LOS SERVICIOS"
echo "═══════════════════════════════════════════════════════════════"

cd agriculture-iot

echo "  🐳 Construyendo todas las imágenes Docker..."
echo "     (esto puede tardar varios minutos la primera vez)"
$DOCKER_COMPOSE build --no-cache

echo ""
echo "  🚀 Iniciando todos los servicios..."
echo "     - API Backend"
echo "     - Frontend Web"
echo "     - MQTT Broker"
echo "     - MQTT Gateway"
echo "     - Sensores IoT"

$DOCKER_COMPOSE up -d

cd ..

echo ""
echo "  ✅ Todos los servicios iniciados"
echo ""

# ============================================================================
# 8. ESPERAR A QUE LOS SERVICIOS ESTÉN LISTOS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "8️⃣  ESPERANDO A QUE LOS SERVICIOS ESTÉN LISTOS"
echo "═══════════════════════════════════════════════════════════════"

echo "  ⏳ Esperando API (puede tardar 30-60 segundos en la primera ejecución)..."
API_READY=false
for i in {1..30}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "  ✅ API respondiendo correctamente"
        API_READY=true
        break
    else
        if [ $i -eq 30 ]; then
            echo "  ⚠️  API tardó más de lo esperado"
            echo "     Verificar logs: cd agriculture-iot && $DOCKER_COMPOSE logs asset-api"
        else
            sleep 2
        fi
    fi
done

echo ""
echo "  ⏳ Esperando Frontend (puede tardar 10-20 segundos)..."
FRONTEND_READY=false
for i in {1..20}; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:80 | grep -q "301\|200"; then
        echo "  ✅ Frontend respondiendo correctamente"
        FRONTEND_READY=true
        break
    else
        if [ $i -eq 20 ]; then
            echo "  ⚠️  Frontend tardó más de lo esperado"
            echo "     Verificar logs: cd agriculture-iot && $DOCKER_COMPOSE logs frontend"
        else
            sleep 1
        fi
    fi
done

echo ""

# ============================================================================
# 9. MOSTRAR ESTADO DE SERVICIOS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "9️⃣  ESTADO DE TODOS LOS SERVICIOS"
echo "═══════════════════════════════════════════════════════════════"

echo ""
cd agriculture-iot && $DOCKER_COMPOSE ps && cd ..

echo ""

# ============================================================================
# 10. VERIFICACIÓN FINAL
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "🔟 VERIFICACIÓN FINAL"
echo "═══════════════════════════════════════════════════════════════"

echo ""
ERRORS=0

if [ "$API_READY" = true ]; then
    echo "  ✅ API Backend: Funcionando"
else
    echo "  ❌ API Backend: No responde"
    ERRORS=$((ERRORS + 1))
fi

if [ "$FRONTEND_READY" = true ]; then
    echo "  ✅ Frontend: Funcionando"
else
    echo "  ❌ Frontend: No responde"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# ============================================================================
# 11. INSTRUCCIONES FINALES
# ============================================================================

if [ $ERRORS -eq 0 ]; then
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║           SISTEMA COMPLETAMENTE INICIADO ✅                   ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
else
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║        SISTEMA INICIADO CON ALGUNOS PROBLEMAS ⚠️              ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
fi

echo ""
echo "🎉 Servicios iniciados"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 URLS DE ACCESO:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  📡 API Backend:           http://localhost:8000"
echo "  📚 Documentación API:     http://localhost:8000/docs"
echo "  ❤️  Health Check:          http://localhost:8000/health"
echo ""
echo "  🌐 Frontend (Dashboard):  http://localhost:80  (redirige a HTTPS)"
echo "  🔒 Frontend HTTPS:        https://localhost:443"
echo ""
echo "  🔌 MQTT Broker:           mqtt://localhost:1883"
echo "  🌐 MQTT WebSocket:        ws://localhost:9001"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "👤 CREDENCIALES DE ACCESO:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Usuario:  superjefe"
echo "  Password: P@ssw0rd!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 VERIFICAR SERVICIOS MANUALMENTE:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  📡 API Health Check:"
echo "     curl http://localhost:8000/health"
echo ""
echo "  🌐 Frontend:"
echo "     curl -I http://localhost:80"
echo ""
echo "  🔌 MQTT Broker (requiere mosquitto_sub instalado):"
echo "     mosquitto_sub -h localhost -p 1883 -t 'sensors/#' -v"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚠️  RECORDATORIOS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  🔐 Certificados SSL autofirmados"
echo "     → Tu navegador mostrará advertencia de seguridad"
echo "     → Es normal en desarrollo, acepta la advertencia"
echo ""
echo "  📊 Los sensores IoT simulan datos automáticamente cada 30 segundos"
echo "     → Temperature sensors: temp-sensor-001, temp-sensor-002"
echo "     → Soil moisture sensors: soil-sensor-001, soil-sensor-002"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✨ ¡Todo listo! Pasos siguientes:"
echo ""
echo "   1. Abre https://localhost en tu navegador"
echo "   2. Acepta la advertencia del certificado SSL"
echo "   3. Inicia sesión con: superjefe / P@ssw0rd!"
echo "   4. Explora el dashboard y la documentación API"
echo ""

if [ $ERRORS -gt 0 ]; then
    echo "⚠️  NOTA: Algunos servicios tuvieron problemas al iniciar."
    echo "   Revisa los logs con los comandos indicados arriba."
    echo ""
fi
