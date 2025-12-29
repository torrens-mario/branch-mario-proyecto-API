#!/bin/bash

# ============================================================================
# SETUP.SH - Configuración Inicial del Proyecto
# ============================================================================
# Este script configura automáticamente todo lo necesario para ejecutar
# el proyecto después de clonarlo desde GitHub
# ============================================================================

set -e  # Salir si hay algún error

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         CONFIGURACIÓN INICIAL DEL PROYECTO                    ║"
echo "║         Agriculture IoT API - Asset Management                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# 1. VERIFICAR DEPENDENCIAS DEL SISTEMA
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "1️⃣  VERIFICANDO DEPENDENCIAS DEL SISTEMA"
echo "═══════════════════════════════════════════════════════════════"

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker no está instalado"
    echo "   Instalar desde: https://docs.docker.com/get-docker/"
    exit 1
fi
echo "  ✅ Docker: $(docker --version)"

# Verificar Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ ERROR: Docker Compose no está instalado"
    echo "   Instalar desde: https://docs.docker.com/compose/install/"
    exit 1
fi
echo "  ✅ Docker Compose: $(docker-compose --version)"

# Verificar OpenSSL (para generar certificados)
if ! command -v openssl &> /dev/null; then
    echo "❌ ERROR: OpenSSL no está instalado"
    echo "   Instalar: sudo apt-get install openssl (Linux)"
    echo "            brew install openssl (macOS)"
    exit 1
fi
echo "  ✅ OpenSSL: $(openssl version)"

# Verificar Python3 (para generar SECRET_KEY)
if ! command -v python3 &> /dev/null; then
    echo "⚠️  WARNING: Python3 no encontrado (usando fallback para SECRET_KEY)"
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

# Crear directorios necesarios
mkdir -p database
mkdir -p logs
mkdir -p frontend/certs
mkdir -p agriculture-iot/nginx_certs

echo "  ✅ database/"
echo "  ✅ logs/"
echo "  ✅ frontend/certs/"
echo "  ✅ agriculture-iot/nginx_certs/"
echo ""

# ============================================================================
# 3. GENERAR CERTIFICADOS SSL/TLS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "3️⃣  GENERANDO CERTIFICADOS SSL/TLS"
echo "═══════════════════════════════════════════════════════════════"

# Certificados para Frontend
if [ ! -f "frontend/certs/cert.pem" ]; then
    echo "  🔑 Generando certificados para frontend..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout frontend/certs/key.pem \
        -out frontend/certs/cert.pem \
        -subj "/C=ES/ST=Andalusia/L=Malaga/O=Development/OU=IT Department/CN=localhost" \
        2>/dev/null
    
    # Establecer permisos seguros
    chmod 600 frontend/certs/key.pem
    chmod 644 frontend/certs/cert.pem
    
    echo "  ✅ Certificados frontend generados"
    echo "     - frontend/certs/key.pem (clave privada)"
    echo "     - frontend/certs/cert.pem (certificado)"
else
    echo "  ℹ️  Certificados frontend ya existen (omitiendo)"
fi

# Certificados para IoT/MQTT
if [ ! -f "agriculture-iot/nginx_certs/server.crt" ]; then
    echo "  🔑 Generando certificados para servicio IoT..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout agriculture-iot/nginx_certs/server.key \
        -out agriculture-iot/nginx_certs/server.crt \
        -subj "/C=ES/ST=Andalusia/L=Malaga/O=Development/OU=IoT Department/CN=localhost" \
        2>/dev/null
    
    # Establecer permisos seguros
    chmod 600 agriculture-iot/nginx_certs/server.key
    chmod 644 agriculture-iot/nginx_certs/server.crt
    
    echo "  ✅ Certificados IoT generados"
    echo "     - agriculture-iot/nginx_certs/server.key (clave privada)"
    echo "     - agriculture-iot/nginx_certs/server.crt (certificado)"
else
    echo "  ℹ️  Certificados IoT ya existen (omitiendo)"
fi

echo ""
echo "  ⚠️  NOTA: Los certificados son autofirmados (solo para desarrollo)"
echo "            Para producción, usar certificados válidos de una CA"
echo ""

# ============================================================================
# 4. GENERAR ARCHIVO .env
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "4️⃣  CONFIGURANDO VARIABLES DE ENTORNO (.env)"
echo "═══════════════════════════════════════════════════════════════"

if [ -f ".env" ]; then
    echo "  ⚠️  Archivo .env ya existe"
    echo ""
    read -p "  ¿Desea sobrescribirlo? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "  ℹ️  Conservando .env existente"
        SKIP_ENV=true
    else
        SKIP_ENV=false
    fi
else
    SKIP_ENV=false
fi

if [ "$SKIP_ENV" = false ]; then
    echo "  📝 Creando archivo .env..."
    
    # Generar SECRET_KEY segura
    if [ "$PYTHON_AVAILABLE" = true ]; then
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        echo "  🔑 SECRET_KEY generada con Python (cryptographically secure)"
    else
        SECRET_KEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
        echo "  🔑 SECRET_KEY generada con OpenSSL (fallback)"
    fi
    
    # Crear archivo .env
    cat > .env << EOF
# ============================================================================
# CONFIGURACIÓN DE LA API - GENERADO AUTOMÁTICAMENTE
# ============================================================================
# Generado por setup.sh el $(date)
# ⚠️  NO subir este archivo al repositorio
# ============================================================================

# ===== SEGURIDAD (CRÍTICO) =====
SECRET_KEY=${SECRET_KEY}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# ===== BASE DE DATOS =====
DATABASE_URL=sqlite:///./database/data.db

# ===== CORS =====
# Dominios permitidos (separados por comas, sin espacios)
# Para producción, cambiar por dominios reales
ALLOWED_ORIGINS=https://localhost,https://127.0.0.1,http://localhost,http://127.0.0.1

# ===== APLICACIÓN =====
ENVIRONMENT=development
API_PORT=8000

# ===== LOGGING =====
LOG_LEVEL=INFO
LOG_FILE=logs/api.log
EOF

    # Establecer permisos seguros para .env
    chmod 600 .env
    
    echo "  ✅ Archivo .env creado con SECRET_KEY segura"
    echo "     Longitud de SECRET_KEY: ${#SECRET_KEY} caracteres"
fi

echo ""

# ============================================================================
# 5. INICIALIZAR BASE DE DATOS
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "5️⃣  INICIALIZANDO BASE DE DATOS"
echo "═══════════════════════════════════════════════════════════════"

if [ -f "database/data.db" ]; then
    echo "  ℹ️  Base de datos ya existe (database/data.db)"
    echo "     Tamaño: $(du -h database/data.db | cut -f1)"
else
    echo "  📊 Creando base de datos vacía..."
    touch database/data.db
    chmod 644 database/data.db
    echo "  ✅ Base de datos creada (database/data.db)"
    echo "     Se inicializará automáticamente al arrancar la API"
fi

echo ""

# ============================================================================
# 6. VERIFICAR ARCHIVOS DOCKER
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "6️⃣  VERIFICANDO CONFIGURACIÓN DOCKER"
echo "═══════════════════════════════════════════════════════════════"

if [ ! -f "docker-compose.yml" ]; then
    echo "  ❌ ERROR: docker-compose.yml no encontrado"
    exit 1
fi
echo "  ✅ docker-compose.yml encontrado"

if [ ! -f "Dockerfile" ]; then
    echo "  ❌ ERROR: Dockerfile no encontrado"
    exit 1
fi
echo "  ✅ Dockerfile encontrado"

if [ ! -f "requirements.txt" ]; then
    echo "  ❌ ERROR: requirements.txt no encontrado"
    exit 1
fi
echo "  ✅ requirements.txt encontrado"

echo ""

# ============================================================================
# 7. RESUMEN DE CONFIGURACIÓN
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "7️⃣  RESUMEN DE CONFIGURACIÓN"
echo "═══════════════════════════════════════════════════════════════"

echo ""
echo "📁 Estructura de archivos:"
echo "   ├── .env                              ✅ Configurado"
echo "   ├── database/data.db                  ✅ Creado"
echo "   ├── frontend/certs/                   ✅ Certificados generados"
echo "   │   ├── cert.pem"
echo "   │   └── key.pem"
echo "   └── agriculture-iot/nginx_certs/      ✅ Certificados generados"
echo "       ├── server.crt"
echo "       └── server.key"
echo ""

# ============================================================================
# 8. OPCIONES ADICIONALES
# ============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "8️⃣  OPCIONES ADICIONALES"
echo "═══════════════════════════════════════════════════════════════"

echo ""
read -p "¿Desea construir las imágenes Docker ahora? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "  🐳 Construyendo imágenes Docker..."
    docker-compose build --no-cache
    echo "  ✅ Imágenes Docker construidas"
fi

echo ""
read -p "¿Desea iniciar los servicios ahora? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "  🚀 Iniciando servicios..."
    docker-compose up -d
    echo ""
    echo "  ⏳ Esperando que los servicios estén listos..."
    sleep 5
    
    # Verificar estado de los servicios
    echo ""
    echo "  📊 Estado de los servicios:"
    docker-compose ps
    
    echo ""
    echo "  🔍 Verificando health check..."
    for i in {1..10}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            echo "  ✅ API respondiendo correctamente"
            break
        else
            if [ $i -eq 10 ]; then
                echo "  ⚠️  API no responde (verificar logs con: docker-compose logs api)"
            else
                echo "  ⏳ Esperando API... (intento $i/10)"
                sleep 3
            fi
        fi
    done
fi

# ============================================================================
# 9. INSTRUCCIONES FINALES
# ============================================================================
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           CONFIGURACIÓN COMPLETADA CON ÉXITO ✅               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "🎉 El proyecto está listo para usar"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 COMANDOS ÚTILES:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  🚀 Iniciar servicios:"
echo "     docker-compose up -d"
echo ""
echo "  🛑 Detener servicios:"
echo "     docker-compose down"
echo ""
echo "  📊 Ver estado de servicios:"
echo "     docker-compose ps"
echo ""
echo "  📝 Ver logs:"
echo "     docker-compose logs -f api"
echo ""
echo "  🔄 Reiniciar servicios:"
echo "     docker-compose restart"
echo ""
echo "  👤 Crear usuario administrador:"
echo "     python3 crear_admin.py"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 URLS DE ACCESO:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  📡 API Backend:          http://localhost:8000"
echo "  📚 Documentación API:    http://localhost:8000/docs"
echo "  ❤️  Health Check:         http://localhost:8000/health"
echo "  🌐 Frontend:             http://localhost:80"
echo "  🔒 Frontend HTTPS:       https://localhost:443"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚠️  IMPORTANTE:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  🔐 Los certificados SSL son autofirmados (tu navegador mostrará"
echo "     advertencia de seguridad - es normal en desarrollo)"
echo ""
echo "  🔑 SECRET_KEY generada automáticamente en .env"
echo "     Para producción, generar una nueva con:"
echo "     python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
echo ""
echo "  🚫 NUNCA subir archivos .env, .db, .key, .pem al repositorio"
echo ""
echo "  📖 Para más información, consultar README.md"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
