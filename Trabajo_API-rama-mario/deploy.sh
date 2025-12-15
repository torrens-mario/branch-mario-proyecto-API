#!/usr/bin/env bash
# ==============================================
# Script de Despliegue - Inventario de Activos IT
# ==============================================

set -e  # Salir si hay error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de log
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Banner
echo -e "${BLUE}"
echo "================================================"
echo "  Sistema de Inventario de Activos IT"
echo "  Script de Despliegue v1.0"
echo "================================================"
echo -e "${NC}"

# Verificar Docker
log_info "Verificando Docker..."
if ! command -v docker &> /dev/null; then
    log_error "Docker no está instalado"
    exit 1
fi
log_success "Docker instalado: $(docker --version)"

# Verificar Docker Compose
log_info "Verificando Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose no está instalado"
    exit 1
fi
log_success "Docker Compose instalado: $(docker-compose --version)"

# Verificar archivo .env
log_info "Verificando configuración..."
if [ ! -f .env ]; then
    log_warning ".env no encontrado, creando desde .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        log_success "Archivo .env creado"
        log_warning "IMPORTANTE: Edita .env y cambia los valores por defecto"
        read -p "¿Deseas editar .env ahora? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ${EDITOR:-nano} .env
        fi
    else
        log_error ".env.example no encontrado"
        exit 1
    fi
fi

# Verificar estructura del frontend
log_info "Verificando estructura del frontend..."
if [ ! -d frontend ]; then
    log_error "Directorio frontend/ no encontrado"
    log_info "Por favor, crea el directorio y copia los archivos HTML/CSS/JS"
    exit 1
fi

required_files=(
    "frontend/index.html"
    "frontend/register.html"
    "frontend/dashboard.html"
    "frontend/Dockerfile"
    "frontend/nginx.conf"
)

missing_files=0
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        log_error "Archivo faltante: $file"
        missing_files=$((missing_files + 1))
    fi
done

if [ $missing_files -gt 0 ]; then
    log_error "Faltan $missing_files archivos del frontend"
    exit 1
fi
log_success "Estructura del frontend verificada"

# Modo de despliegue
echo ""
log_info "Selecciona el modo de despliegue:"
echo "  1) Desarrollo (con hot reload)"
echo "  2) Producción"
echo ""
read -p "Opción [1-2]: " deploy_mode

# Detener servicios existentes
log_info "Deteniendo servicios existentes..."
docker-compose down 2>/dev/null || true
log_success "Servicios detenidos"

# Construir imágenes
log_info "Construyendo imágenes Docker..."
docker-compose build --no-cache
log_success "Imágenes construidas"

# Levantar servicios
log_info "Levantando servicios..."
if [ "$deploy_mode" == "1" ]; then
    log_info "Modo: Desarrollo"
    docker-compose up -d
else
    log_info "Modo: Producción"
    docker-compose -f docker-compose.yml up -d
fi

# Esperar a que los servicios estén listos
log_info "Esperando a que los servicios estén listos..."
sleep 10

# Verificar salud de los servicios
log_info "Verificando salud de los servicios..."

# Backend
if curl -f http://localhost:8000/health &>/dev/null; then
    log_success "Backend: OK (http://localhost:8000)"
else
    log_error "Backend: ERROR"
    docker-compose logs backend
fi

# Frontend
if curl -f http://localhost/ &>/dev/null; then
    log_success "Frontend: OK (http://localhost)"
else
    log_error "Frontend: ERROR"
    docker-compose logs frontend
fi

# PostgreSQL
if docker-compose exec -T postgres pg_isready -U asset_user &>/dev/null; then
    log_success "PostgreSQL: OK"
else
    log_error "PostgreSQL: ERROR"
fi

# Crear usuario admin (opcional)
echo ""
read -p "¿Deseas crear un usuario administrador? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Creando usuario administrador..."
    
    read -p "Username [admin]: " admin_user
    admin_user=${admin_user:-admin}
    
    read -p "Email [admin@example.com]: " admin_email
    admin_email=${admin_email:-admin@example.com}
    
    read -s -p "Password [Admin123!@#]: " admin_pass
    admin_pass=${admin_pass:-Admin123!@#}
    echo ""
    
    docker-compose exec -T backend python -c "
from app.core.database import get_session_context
from app.models.asset import User
from app.core.security import get_password_hash

try:
    with get_session_context() as session:
        admin = User(
            username='$admin_user',
            email='$admin_email',
            hashed_password=get_password_hash('$admin_pass'),
            role='admin',
            is_active=True
        )
        session.add(admin)
        session.commit()
        print('✓ Usuario administrador creado')
except Exception as e:
    print(f'✗ Error: {e}')
"
fi

# Resumen
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  ¡Despliegue completado!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${BLUE}Acceso a los servicios:${NC}"
echo -e "  • Frontend:    ${GREEN}http://localhost${NC}"
echo -e "  • Backend API: ${GREEN}http://localhost:8000${NC}"
echo -e "  • Swagger:     ${GREEN}http://localhost:8000/docs${NC}"
echo -e "  • ReDoc:       ${GREEN}http://localhost:8000/redoc${NC}"
echo ""
echo -e "${BLUE}Comandos útiles:${NC}"
echo -e "  • Ver logs:       ${YELLOW}docker-compose logs -f${NC}"
echo -e "  • Detener:        ${YELLOW}docker-compose down${NC}"
echo -e "  • Reiniciar:      ${YELLOW}docker-compose restart${NC}"
echo -e "  • Ver estado:     ${YELLOW}docker-compose ps${NC}"
echo ""

# Abrir navegador (opcional)
if command -v xdg-open &> /dev/null; then
    read -p "¿Deseas abrir el navegador? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        xdg-open http://localhost &>/dev/null &
    fi
fi

exit 0