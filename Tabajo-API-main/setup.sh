#!/bin/bash

# --- CONFIGURACIÓN ---
PROJECT_DIR="agriculture-iot"
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   SISTEMA DE PREPARACIÓN Y DESPLIEGUE AGRO-IOT     ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. FASE DE PRE-REQUISITOS DEL SISTEMA
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Por favor, ejecuta el script con sudo: sudo ./setup.sh${NC}"
  exit 1
fi

echo -e "\n${YELLOW}[1/5] Preparando entorno e instalando dependencias...${NC}"
apt-get update -qq && apt-get install -y -qq curl git net-tools xdg-utils > /dev/null

# 2. VERIFICACIÓN DE DOCKER
echo -e "\n${GREEN}[2/5] Verificando Docker Engine...${NC}"
if ! [ -x "$(command -v docker)" ]; then
    echo -e "${YELLOW}Instalando Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh && rm get-docker.sh
    systemctl start docker && systemctl enable docker
else
    echo -e "✅ Docker Engine está listo."
fi

# 3. ACCESO Y DESPLIEGUE
echo -e "\n${GREEN}[3/5] Levantando infraestructura (IT/OT)...${NC}"
if [ -d "$PROJECT_DIR" ]; then cd "$PROJECT_DIR"; else echo -e "${RED}Error: No existe $PROJECT_DIR${NC}"; exit 1; fi

docker compose down -v --remove-orphans > /dev/null 2>&1
docker compose up -d --build

# ---------------------------------------------------------
# 4. RESTAURACIÓN DE CREDENCIALES Y SINCRONIZACIÓN TOTAL
# ---------------------------------------------------------
echo -e "\n${YELLOW}[4/5] Restaurando superjefe y sincronizando activos...${NC}"
sleep 5

docker exec -it asset-api python -c "
try:
    import sys; sys.path.append('.')
    from sqlmodel import Session, select
    from datetime import datetime, timezone
    from app.core.database import engine
    from app.models.asset import User, Asset
    from app.core.security import get_password_hash
    
    with Session(engine) as session:
        # 1. BORRADO Y RECREACIÓN LIMPIA DEL USUARIO
        # Esto asegura que no haya errores de contraseña previos
        old_user = session.exec(select(User).where(User.username == 'superjefe')).first()
        if old_user:
            session.delete(old_user)
            session.commit()
        
        new_admin = User(
            username='superjefe',
            email='admin@agroiot.com',
            hashed_password=get_password_hash('P@ssw0rd!'),
            is_active=True,
            role='admin',
            created_at=datetime.now(timezone.utc)
        )
        # Forzamos el nombre completo si el campo existe
        if hasattr(new_admin, 'full_name'):
            new_admin.full_name = 'Superjefe Administrador'
            
        session.add(new_admin)
        print('✅ Usuario superjefe recreado con: P@ssw0rd!')

        # 2. SINCRONIZACIÓN DE ACTIVOS PARA ESTADÍSTICAS
        # Ponemos 'ACTIVO' en mayúsculas porque es lo que sale en tus badges verdes
        assets = session.exec(select(Asset)).all()
        for asset in assets:
            asset.status = 'ACTIVO'
            session.add(asset)
            
        session.commit()
        print(f'✅ {len(assets)} activos sincronizados a estado ACTIVO.')
except Exception as e:
    print(f'❌ Error en el proceso: {e}')
"

# 5. VERIFICACIÓN DE SEGURIDAD
echo -e "\n${GREEN}[5/5] Verificando estado de vulnerabilidades...${NC}"
sleep 2
echo -e "${YELLOW}Estado del sensor de suelo (Buffer Overflow):${NC}"
docker logs soil-sensor-001 2>&1 | grep "VULNERABILITY" | tail -n 1

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}           PROYECTO DESPLEGADO CON ÉXITO            ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "🚀 Dashboard:  ${YELLOW}http://localhost${NC}"
echo -e "📡 Red IoT:    ${YELLOW}10.10.1.0/24${NC}"
echo -e "🔑 Credenciales: ${GREEN}superjefe / P@ssw0rd!${NC}"
echo -e "${BLUE}====================================================${NC}"

# Abrir navegador
sudo -u $SUDO_USER xdg-open http://localhost > /dev/null 2>&1 &