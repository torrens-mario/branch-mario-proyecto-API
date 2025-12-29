#!/bin/bash

# Script FINAL que aplica todas las correcciones

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       APLICACIÓN FINAL DE TODAS LAS CORRECCIONES  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# 1. Actualizar app/core/database.py
echo -e "\n${YELLOW}[1/3] Actualizando database.py con creación automática de admin...${NC}"
cat > app/core/database.py << 'EOFDATABASE'
from sqlmodel import create_engine, Session, SQLModel, select
from contextlib import contextmanager
import os
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db")

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

def create_db_and_tables():
    """Crear base de datos y tablas"""
    logger.info("Creando tablas de la base de datos...")
    SQLModel.metadata.create_all(engine)
    logger.info("Tablas de la base de datos creadas correctamente")
    
    # ✅ CREAR USUARIO ADMIN AUTOMÁTICAMENTE
    create_default_admin()

def create_default_admin():
    """Crear usuario administrador por defecto si no existe"""
    from app.models.asset import User
    from app.core.security import get_password_hash
    from datetime import datetime, timezone
    
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "superjefe")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "P@ssw0rd!")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@agroiot.com")
    
    try:
        with Session(engine) as session:
            existing = session.exec(
                select(User).where(User.username == ADMIN_USERNAME)
            ).first()
            
            if existing:
                logger.info(f"Usuario admin '{ADMIN_USERNAME}' ya existe (ID: {existing.id})")
                
                if not hasattr(existing, 'role') or existing.role != 'admin':
                    existing.role = 'admin'
                    session.add(existing)
                    session.commit()
                    logger.info(f"Rol actualizado a admin")
                
                if not existing.is_active:
                    existing.is_active = True
                    session.add(existing)
                    session.commit()
                    logger.info(f"Usuario reactivado")
                
                return
            
            admin = User(
                username=ADMIN_USERNAME,
                email=ADMIN_EMAIL,
                hashed_password=get_password_hash(ADMIN_PASSWORD),
                is_active=True,
                role="admin",
                created_at=datetime.now(timezone.utc)
            )
            
            session.add(admin)
            session.commit()
            session.refresh(admin)
            
            logger.info(f"✅ Usuario administrador creado: {ADMIN_USERNAME} (ID: {admin.id})")
            logger.info(f"   Email: {ADMIN_EMAIL}")
            logger.info(f"   Rol: admin")
            
    except Exception as e:
        logger.error(f"Error creando usuario admin: {e}")

def get_session():
    """Dependency para obtener sesión de DB en FastAPI"""
    with Session(engine) as session:
        yield session

@contextmanager
def get_session_context():
    """Context manager para uso fuera de FastAPI"""
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
EOFDATABASE

echo -e "${GREEN}✅ database.py actualizado${NC}"

# 2. Reiniciar contenedores
echo -e "\n${YELLOW}[2/3] Reiniciando contenedores...${NC}"
cd agriculture-iot
docker compose down
docker compose up -d --build
cd ..

# 3. Esperar y verificar
echo -e "\n${YELLOW}[3/3] Verificando funcionamiento...${NC}"

for i in {1..30}; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✅ API funcionando${NC}"
        break
    fi
    echo -ne "${YELLOW}Esperando API... ($i/30)\r${NC}"
    sleep 2
done

# Verificación completa
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              VERIFICACIÓN FINAL                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# Health check
HEALTH=$(curl -s http://localhost:8000/health)
if echo "$HEALTH" | grep -q "ok"; then
    echo -e "${GREEN}✅ Health check: $HEALTH${NC}"
else
    echo -e "${RED}❌ Health check falló${NC}"
fi

# Login test
echo -e "\n${YELLOW}Probando login...${NC}"
sleep 3  # Esperar a que se cree el admin

LOGIN=$(curl -s -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=superjefe&password=P@ssw0rd!")

if echo "$LOGIN" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Login exitoso${NC}"
    TOKEN=$(echo "$LOGIN" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    echo -e "   Token: ${TOKEN:0:50}..."
else
    echo -e "${RED}❌ Login falló: $LOGIN${NC}"
    echo -e "\n${YELLOW}Verificando logs de la API...${NC}"
    docker logs asset-api --tail 20
fi

# Verificar que el admin existe
echo -e "\n${YELLOW}Verificando usuario admin en la base de datos...${NC}"
docker exec asset-api python3 -c "
from sqlmodel import Session, select
from app.core.database import engine
from app.models.asset import User

with Session(engine) as session:
    users = session.exec(select(User)).all()
    print(f'Total usuarios: {len(users)}')
    for user in users:
        role = getattr(user, 'role', 'user')
        print(f'  - {user.username} ({role})')
" 2>/dev/null

echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           ✅ CORRECCIÓN COMPLETADA                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}🌐 Acceso:${NC}"
echo -e "  Frontend:  ${YELLOW}https://localhost${NC}"
echo -e "  API Docs:  ${YELLOW}http://localhost:8000/docs${NC}"

echo -e "\n${GREEN}🔐 Credenciales:${NC}"
echo -e "  Usuario:   ${YELLOW}superjefe${NC}"
echo -e "  Contraseña: ${YELLOW}P@ssw0rd!${NC}"

echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}\n"