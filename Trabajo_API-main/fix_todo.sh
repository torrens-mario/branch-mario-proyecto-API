#!/bin/bash

# Script maestro que corrige TODOS los problemas

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       CORRECCIÓN COMPLETA DE TODOS LOS PROBLEMAS   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# 1. Actualizar app/main.py
echo -e "\n${YELLOW}[1/5] Corrigiendo /health endpoint...${NC}"
cat > app/main.py << 'EOFMAIN'
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import os
from app.core.logging_config import setup_logging
from app.core.database import create_db_and_tables
from app.routers.users import users
from app.routers.auth import auth
from app.routers.messages import messages
from app.routers.assets import assets
from app.routers.vulnerabilities import vulnerabilities
from fastapi.middleware.cors import CORSMiddleware

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agriculture IoT API",
    openapi_url="/openapi.json",
    docs_url="/docs",
    servers=[
        {"url": "/api", "description": "Nginx Proxy"},
        {"url": "/", "description": "Directo"}
    ]
)

ALLOWED_ORIGINS_STR = os.getenv(
    "ALLOWED_ORIGINS",
    "https://localhost,https://127.0.0.1"
)

ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",")]

if "*" in ALLOWED_ORIGINS:
    logger.critical("❌ ERROR: No se puede usar CORS '*' con allow_credentials=True")
    raise ValueError(
        "Configuración CORS insegura: No se puede usar allow_origins=['*'] "
        "con allow_credentials=True. Configure ALLOWED_ORIGINS en .env"
    )

logger.info(f"CORS configurado para orígenes: {ALLOWED_ORIGINS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With"
    ],
    expose_headers=["Content-Length", "X-Request-ID"],
    max_age=3600
)

@app.on_event("startup")
def on_startup():
    logger.info("Iniciando API de Inventario de Activos...")
    create_db_and_tables()
    logger.info("API preparada para recibir solicitudes")

@app.get("/health", tags=["health"])
def health():
    """Health check endpoint - NO requiere autenticación"""
    return {
        "status": "ok",
        "environment": os.getenv("ENVIRONMENT", "development")
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exec: Exception):
    logger.error(
        f"Error inesperado en {request.method} {request.url.path}: {exec}",
        exc_info=True,
        extra={
            "client_host": request.client.host if request.client else "unknown",
            "method": request.method,
            "path": request.url.path,
            "query_params": str(request.query_params)
        }
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(
        f"Error de validación en {request.method} {request.url.path}: {exc.errors()}",
        extra={
            "client_host": request.client.host if request.client else "unknown",
            "errors": exc.errors()
        }
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Datos de petición inválidos"}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(
        f"Error HTTP {exc.status_code} en {request.url.path}: {exc.detail}",
        extra={"client_host": request.client.host if request.client else "unknown"}
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
EOFMAIN

echo -e "${GREEN}✅ app/main.py corregido${NC}"

# 2. Crear script de creación de admin
echo -e "\n${YELLOW}[2/5] Creando script para usuario admin...${NC}"
cat > crear_admin.py << 'EOFADMIN'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlmodel import Session, select
from datetime import datetime, timezone
from app.core.database import engine
from app.models.asset import User
from app.core.security import get_password_hash

def crear_admin():
    print("=" * 60)
    print("CREACIÓN DE USUARIO ADMINISTRADOR")
    print("=" * 60)
    
    username = "superjefe"
    password = "P@ssw0rd!"
    email = "admin@agroiot.com"
    
    with Session(engine) as session:
        existing = session.exec(
            select(User).where(User.username == username)
        ).first()
        
        if existing:
            print(f"⚠️  Usuario '{username}' ya existe")
            print(f"   ID: {existing.id}")
            print(f"   Email: {existing.email}")
            print(f"   Rol: {existing.role}")
            print(f"   Activo: {existing.is_active}")
            
            existing.hashed_password = get_password_hash(password)
            existing.is_active = True
            if not hasattr(existing, 'role') or existing.role != 'admin':
                existing.role = 'admin'
            
            session.add(existing)
            session.commit()
            print(f"✅ Contraseña actualizada y rol verificado")
            return
        
        admin = User(
            username=username,
            email=email,
            hashed_password=get_password_hash(password),
            is_active=True,
            role="admin",
            created_at=datetime.now(timezone.utc)
        )
        
        session.add(admin)
        session.commit()
        session.refresh(admin)
        
        print(f"✅ Usuario administrador creado exitosamente")
        print(f"   Username: {username}")
        print(f"   Password: {password}")
        print(f"   Email: {email}")
        print(f"   ID: {admin.id}")
        print(f"   Rol: {admin.role}")
        print("=" * 60)

def listar_usuarios():
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        
        if not users:
            print("\n⚠️  No hay usuarios en la base de datos")
            return
        
        print(f"\n📋 Total de usuarios: {len(users)}")
        print("-" * 80)
        print(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Rol':<10} {'Activo':<8}")
        print("-" * 80)
        
        for user in users:
            role = getattr(user, 'role', 'user')
            print(f"{user.id:<5} {user.username:<20} {user.email:<30} {role:<10} {'Sí' if user.is_active else 'No':<8}")
        
        print("-" * 80)

if __name__ == "__main__":
    try:
        crear_admin()
        listar_usuarios()
        
        print("\n✅ Proceso completado exitosamente")
        print("\n🔐 Credenciales de login:")
        print("   Usuario: superjefe")
        print("   Contraseña: P@ssw0rd!")
        print("\n🌐 Accede a: https://localhost")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
EOFADMIN

chmod +x crear_admin.py
echo -e "${GREEN}✅ Script crear_admin.py creado${NC}"

# 3. Reiniciar contenedores
echo -e "\n${YELLOW}[3/5] Reiniciando contenedores con cambios...${NC}"
cd agriculture-iot
docker compose down
docker compose up -d --build
cd ..

# 4. Esperar que API esté lista
echo -e "\n${YELLOW}[4/5] Esperando que la API inicie...${NC}"
for i in {1..30}; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✅ API funcionando${NC}"
        break
    fi
    echo -ne "${YELLOW}Esperando... ($i/30)\r${NC}"
    sleep 2
done

# 5. Crear usuario admin
echo -e "\n${YELLOW}[5/5] Creando usuario administrador...${NC}"
docker exec asset-api python3 /app/crear_admin.py

# Verificación final
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              VERIFICACIÓN FINAL                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# Test health
HEALTH=$(curl -s http://localhost:8000/health)
if echo "$HEALTH" | grep -q "ok"; then
    echo -e "${GREEN}✅ Health check: $HEALTH${NC}"
else
    echo -e "${RED}❌ Health check falló${NC}"
fi

# Test login
LOGIN=$(curl -s -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=superjefe&password=P@ssw0rd!")

if echo "$LOGIN" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Login exitoso (token recibido)${NC}"
else
    echo -e "${RED}❌ Login falló: $LOGIN${NC}"
fi

echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              ✅ CORRECCIÓN COMPLETADA              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}Acceso a la aplicación:${NC}"
echo -e "  Frontend:  ${YELLOW}https://localhost${NC}"
echo -e "  API Docs:  ${YELLOW}http://localhost:8000/docs${NC}"

echo -e "\n${GREEN}Credenciales:${NC}"
echo -e "  Usuario:   ${YELLOW}superjefe${NC}"
echo -e "  Contraseña: ${YELLOW}P@ssw0rd!${NC}"

echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}\n"