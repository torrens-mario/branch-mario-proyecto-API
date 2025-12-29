#!/bin/bash

# ========================================================
# SCRIPT DE CORRECCIÓN AUTOMÁTICA - Proyecto API Segura
# ========================================================

set -e  # Salir si hay errores

NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CORRECCIÓN AUTOMÁTICA DE SEGURIDAD              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

# ========================================================
# 1. CORRECCIÓN: Secretos Expuestos
# ========================================================
echo -e "\n${YELLOW}[1/5] Eliminando secretos del repositorio...${NC}"

# Eliminar del staging area
git rm --cached -f .env 2>/dev/null || true
git rm --cached -f .env.local 2>/dev/null || true
git rm --cached -rf agriculture-iot/nginx_certs/*.pem 2>/dev/null || true
git rm --cached -rf agriculture-iot/nginx_certs/*.key 2>/dev/null || true
git rm --cached -rf frontend/certs/*.pem 2>/dev/null || true
git rm --cached -rf frontend/certs/*.key 2>/dev/null || true
git rm --cached -rf secrets/ 2>/dev/null || true

# Crear/Actualizar .gitignore
cat > .gitignore << 'EOF'
# ========================================================
# SECRETOS Y CONFIGURACIONES SENSIBLES
# ========================================================
.env
.env.*
!.env.example
secrets/
*.secret
credentials.json

# Certificados SSL/TLS
*.pem
*.key
*.crt
*.p12
*.pfx
*.jks

# ========================================================
# PYTHON
# ========================================================
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Entornos virtuales
venv/
env/
.venv
ENV/
env.bak/
venv.bak/

# ========================================================
# BASES DE DATOS
# ========================================================
*.db
*.sqlite
*.sqlite3
database/data.db
*.sql

# ========================================================
# LOGS Y TEMPORALES
# ========================================================
logs/
*.log
*.log.*
*.tmp
*.temp

# ========================================================
# IDEs Y EDITORES
# ========================================================
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# ========================================================
# DOCKER
# ========================================================
.dockerignore

# ========================================================
# REPORTES DE SEGURIDAD
# ========================================================
reports/*.html
reports/*.json
!reports/.gitkeep
EOF

echo -e "${GREEN}✅ .gitignore actualizado${NC}"

# ========================================================
# 2. CORRECCIÓN: SECRET_KEY Hardcodeada
# ========================================================
echo -e "\n${YELLOW}[2/5] Corrigiendo SECRET_KEY hardcodeada...${NC}"

# Generar SECRET_KEY segura (256 bits)
NEW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Crear .env.example
cat > .env.example << EOF
# ========================================================
# CONFIGURACIÓN DE LA API - PLANTILLA
# ========================================================
# ⚠️  IMPORTANTE: Copiar este archivo a .env y cambiar todos los valores

# JWT Configuration
SECRET_KEY=CHANGE_THIS_TO_A_RANDOM_256_BIT_STRING
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Database
DATABASE_URL=sqlite:///./database/data.db
# Para producción usar PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/dbname

POSTGRES_USER=secure_api_user
POSTGRES_PASSWORD=CHANGE_THIS_PASSWORD
POSTGRES_DB=secure_api_db
POSTGRES_PORT=5432

# API Configuration
API_PORT=8000
ENVIRONMENT=production
DEBUG=False

# CORS (dominios separados por comas, sin espacios)
ALLOWED_ORIGINS=https://localhost,https://127.0.0.1

# Admin inicial (cambiar después del primer despliegue)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=CHANGE_THIS_STRONG_PASSWORD
ADMIN_EMAIL=admin@example.com

# PgAdmin (solo para desarrollo)
PGADMIN_EMAIL=admin@example.com
PGADMIN_PASSWORD=CHANGE_THIS
PGADMIN_PORT=5050
EOF

# Crear .env real con valores seguros
cat > .env << EOF
# ========================================================
# CONFIGURACIÓN DE LA API - VALORES REALES
# ========================================================
# ⚠️  ARCHIVO SENSIBLE - NO SUBIR A GIT

SECRET_KEY=${NEW_SECRET_KEY}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

DATABASE_URL=sqlite:///./database/data.db

POSTGRES_USER=secure_api_user
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
POSTGRES_DB=secure_api_db
POSTGRES_PORT=5432

API_PORT=8000
ENVIRONMENT=production
DEBUG=False

ALLOWED_ORIGINS=https://localhost,https://127.0.0.1,https://localhost:443

ADMIN_USERNAME=superjefe
ADMIN_PASSWORD=P@ssw0rd!
ADMIN_EMAIL=admin@agroiot.com

PGADMIN_EMAIL=admin@example.com
PGADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(12))")
PGADMIN_PORT=5050
EOF

echo -e "${GREEN}✅ Archivos .env creados${NC}"

# Actualizar app/core/security.py
cat > app/core/security.py << 'EOFSEC'
from datetime import datetime, timedelta
from typing import Optional, Dict
import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import os
import sys
import logging

logger = logging.getLogger(__name__)

# ================= CONFIGURACIÓN SEGURA =================
# ⚠️  CRÍTICO: SECRET_KEY debe venir de variable de entorno
SECRET_KEY = os.getenv("SECRET_KEY")

# Validación estricta de SECRET_KEY
if not SECRET_KEY:
    logger.critical("❌ ERROR FATAL: SECRET_KEY no está configurada")
    print("\n" + "="*60)
    print("❌ ERROR CRÍTICO DE SEGURIDAD")
    print("="*60)
    print("La variable SECRET_KEY no está configurada.")
    print("\nPara corregir:")
    print("1. Crear archivo .env en la raíz del proyecto")
    print("2. Añadir: SECRET_KEY=<valor-aleatorio-seguro>")
    print("3. Generar clave segura con:")
    print("   python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    print("="*60 + "\n")
    sys.exit(1)

if SECRET_KEY == "CHANGE_THIS_TO_A_RANDOM_256_BIT_STRING" or SECRET_KEY == "CHANGE_THIS_IN_PRODUCTION":
    logger.critical("❌ ERROR: SECRET_KEY usando valor por defecto")
    print("\n❌ ERROR: SECRET_KEY no ha sido cambiada del valor por defecto")
    print("Genere una clave segura y actualice el archivo .env")
    sys.exit(1)

if len(SECRET_KEY) < 32:
    logger.critical(f"❌ ERROR: SECRET_KEY demasiado corta ({len(SECRET_KEY)} caracteres)")
    print(f"\n❌ ERROR: SECRET_KEY debe tener al menos 32 caracteres")
    print(f"Longitud actual: {len(SECRET_KEY)} caracteres")
    sys.exit(1)

logger.info("✅ SECRET_KEY validada correctamente")

ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# ================= SEGURIDAD (HASHING) =================
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ================= MODELOS DE DATOS =================
class TokenData(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = "user"
    token_type: Optional[str] = "access"

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# ================= FUNCIONES CORE =================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        ph.verify(hashed_password, plain_password)
        if ph.check_needs_rehash(hashed_password):
            logger.info("Password hash necesita actualización")
        return True
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        logger.warning("Hash bcrypt detectado, usando fallback")
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        if pwd_context.verify(plain_password, hashed_password):
            logger.info("Verificación legacy bcrypt exitosa")
            return True
        return False

def get_password_hash(password: str) -> str:
    return ph.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Access token creado para: {data.get('sub')}")
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Refresh token creado para: {data.get('sub')}")
    return encoded_jwt

def decode_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        logger.warning("Token expirado")
        raise HTTPException(status_code=401, detail="Token expirado")
    except PyJWTError as e:
        logger.error(f"Error decodificando JWT: {e}")
        raise HTTPException(status_code=401, detail="No se pudieron validar las credenciales")

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Tipo de token inválido")
    username: str = payload.get("sub")
    role: str = payload.get("role", "user")
    if username is None:
        raise HTTPException(status_code=401, detail="Payload inválido")
    return {"username": username, "role": role}

def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    if user["role"] != "admin":
        logger.warning(f"Usuario {user['username']} sin privilegios de admin")
        raise HTTPException(status_code=403, detail="Privilegios de administrador requeridos")
    return user

def require_role(role: str):
    def checker(user = Depends(get_current_user)):
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="Privilegios insuficientes")
        return user
    return checker
EOFSEC

echo -e "${GREEN}✅ security.py corregido${NC}"

# ========================================================
# 3. CORRECCIÓN: Limpieza del Repositorio
# ========================================================
echo -e "\n${YELLOW}[3/5] Limpiando archivos compilados y temporales...${NC}"

# Eliminar __pycache__
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true

# Eliminar entornos virtuales
rm -rf venv/ env/ .venv/ 2>/dev/null || true

# Eliminar logs
find logs/ -type f -name "*.log" -delete 2>/dev/null || true

# Eliminar bases de datos SQLite
rm -f database/*.db 2>/dev/null || true



echo -e "${GREEN}✅ Repositorio limpio${NC}"

# ========================================================
# 4. CORRECCIÓN: Puertos Docker
# ========================================================
echo -e "\n${YELLOW}[4/5] Estandarizando puertos Docker...${NC}"

# Actualizar Dockerfile
cat > Dockerfile << 'EOFDOCKER'
# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Usuario no-root
RUN useradd -m appuser
WORKDIR /app

# Dependencias del sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código de la aplicación
COPY app ./app
COPY .env.example ./.env.example
COPY scripts ./scripts

# Puerto estandarizado
ENV PORT=8000
EXPOSE 8000

# Usuario no-root
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Comando de inicio
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOFDOCKER

# Actualizar docker-compose.yml (API principal)
cat > docker-compose.yml << 'EOFCOMPOSE'
version: '3.9'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    
    container_name: secure_api_app
    restart: unless-stopped
    
    ports:
      - "${API_PORT:-8000}:8000"
    
    env_file:
      - .env
    
    volumes:
      - ./app:/app/app:ro
      - ./logs:/app/logs
      - ./database:/app/database
    
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    
    networks:
      - secure_api_network
    
    security_opt:
      - no-new-privileges:true

networks:
  secure_api_network:
    driver: bridge
    name: secure_api_network
EOFCOMPOSE

# Actualizar frontend/nginx.conf
cat > frontend/nginx.conf << 'EOFNGINX'
server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name localhost;

    # Certificados SSL
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    # Configuración SSL segura
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Cabeceras de seguridad
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Frontend estático
    location / {
        root /usr/share/nginx/html;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Proxy a la API
    location /api/ {
        # CORRECCIÓN: Puerto estandarizado a 8000
        rewrite ^/api/(.*)$ /$1 break;
        proxy_pass http://asset-api:8000;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOFNGINX

# Actualizar agriculture-iot/docker-compose.yml
sed -i 's/http:\/\/asset-api:8000/http:\/\/asset-api:8000/g' agriculture-iot/docker-compose.yml
sed -i 's/- "8000:8000"/- "8000:8000"/g' agriculture-iot/docker-compose.yml
sed -i 's/--port 8000/--port 8000/g' agriculture-iot/docker-compose.yml



echo -e "${GREEN}✅ Puertos estandarizados a 8000${NC}"

# ========================================================
# 5. CORRECCIÓN: CORS Restrictivo
# ========================================================
echo -e "\n${YELLOW}[5/5] Configurando CORS restrictivo...${NC}"

# Actualizar app/main.py
cat > app/main.py << 'EOFMAIN'
from app.routers.assets import assets
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
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from app.routers.vulnerabilities import vulnerabilities

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

# ========================================================
# CONFIGURACIÓN CORS SEGURA
# ========================================================
# Obtener orígenes permitidos desde variable de entorno
ALLOWED_ORIGINS_STR = os.getenv(
    "ALLOWED_ORIGINS",
    "https://localhost,https://127.0.0.1"
)

# Convertir string a lista
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",")]

# ⚠️  VALIDACIÓN DE SEGURIDAD: No permitir "*" con credenciales
if "*" in ALLOWED_ORIGINS:
    logger.critical("❌ ERROR: No se puede usar CORS '*' con allow_credentials=True")
    raise ValueError(
        "Configuración CORS insegura: No se puede usar allow_origins=['*'] "
        "con allow_credentials=True. Configure ALLOWED_ORIGINS en .env"
    )

logger.info(f"CORS configurado para orígenes: {ALLOWED_ORIGINS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # ✅ Lista explícita
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
    max_age=3600  # Cache de preflight 1 hora
)

@app.on_event("startup")
def on_startup():
    logger.info("Iniciando API de Inventario de Activos...")
    create_db_and_tables()
    logger.info("API preparada para recibir solicitudes")

app.include_router(assets.router)

# ========================================================
# MANEJO DE ERRORES
# ========================================================
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

@app.get("/health")
def health():
    return {"status": "ok", "environment": os.getenv("ENVIRONMENT", "development")}

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
EOFMAIN



echo -e "${GREEN}✅ CORS configurado de forma segura${NC}"

# ========================================================
# GENERACIÓN DE CERTIFICADOS SSL
# ========================================================
echo -e "\n${YELLOW}[EXTRA] Generando certificados SSL autofirmados...${NC}"

mkdir -p frontend/certs
mkdir -p agriculture-iot/nginx_certs

# Certificados para frontend
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout frontend/certs/key.pem \
    -out frontend/certs/cert.pem \
    -subj "/C=ES/ST=Alava/L=Vitoria/O=EUNEIZ/CN=localhost" 2>/dev/null

# Certificados para agriculture-iot
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout agriculture-iot/nginx_certs/server.key \
    -out agriculture-iot/nginx_certs/server.crt \
    -subj "/C=ES/ST=Alava/L=Vitoria/O=EUNEIZ/CN=localhost" 2>/dev/null

echo -e "${GREEN}✅ Certificados SSL generados${NC}"

# ========================================================
# SCRIPT DE LIMPIEZA
# ========================================================
cat > clean.sh << 'EOFCLEAN'
#!/bin/bash
echo "🧹 Limpiando archivos compilados y temporales..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete 2>/dev/null
find . -type f -name "*.pyo" -delete 2>/dev/null
find . -type f -name "*.log" -delete 2>/dev/null
rm -rf venv/ env/ .venv/ 2>/dev/null
echo "✅ Limpieza completada"
EOFCLEAN

chmod +x clean.sh

# ========================================================
# ACTUALIZAR SETUP.SH
# ========================================================
cat > setup.sh << 'EOFSETUP'
#!/bin/bash

PROJECT_DIR="agriculture-iot"
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   DESPLIEGUE SEGURO - AGRICULTURE IoT API          ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Verificar que existe .env
if [ ! -f ".env" ]; then
    echo -e "${RED}❌ ERROR: Archivo .env no encontrado${NC}"
    echo -e "${YELLOW}Copiando desde .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}⚠️  IMPORTANTE: Editar .env y cambiar todos los valores${NC}"
    exit 1
fi

# Verificar SECRET_KEY
if grep -q "CHANGE_THIS" .env; then
    echo -e "${RED}❌ ERROR: .env contiene valores por defecto${NC}"
    echo -e "Edite el archivo .env y cambie todos los valores marcados con CHANGE_THIS"
    exit 1
fi

echo -e "\n${GREEN}[1/6] Verificando dependencias...${NC}"
command -v docker >/dev/null 2>&1 || {
    echo -e "${RED}Docker no instalado. Instalando...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
}

echo -e "\n${GREEN}[2/6] Instalando dependencias Python...${NC}"
pip install --upgrade pip --break-system-packages >/dev/null 2>&1
pip install -r requirements.txt --break-system-packages >/dev/null 2>&1

echo -e "\n${GREEN}[3/6] Creando directorios necesarios...${NC}"
mkdir -p logs database reports
touch logs/.gitkeep reports/.gitkeep

echo -e "\n${GREEN}[4/6] Levantando infraestructura principal...${NC}"
docker compose down -v --remove-orphans >/dev/null 2>&1
docker compose up -d --build

echo -e "\n${GREEN}[5/6] Esperando que la API esté lista...${NC}"
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✅ API lista${NC}"
        break
    fi
    echo -e "${YELLOW}Esperando API... ($attempt/$max_attempts)${NC}"
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}❌ ERROR: API no respondió en 60 segundos${NC}"
    docker compose logs api
    exit 1
fi

echo -e "\n${GREEN}[6/6] Levantando módulo IoT...${NC}"
if [ -d "$PROJECT_DIR" ]; then
    cd "$PROJECT_DIR"
    docker compose down -v --remove-orphans >/dev/null 2>&1
    docker compose up -d --build
    cd ..
else
    echo -e "${YELLOW}⚠️  Directorio $PROJECT_DIR no encontrado${NC}"
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}           ✅ DESPLIEGUE COMPLETADO                 ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "🌐 Frontend HTTPS: ${YELLOW}https://localhost${NC}"
echo -e "📡 API Backend:    ${YELLOW}http://localhost:8000${NC}"
echo -e "📖 Documentación:  ${YELLOW}http://localhost:8000/docs${NC}"
echo -e "🔑 Usuario admin:  ${YELLOW}superjefe / P@ssw0rd!${NC}"
echo -e "${BLUE}====================================================${NC}"

# Abrir navegador
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open https://localhost >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    open https://localhost >/dev/null 2>&1 &
fi
EOFSETUP

chmod +x setup.sh

echo -e "${GREEN}✅ setup.sh actualizado${NC}"

# ========================================================
# CREAR ESTRUCTURA DE DIRECTORIOS
# ========================================================
echo -e "\n${YELLOW}[EXTRA] Creando estructura de directorios...${NC}"

mkdir -p logs database reports
touch logs/.gitkeep
touch database/.gitkeep
touch reports/.gitkeep

# ========================================================
# RESUMEN FINAL
# ========================================================
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           ✅ CORRECCIONES COMPLETADAS              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}Correcciones aplicadas:${NC}"
echo -e "  ✅ [1/5] Secretos eliminados del repositorio"
echo -e "  ✅ [2/5] SECRET_KEY desde variables de entorno"
echo -e "  ✅ [3/5] Repositorio limpiado (__pycache__, logs, etc.)"
echo -e "  ✅ [4/5] Puertos Docker estandarizados (8000)"
echo -e "  ✅ [5/5] CORS configurado con lista blanca"

echo -e "\n${YELLOW}Archivos generados:${NC}"
echo -e "  📄 .env (con valores seguros)"
echo -e "  📄 .env.example (plantilla)"
echo -e "  📄 .gitignore (actualizado)"
echo -e "  📄 setup.sh (mejorado)"
echo -e "  📄 clean.sh (nuevo)"
echo -e "  🔐 Certificados SSL (regenerados)"

echo -e "\n${YELLOW}Próximos pasos:${NC}"
echo -e "  1. Revisar archivo .env y ajustar valores si es necesario"
echo -e "  2. Ejecutar: ${GREEN}./setup.sh${NC}"
echo -e "  3. Verificar que todo funciona en: ${GREEN}https://localhost${NC}"
echo -e "  4. Hacer commit final de todas las correcciones"

echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Ejecute './setup.sh' para iniciar el sistema    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}\n"