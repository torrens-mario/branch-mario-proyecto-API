from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import os
from app.core.logging_config import setup_logging
from app.core.database import create_db_and_tables
from app.routers.users import users
from app.routers.auth import auth
from app.routers.assets import assets

# ================= CONFIGURACIÓN INICIAL =================
setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="API de Inventario de Activos IT",
    description="API segura para el manejo de activos de TI con autenticación JWT y RBAC",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ================= MIDDLEWARE DE CORS =================
# Configuración para permitir requests desde el frontend
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost,http://localhost:80,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=3600,
)

# ================= MIDDLEWARE DE SEGURIDAD =================
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware para agregar cabeceras de seguridad HTTP
    
    Implementa protecciones OWASP Top 10:
    - A05:2021 Security Misconfiguration
    - A03:2021 Injection
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Cabeceras de seguridad
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ================= EVENTOS DEL CICLO DE VIDA =================
@app.on_event("startup")
def on_startup():
    logger.info("🚀 Iniciando API de Inventario de Activos IT...")
    create_db_and_tables()
    logger.info("✅ Base de datos inicializada")
    logger.info("✅ API lista para recibir solicitudes")
    logger.info(f"📝 Documentación disponible en: /docs")

@app.on_event("shutdown")
def on_shutdown():
    logger.info("🛑 Apagando API de Inventario de Activos IT...")

# ================= MANEJO DE ERRORES =================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Manejador global de excepciones
    
    Security:
    - NO exponer stack traces al cliente
    - Logear error completo internamente
    - Devolver mensaje genérico
    
    Referencias: CWE-209, OWASP Top 10 A09:2021
    """
    logger.error(
        f"❌ Error inesperado en {request.method} {request.url.path}: {exc}",
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
    """
    Manejador de errores de validación de Pydantic
    
    Security:
    - Devolver errores genéricos
    - Logear detalles internamente
    """
    logger.warning(
        f"⚠️ Error de validación en {request.method} {request.url.path}",
        extra={
            "client_host": request.client.host if request.client else "unknown",
            "errors": exc.errors()
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Datos de entrada inválidos",
            "errors": exc.errors()
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Manejador de excepciones HTTP explícitas
    """
    logger.warning(
        f"⚠️ Error HTTP {exc.status_code} en {request.url.path}: {exc.detail}",
        extra={"client_host": request.client.host if request.client else "unknown"}
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

# ================= RUTAS PRINCIPALES =================
@app.get("/", tags=["root"])
def read_root():
    """
    Endpoint raíz - Información de la API
    """
    return {
        "message": "API de Inventario de Activos IT",
        "version": "1.0.0",
        "status": "online",
        "docs": "/docs",
        "redoc": "/redoc"
    }

@app.get("/health", tags=["health"])
def health_check():
    """
    Health check endpoint para monitoreo
    """
    return {"status": "healthy", "service": "asset-inventory-api"}

# ================= INCLUIR ROUTERS =================
app.include_router(auth.router, prefix="/auth", tags=["Autenticación"])
app.include_router(users.router, prefix="/users", tags=["Usuarios"])
app.include_router(assets.router, prefix="/assets", tags=["Activos"])

# ================= ARRANQUE LOCAL =================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )