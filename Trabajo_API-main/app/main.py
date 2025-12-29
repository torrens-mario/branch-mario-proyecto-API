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
