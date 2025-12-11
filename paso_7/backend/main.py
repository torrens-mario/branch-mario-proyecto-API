"""
Backend simple con FastAPI - Paso 7
CON SQLite + bcrypt + JWT + Cookies HttpOnly + VALIDACIÓN DE JWT + CORS SEGURO + DASHBOARD DE VULNERABILIDADES + RATE LIMITING
Añade gestión de vulnerabilidades CVE con dashboard visual y rate limiting
"""

from fastapi import FastAPI, Form, Request, Response, Cookie, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import hashlib
import secrets
import os
import json
import bcrypt  # Para hashear contraseñas de forma segura
import jwt  # Para crear y verificar JWT
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging

# ============================================================
# PASO 7: LOGGING ESTRUCTURADO (A09:2021 - Logging & Monitoring)
# ============================================================
# Crear directorio para logs
os.makedirs("./data", exist_ok=True)
os.makedirs("./logs", exist_ok=True)

# Configurar logger estructurado en JSON
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler('./logs/security.log'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger("security")

def log_security_event(event_type: str, details: dict):
    """Registra un evento de seguridad en formato JSON"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        **details
    }
    security_logger.info(json.dumps(log_entry))

# Configuración de SQLAlchemy
DATABASE_URL = "sqlite:///./data/lab.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo de Usuario
class User(Base):
    __tablename__ = "users"
    
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    created_at = Column(DateTime, default=datetime.now)

# Crear tablas
Base.metadata.create_all(bind=engine)

# ============================================================
# CONFIGURACIÓN JWT Y COOKIES (PASO 3)
# ============================================================
SECRET_KEY = "clave-super-secreta-cambiar-en-produccion-usar-variable-entorno"
REFRESH_SECRET_KEY = "refresh-token-secret-key-diferente-de-access-token"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 8
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Inicializar FastAPI
app = FastAPI(title="Lab Seguridad - Backend con bcrypt + JWT + Validación + CORS Seguro + Rate Limiting")

# ============================================================
# PASO 7: RATE LIMITING (PROTECCIÓN CONTRA ABUSO - A04:2021)
# ============================================================
# Configuración de slowapi para rate limiting por IP
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ============================================================
# PASO 5: CORS SEGURO (CONFIGURACIÓN RESTRICTIVA)
# ============================================================
# CAMBIO IMPORTANTE: Ya NO usamos allow_origins=["*"]
# Especificamos EXACTAMENTE qué origen puede acceder al backend

app.add_middleware(
    CORSMiddleware,
    # Solo permitir nuestro frontend (HTTPS)
    allow_origins=[
        "https://localhost:8443",  # Frontend en producción (HTTPS)
        "http://localhost:8080"    # Frontend en desarrollo (HTTP) - opcional, eliminar en producción
    ],
    # Permitir cookies (necesario para auth_token en HttpOnly)
    allow_credentials=True,
    # Solo métodos HTTP necesarios (no permitir TRACE, OPTIONS no autorizados, etc.)
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    # Solo headers necesarios (no permitir headers personalizados arbitrarios)
    allow_headers=[
        "Content-Type",      # Para enviar JSON/form-data
        "Authorization",     # Para tokens JWT (aunque usamos cookies)
        "Accept",            # Para negociación de contenido
        "Accept-Language"    # Para internacionalización
    ],
)


def create_jwt_token(user_id: int, username: str, role: str):
    """Crea un JWT firmado con claims del usuario y expiración."""
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_jwt_token(token: str):
    """Verifica y decodifica un JWT."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None


def create_refresh_token(user_id: int):
    """Crea un refresh token de larga duración."""
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_refresh_token(token: str):
    """Verifica y decodifica un refresh token."""
    try:
        payload = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None


# ============================================================
# PASO 4: VALIDACIÓN DE JWT DESDE COOKIES
# ============================================================

def get_current_user_from_cookie(auth_token: Optional[str] = Cookie(None)) -> Dict:
    """
    Valida el JWT desde la cookie HttpOnly y extrae los datos del usuario.
    Se usa como dependencia en endpoints protegidos con Depends().
    """
    if not auth_token:
        raise HTTPException(
            status_code=401,
            detail="No autenticado. Falta cookie de autenticación."
        )
    
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        username = payload.get("username")
        role = payload.get("role")
        
        if not user_id or not username:
            raise HTTPException(
                status_code=401,
                detail="Token inválido: datos incompletos"
            )
        
        return {"user_id": user_id, "username": username, "role": role}
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expirado. Por favor, inicia sesión de nuevo."
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=401,
            detail="Token inválido"
        )
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Error validando token: {str(e)}"
        )


# ============================================================
# PASO 6: GESTIÓN DE VULNERABILIDADES CVE
# ============================================================

VULNERABILITIES_FILE = "./vulnerabilities.json"
CHECKSUM_FILE = "./vulnerabilities.json.sha256"

# ============================================================
# PASO 7: CHECKSUM PARA INTEGRIDAD DE DATOS (A08:2021)
# ============================================================
def calculate_file_checksum(filepath: str) -> str:
    """Calcula SHA-256 checksum de un archivo"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculando checksum: {e}")
        return ""

def save_checksum(filepath: str):
    """Guarda el checksum de un archivo"""
    checksum = calculate_file_checksum(filepath)
    if checksum:
        try:
            with open(f"{filepath}.sha256", 'w') as f:
                f.write(checksum)
            log_security_event("checksum_saved", {
                "file": filepath,
                "checksum": checksum
            })
        except Exception as e:
            print(f"Error guardando checksum: {e}")

def verify_checksum(filepath: str) -> bool:
    """Verifica la integridad de un archivo contra su checksum"""
    checksum_file = f"{filepath}.sha256"
    if not os.path.exists(checksum_file):
        print(f"⚠️  Advertencia: No existe checksum para {filepath}")
        return True  # Permitir la primera vez
    
    try:
        with open(checksum_file, 'r') as f:
            stored_checksum = f.read().strip()
        
        current_checksum = calculate_file_checksum(filepath)
        
        if stored_checksum != current_checksum:
            log_security_event("checksum_mismatch", {
                "file": filepath,
                "stored": stored_checksum,
                "current": current_checksum,
                "status": "INTEGRITY_VIOLATION"
            })
            print(f"⚠️  ALERTA: Integridad comprometida en {filepath}")
            return False
        
        return True
    except Exception as e:
        print(f"Error verificando checksum: {e}")
        return True  # No bloquear en caso de error

def load_vulnerabilities():
    """Carga las vulnerabilidades desde el archivo JSON con verificación de integridad"""
    try:
        # A08:2021 - Verificar integridad antes de cargar
        if not verify_checksum(VULNERABILITIES_FILE):
            log_security_event("integrity_violation", {
                "file": VULNERABILITIES_FILE,
                "action": "load_blocked",
                "severity": "CRITICAL"
            })
            raise HTTPException(
                status_code=500,
                detail="Integridad del archivo comprometida. Contacte al administrador."
            )
        
        with open(VULNERABILITIES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            log_security_event("vulnerabilities_loaded", {
                "file": VULNERABILITIES_FILE,
                "total": data.get("metadata", {}).get("total_vulnerabilities", 0)
            })
            return data
    except FileNotFoundError:
        # Si no existe, crear archivo con estructura básica
        default_data = {"vulnerabilities": [], "metadata": {"total_vulnerabilities": 0, "pending": 0, "resolved": 0}}
        save_vulnerabilities(default_data)
        return default_data

def save_vulnerabilities(data):
    """Guarda las vulnerabilidades en el archivo JSON con checksum"""
    with open(VULNERABILITIES_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    # A08:2021 - Guardar checksum para verificación de integridad
    save_checksum(VULNERABILITIES_FILE)
    
    log_security_event("vulnerabilities_saved", {
        "file": VULNERABILITIES_FILE,
        "total": data.get("metadata", {}).get("total_vulnerabilities", 0),
        "checksum_saved": True
    })

def update_metadata(data):
    """Actualiza los metadatos de las vulnerabilidades"""
    vulns = data["vulnerabilities"]
    data["metadata"] = {
        "total_vulnerabilities": len(vulns),
        "pending": sum(1 for v in vulns if v["status"] == "pending"),
        "resolved": sum(1 for v in vulns if v["status"] == "resolved"),
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
        "high": sum(1 for v in vulns if v["severity"] == "HIGH"),
        "medium": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
        "low": sum(1 for v in vulns if v["severity"] == "LOW")
    }
    return data

def get_db():
    """Obtener sesión de base de datos"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass


def init_default_users():
    """Crear usuarios por defecto si no existen (CON BCRYPT)"""
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        
        admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt(rounds=12))
        admin = User(
            username="admin",
            email="admin@lab.local",
            password=admin_password.decode('utf-8'),
            role="admin"
        )
        db.add(admin)
        
        profe_password = bcrypt.hashpw("p.Euneiz123".encode('utf-8'), bcrypt.gensalt(rounds=12))
        profe = User(
            username="Profe",
            email="rufino.cabrera@euneiz.com",
            password=profe_password.decode('utf-8'),
            role="admin"
        )
        db.add(profe)
        
        # Usuario normal para pruebas de RBAC
        user1_password = bcrypt.hashpw("user123".encode('utf-8'), bcrypt.gensalt(rounds=12))
        user1 = User(
            username="user1",
            email="user1@test.com",
            password=user1_password.decode('utf-8'),
            role="user"
        )
        db.add(user1)
        
        db.commit()
        print("✓ Usuarios por defecto creados con bcrypt: admin, Profe, user1")
    except Exception as e:
        print(f"Error creando usuarios por defecto: {e}")
        db.rollback()
    finally:
        db.close()


@app.on_event("startup")
async def startup_event():
    """Inicializar usuarios al arrancar"""
    init_default_users()


@app.get("/")
async def root():
    return {
        "message": "Backend del Laboratorio de Seguridad",
        "version": "Paso 5 - JWT con Validación + CORS Seguro",
        "endpoints": ["/api/register", "/api/login", "/api/logout", "/api/users"],
        "cors": {
            "allowed_origins": ["https://localhost:8443", "http://localhost:8080"],
            "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
            "credentials": True
        }
    }


@app.post("/api/register")
@limiter.limit("3/minute")  # A04:2021 - Máximo 3 registros por minuto por IP
async def register(
    request: Request,
    response: Response,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    """Registro de usuarios con cookie HttpOnly y rate limiting"""
    db = SessionLocal()
    try:
        if len(username) < 3:
            return JSONResponse(
                content={"success": False, "message": "Usuario muy corto"},
                status_code=400
            )
        
        if db.query(User).filter(User.username == username).first():
            return JSONResponse(
                content={"success": False, "message": "El usuario ya existe"},
                status_code=400
            )
        
        if db.query(User).filter(User.email == email).first():
            return JSONResponse(
                content={"success": False, "message": "El email ya está registrado"},
                status_code=400
            )
        
        if len(password) < 8:
            return JSONResponse(
                content={"success": False, "message": "Contraseña muy corta"},
                status_code=400
            )
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        new_user = User(
            username=username,
            email=email,
            password=password_hash.decode('utf-8'),
            role="user"
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        access_token = create_jwt_token(new_user.user_id, new_user.username, new_user.role)
        refresh_token = create_refresh_token(new_user.user_id)
        
        response.set_cookie(
            key="auth_token",
            value=access_token,
            max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
            path="/",
            secure=False,
            httponly=True,
            samesite="strict"
        )
        
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
            path="/api/refresh",
            secure=False,
            httponly=True,
            samesite="strict"
        )
        
        response.set_cookie(
            key="lang",
            value="es-ES",
            max_age=365 * 24 * 3600,
            path="/",
            secure=False,
            httponly=False,
            samesite="lax"
        )
        
        response.set_cookie(
            key="theme",
            value="light",
            max_age=365 * 24 * 3600,
            path="/",
            secure=False,
            httponly=False,
            samesite="lax"
        )
        
        response.status_code = 201
        return {
            "success": True,
            "message": "Usuario registrado exitosamente",
            "user_id": new_user.user_id,
            "username": new_user.username,
            "email": new_user.email,
            "role": new_user.role
        }
    except Exception as e:
        db.rollback()
        return JSONResponse(
            content={"success": False, "message": f"Error: {str(e)}"},
            status_code=500
        )
    finally:
        db.close()


@app.post("/api/login")
@limiter.limit("5/minute")  # A04:2021 - Máximo 5 intentos de login por minuto por IP
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    """Inicio de sesión con cookie HttpOnly y rate limiting"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            # A09:2021 - Registrar intento de login fallido (usuario no existe)
            log_security_event("login_failed", {
                "username": username,
                "ip": request.client.host,
                "reason": "user_not_found",
                "severity": "WARNING"
            })
            return JSONResponse(
                content={"success": False, "message": "Credenciales incorrectas"},
                status_code=401
            )
        
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            # A09:2021 - Registrar intento de login fallido (contraseña incorrecta)
            log_security_event("login_failed", {
                "username": username,
                "ip": request.client.host,
                "reason": "invalid_password",
                "severity": "WARNING"
            })
            return JSONResponse(
                content={"success": False, "message": "Credenciales incorrectas"},
                status_code=401
            )
        
        access_token = create_jwt_token(user.user_id, user.username, user.role)
        refresh_token = create_refresh_token(user.user_id)
        
        response.set_cookie(
            key="auth_token",
            value=access_token,
            max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
            path="/",
            secure=False,
            httponly=True,
            samesite="strict"
        )
        
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
            path="/api/refresh",
            secure=False,
            httponly=True,
            samesite="strict"
        )
        
        response.set_cookie(
            key="lang",
            value="es-ES",
            max_age=365 * 24 * 3600,
            path="/",
            secure=False,
            httponly=False,
            samesite="lax"
        )
        
        response.set_cookie(
            key="theme",
            value="light",
            max_age=365 * 24 * 3600,
            path="/",
            secure=False,
            httponly=False,
            samesite="lax"
        )
        
        # A09:2021 - Registrar login exitoso
        log_security_event("login_success", {
            "username": user.username,
            "user_id": user.user_id,
            "role": user.role,
            "ip": request.client.host,
            "severity": "INFO"
        })
        
        return {
            "success": True,
            "message": "Inicio de sesión exitoso",
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    finally:
        db.close()


@app.get("/api/logout")
async def logout(response: Response):
    """Cierre de sesión - Elimina cookies sensibles"""
    response.set_cookie(
        key="auth_token",
        value="",
        max_age=0,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict"
    )
    
    response.set_cookie(
        key="refresh_token",
        value="",
        max_age=0,
        path="/api/refresh",
        secure=True,
        httponly=True,
        samesite="strict"
    )
    
    return JSONResponse(
        content={"success": True, "message": "Sesión cerrada, cookies eliminadas"}
    )


@app.post("/api/refresh")
async def refresh(request: Request, response: Response):
    """Renueva el access token usando el refresh token"""
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        return JSONResponse(
            content={"success": False, "message": "No hay refresh token"},
            status_code=401
        )
    
    payload = verify_refresh_token(refresh_token)
    
    if not payload:
        return JSONResponse(
            content={"success": False, "message": "Refresh token inválido o expirado"},
            status_code=401
        )
    
    db = SessionLocal()
    try:
        user_id = int(payload.get("sub"))
        user = db.query(User).filter(User.user_id == user_id).first()
        
        if not user:
            return JSONResponse(
                content={"success": False, "message": "Usuario no encontrado"},
                status_code=401
            )
        
        new_access_token = create_jwt_token(user.user_id, user.username, user.role)
        
        response.set_cookie(
            key="auth_token",
            value=new_access_token,
            max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
            path="/",
            secure=False,
            httponly=True,
            samesite="strict"
        )
        
        return JSONResponse(
            content={
                "success": True,
                "message": "Token renovado exitosamente",
                "username": user.username
            }
        )
    finally:
        db.close()


@app.get("/api/users")
async def list_users(
    request: Request,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Lista de usuarios (PASO 4: PROTEGIDO CON JWT)"""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        
        users_list = [
            {
                "user_id": u.user_id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "created_at": u.created_at.isoformat() if u.created_at else None
            }
            for u in users
        ]
        
        return JSONResponse(content={
            "success": True,
            "users": users_list,
            "authenticated_as": current_user["username"]
        })
    finally:
        db.close()


@app.get("/api/users/{user_id}")
async def get_user(
    user_id: int,
    request: Request,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Obtener detalles de un usuario (PASO 4: PROTEGIDO)"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        
        if not user:
            return JSONResponse(
                content={"success": False, "message": "Usuario no encontrado"},
                status_code=404
            )
        
        password_hash = user.password
        password_partial = f"{password_hash[:3]}...{password_hash[-3:]}"
        
        return JSONResponse(
            content={
                "success": True,
                "user": {
                    "user_id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                    "password_hash": password_partial,
                    "role": user.role,
                    "created_at": user.created_at.isoformat() if user.created_at else None
                }
            }
        )
    finally:
        db.close()


@app.put("/api/users/{user_id}")
async def update_user(
    user_id: int,
    role: str = Form(...),
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Actualizar rol de usuario (PASO 4: Solo ADMIN)"""
    
    # Verificar que el usuario autenticado es admin
    if current_user["role"] != "admin":
        # A09:2021 - Registrar acceso denegado
        log_security_event("access_denied", {
            "endpoint": f"/api/users/{user_id}",
            "method": "PUT",
            "user": current_user["username"],
            "role": current_user["role"],
            "reason": "insufficient_privileges",
            "severity": "WARNING"
        })
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado. Solo administradores pueden modificar roles."
        )
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        
        if not user:
            return JSONResponse(
                content={"success": False, "message": "Usuario no encontrado"},
                status_code=404
            )
        
        if role not in ["admin", "user"]:
            return JSONResponse(
                content={"success": False, "message": "Rol inválido"},
                status_code=400
            )
        
        old_role = user.role
        user.role = role
        db.commit()
        
        # A09:2021 - Registrar cambio de rol
        log_security_event("role_changed", {
            "target_user": user.username,
            "target_user_id": user.user_id,
            "old_role": old_role,
            "new_role": role,
            "changed_by": current_user["username"],
            "severity": "INFO"
        })
        
        return JSONResponse(
            content={
                "success": True,
                "message": "Usuario actualizado exitosamente",
                "user": {
                    "user_id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role
                }
            }
        )
    finally:
        db.close()


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Eliminar usuario (PASO 4: Solo ADMIN)"""
    
    # Verificar que el usuario autenticado es admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado. Solo administradores pueden eliminar usuarios."
        )
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        
        if not user:
            return JSONResponse(
                content={"success": False, "message": "Usuario no encontrado"},
                status_code=404
            )
        
        if user.username in ["admin", "Profe"]:
            return JSONResponse(
                content={"success": False, "message": "No se puede eliminar este usuario"},
                status_code=403
            )
        
        db.delete(user)
        db.commit()
        
        return JSONResponse(
            content={
                "success": True,
                "message": "Usuario eliminado exitosamente"
            }
        )
    finally:
        db.close()


# ============================================================
# PASO 6: ENDPOINTS DE VULNERABILIDADES
# ============================================================

@app.get("/api/vulnerabilities")
@limiter.limit("30/minute")  # A04:2021 - Máximo 30 consultas por minuto por IP
async def list_vulnerabilities(
    request: Request,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Lista todas las vulnerabilidades (requiere autenticación y rate limiting)"""
    try:
        data = load_vulnerabilities()
        return JSONResponse(content={
            "success": True,
            "vulnerabilities": data["vulnerabilities"],
            "metadata": data["metadata"]
        })
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": f"Error: {str(e)}"},
            status_code=500
        )

@app.get("/api/vulnerabilities/stats")
async def get_vulnerability_stats(
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Obtiene estadísticas de vulnerabilidades para gráficos"""
    try:
        data = load_vulnerabilities()
        return JSONResponse(content={
            "success": True,
            "stats": data["metadata"]
        })
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": f"Error: {str(e)}"},
            status_code=500
        )

@app.put("/api/vulnerabilities/{vuln_id}/resolve")
async def resolve_vulnerability(
    vuln_id: int,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Marca una vulnerabilidad como resuelta (cualquier usuario autenticado)"""
    try:
        data = load_vulnerabilities()
        
        # Buscar la vulnerabilidad
        vuln = next((v for v in data["vulnerabilities"] if v["id"] == vuln_id), None)
        
        if not vuln:
            return JSONResponse(
                content={"success": False, "message": "Vulnerabilidad no encontrada"},
                status_code=404
            )
        
        if vuln["status"] == "resolved":
            return JSONResponse(
                content={"success": False, "message": "La vulnerabilidad ya está resuelta"},
                status_code=400
            )
        
        # Marcar como resuelta
        vuln["status"] = "resolved"
        vuln["resolved_date"] = datetime.utcnow().strftime("%Y-%m-%d")
        
        # Actualizar metadatos
        data = update_metadata(data)
        
        # Guardar cambios
        save_vulnerabilities(data)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Vulnerabilidad {vuln['cve']} marcada como resuelta",
            "vulnerability": vuln,
            "metadata": data["metadata"]
        })
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": f"Error: {str(e)}"},
            status_code=500
        )

@app.put("/api/vulnerabilities/{vuln_id}/unresolve")
async def unresolve_vulnerability(
    vuln_id: int,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """Marca una vulnerabilidad como pendiente de nuevo (solo admin)"""
    
    # Solo admin puede desmarcar vulnerabilidades resueltas
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Solo administradores pueden desmarcar vulnerabilidades resueltas"
        )
    
    try:
        data = load_vulnerabilities()
        
        # Buscar la vulnerabilidad
        vuln = next((v for v in data["vulnerabilities"] if v["id"] == vuln_id), None)
        
        if not vuln:
            return JSONResponse(
                content={"success": False, "message": "Vulnerabilidad no encontrada"},
                status_code=404
            )
        
        if vuln["status"] == "pending":
            return JSONResponse(
                content={"success": False, "message": "La vulnerabilidad ya está pendiente"},
                status_code=400
            )
        
        # Marcar como pendiente
        vuln["status"] = "pending"
        vuln["resolved_date"] = None
        
        # Actualizar metadatos
        data = update_metadata(data)
        
        # Guardar cambios
        save_vulnerabilities(data)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Vulnerabilidad {vuln['cve']} marcada como pendiente",
            "vulnerability": vuln,
            "metadata": data["metadata"]
        })
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": f"Error: {str(e)}"},
            status_code=500
        )


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("Backend del Laboratorio de Seguridad - Paso 6")
    print("="*60)
    print("\nBase de datos SQLite: ./data/lab.db")
    print("\nUsuarios por defecto:")
    print("  1. Username: admin")
    print("     Password: admin123")
    print("  2. Username: Profe")
    print("     Password: p.Euneiz123")
    print("\nCORS configurado:")
    print("  - Orígenes permitidos: https://localhost:8443, http://localhost:8080")
    print("  - Métodos permitidos: GET, POST, PUT, DELETE")
    print("  - Credentials: True")
    print("\nNUEVO - Dashboard de Vulnerabilidades:")
    print("  - GET /api/vulnerabilities - Lista de CVEs")
    print("  - GET /api/vulnerabilities/stats - Estadísticas")
    print("  - PUT /api/vulnerabilities/{id}/resolve - Marcar resuelta")
    print("\n" + "="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
