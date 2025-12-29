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
