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
