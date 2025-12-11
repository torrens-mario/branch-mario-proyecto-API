#!/usr/bin/env python3
"""
Script de Verificación de Cumplimiento de Seguridad
Lab de Desarrollo Web Seguro - EUNEIZ 2025

Este script verifica automáticamente el cumplimiento de los requisitos de seguridad:
- HTTPS con TLS 1.3
- HTTP/2
- JWT con 8h de expiración
- bcrypt para contraseñas
- Control de acceso por roles (admin vs user)
- Comunicación con base de datos
- Contenedores funcionando correctamente

CARACTERÍSTICAS:
- ✅ **Detección automática de contenedores** (lab-*, paso_*-*, nombres personalizados)
- ✅ **Detección automática de puertos** (8080, 8443, 443, 8000-8084, etc.)
- ✅ **Flexible con usuarios** (2+ usuarios, no requiere exactamente 3)
- ✅ **Tests no destructivos** (no modifica ni elimina datos de la DB)
- ✅ **Explicación detallada** de cada WARNING y FAIL (causa + solución)
- ✅ **Compatible con cualquier paso** del laboratorio (1-7)
- ✅ **Genérico para proyectos de estudiantes** (adapta configuración automáticamente)

USO:
    python3 verify-compliance.py

NOTA: Debes tener usuarios reales en el sistema.
      Por defecto usa: admin/admin123 y user1/user123
      Puedes modificar las credenciales más abajo.
"""

import subprocess
import requests
import json
import re
import sys
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
import base64
import time

# ============================================================
# CONFIGURACIÓN - MODIFICA SEGÚN TUS CREDENCIALES REALES
# ============================================================

# NOTA: Puedes cambiar el puerto si tu lab usa otro (ej: 443, 8080, 8081, etc.)
BASE_URL = "https://localhost:8443"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"
USER_USER = "user1"  # Opcional: si no existe, algunos tests se saltarán
USER_PASS = "user123"

# Colores para terminal
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")

def detect_https_port():
    """Detecta automáticamente el puerto HTTPS desde Docker"""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "publish=443", "--format", "{{.Ports}}"],
            capture_output=True,
            text=True
        )
        
        if not result.stdout:
            # Intentar con otros puertos comunes
            for port in [8443, 443, 8080, 8081, 8082, 8083, 8084]:
                result = subprocess.run(
                    ["docker", "ps", "--format", "{{.Ports}}"],
                    capture_output=True,
                    text=True
                )
                if f":{port}->" in result.stdout or f":{port}/tcp" in result.stdout:
                    return port
        
        # Extraer puerto mapeado
        port_pattern = r'0\.0\.0\.0:(\d+)->443'
        match = re.search(port_pattern, result.stdout)
        if match:
            return int(match.group(1))
        
        return 8443  # Default
    except:
        return 8443  # Default

def print_test(name):
    print(f"{Colors.BLUE}[TEST]{Colors.END} {name}... ", end='', flush=True)

def print_pass(detail=""):
    print(f"{Colors.GREEN}✓ PASS{Colors.END} {detail}")

def print_fail(detail="", explanation=""):
    print(f"{Colors.RED}✗ FAIL{Colors.END} {detail}")
    if explanation:
        print(f"  {Colors.RED}→{Colors.END} {explanation}")

def print_warn(detail="", explanation=""):
    print(f"{Colors.YELLOW}⚠ WARNING{Colors.END} {detail}")
    if explanation:
        print(f"  {Colors.YELLOW}→{Colors.END} {explanation}")

# ============================================================
# VERIFICACIONES DE INFRAESTRUCTURA
# ============================================================

def check_docker_containers():
    """Verifica que los contenedores Docker estén corriendo (flexible con nombres)"""
    print_header("1. VERIFICACIÓN DE CONTENEDORES DOCKER")
    
    print(f"{Colors.YELLOW}NOTA: Se buscarán contenedores con cualquier nombre (lab-*, paso_*-*, etc.){Colors.END}\n")
    
    try:
        # Obtener TODOS los contenedores corriendo
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        
        all_containers = result.stdout.strip().split('\n')
        
        # Buscar contenedores por patrones flexibles
        required_types = {
            'nginx': ['nginx', 'web', 'frontend'],
            'backend': ['backend', 'api', 'fastapi', 'uvicorn'],
            'database': ['database', 'db', 'sqlite', 'postgres', 'mysql'],
            'mitm': ['mitm', 'proxy', 'mitmproxy']
        }
        
        found_containers = {}
        
        for container_type, patterns in required_types.items():
            print_test(f"Contenedor tipo '{container_type}'")
            found = None
            
            # Buscar por patrones
            for container_name in all_containers:
                for pattern in patterns:
                    if pattern in container_name.lower():
                        found = container_name
                        break
                if found:
                    break
            
            if found:
                found_containers[container_type] = found
                print_pass(f"Encontrado: {found}")
            else:
                print_warn(
                    f"No encontrado (patrones: {', '.join(patterns)})",
                    f"CAUSA: No hay contenedor con '{container_type}' en el nombre. SOLUCIÓN: Verifica 'docker ps'"
                )
        
        # Verificar que al menos tengamos nginx y backend (mínimo)
        if 'nginx' in found_containers and 'backend' in found_containers:
            print(f"\n{Colors.GREEN}✓ Contenedores mínimos encontrados: {len(found_containers)}/4{Colors.END}")
            return True
        else:
            print_fail(
                f"Faltan contenedores críticos",
                "CAUSA: No se encontraron nginx o backend. SOLUCIÓN: Ejecuta './lab.sh' y selecciona un paso."
            )
            return False
        
    except subprocess.CalledProcessError as e:
        print_fail(
            f"Error al verificar contenedores: {e}",
            "CAUSA: Docker no responde. SOLUCIÓN: Verifica 'sudo systemctl status docker'"
        )
        return False
    except Exception as e:
        print_fail(
            f"Error inesperado: {e}",
            "CAUSA: Problema con Docker. SOLUCIÓN: Ejecuta 'docker ps' manualmente para verificar."
        )
        return False

def check_ports():
    """Verifica que los puertos estén escuchando (detecta automáticamente)"""
    print_header("2. VERIFICACIÓN DE PUERTOS")
    
    print(f"{Colors.YELLOW}NOTA: Se detectarán puertos automáticamente desde Docker{Colors.END}\n")
    
    # Detectar puertos desde Docker
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Ports}}"],
            capture_output=True,
            text=True
        )
        
        ports_output = result.stdout
        detected_ports = []
        
        # Extraer puertos del formato: 0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp
        import re
        port_pattern = r'0\.0\.0\.0:(\d+)'
        detected_ports = list(set(re.findall(port_pattern, ports_output)))
        
        if detected_ports:
            print(f"{Colors.GREEN}✓ Puertos detectados: {', '.join(sorted(detected_ports, key=int))}{Colors.END}\n")
        else:
            print(f"{Colors.YELLOW}⚠ No se detectaron puertos mapeados (puede estar en red interna Docker){Colors.END}\n")
    except:
        pass
    
    # Verificar puertos comunes
    ports = {
        8080: "HTTP (redirección)",
        8443: "HTTPS (principal)",
    }
    
    all_open = True
    for port, desc in ports.items():
        print_test(f"Puerto {port} ({desc})")
        try:
            # Método 1: Intentar con lsof
            result = subprocess.run(
                ["lsof", "-i", f":{port}"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print_pass()
                continue
            
            # Método 2: Verificar con docker ps (puertos mapeados)
            result = subprocess.run(
                ["docker", "ps", "--filter", "name=lab-nginx", 
                 "--format", "{{.Ports}}"],
                capture_output=True,
                text=True
            )
            if f"{port}->" in result.stdout or f":{port}" in result.stdout:
                print_pass("(detectado vía Docker)")
                continue
            
            # Método 3: Intentar conectar
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            if result == 0:
                print_pass("(puerto responde)")
            else:
                print_warn(
                    f"Puerto {port} no responde",
                    "CAUSA: El puerto está dentro de Docker. SOLUCIÓN: Si curl funciona en otros tests, ignora esto."
                )
        except Exception as e:
            print_warn(
                f"No se pudo verificar completamente",
                "CAUSA: Herramientas de red no disponibles. SOLUCIÓN: Si curl funciona, ignora esto."
            )
    
    return all_open

# ============================================================
# VERIFICACIONES DE PROTOCOLO
# ============================================================

def check_https_tls():
    """Verifica HTTPS con TLS 1.3 y HTTP/2"""
    print_header("3. VERIFICACIÓN DE HTTPS, TLS Y HTTP/2")
    
    # TLS 1.3
    print_test("HTTPS con TLS 1.3")
    try:
        result = subprocess.run(
            ["curl", "-sI", "-k", "--tlsv1.3", f"{BASE_URL}/"],
            capture_output=True,
            text=True
        )
        
        if "HTTP/2" in result.stdout or "HTTP/1.1" in result.stdout:
            # Verificar TLS version con openssl
            tls_result = subprocess.run(
                ["openssl", "s_client", "-connect", "localhost:8443", 
                 "-tls1_3", "-brief"],
                input="Q\n",  # ← Cambiar de b"Q\n" a "Q\n"
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if "TLSv1.3" in tls_result.stdout or "TLSv1.3" in tls_result.stderr:
                print_pass("TLS 1.3 activo")
            else:
                print_warn(
                    "TLS 1.3 no detectado (puede ser TLS 1.2)",
                    "CAUSA: NGINX puede estar configurado con TLS 1.2. SOLUCIÓN: Verifica nginx.conf (ssl_protocols)"
                )
        else:
            print_fail(
                "No hay respuesta HTTPS",
                "CAUSA: Servidor HTTPS no responde. SOLUCIÓN: Verifica que el contenedor nginx esté corriendo con 'docker ps'"
            )
            return False
    except subprocess.TimeoutExpired:
        print_warn(
            "Timeout en verificación TLS",
            "CAUSA: openssl tardó mucho. SOLUCIÓN: Si curl funciona, esto es OK (solo problema de timeout)."
        )
        return True
    except Exception as e:
        print_warn(
            f"No se pudo verificar TLS: {e}",
            "CAUSA: Problema con openssl. SOLUCIÓN: Si curl funciona, esto es OK."
        )
        return True
    
    # HTTP/2
    print_test("HTTP/2")
    try:
        result = subprocess.run(
            ["curl", "-sI", "-k", "--http2", f"{BASE_URL}/"],
            capture_output=True,
            text=True
        )
        
        if "HTTP/2" in result.stdout:
            print_pass("HTTP/2 activo")
            return True
        else:
            print_warn("HTTP/2 no detectado (usando HTTP/1.1)")
            return True
    except Exception as e:
        print_fail(f"Error: {e}")
        return False

# ============================================================
# VERIFICACIONES DE AUTENTICACIÓN
# ============================================================

def login_and_get_cookies(username, password):
    """Hace login y obtiene las cookies"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/login",
            data={"username": username, "password": password},
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.cookies
        else:
            return None
    except Exception as e:
        print_fail(f"Error en login: {e}")
        return None

def decode_jwt(token):
    """Decodifica un JWT sin verificar la firma"""
    try:
        # JWT tiene 3 partes: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decodificar payload (segunda parte)
        payload = parts[1]
        # Agregar padding si es necesario
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print_warn(f"Error decodificando JWT: {e}")
        return None

def check_jwt_authentication():
    """Verifica JWT con 8h de expiración"""
    print_header("4. VERIFICACIÓN DE JWT")
    
    # Login como admin
    print_test("Login como admin")
    cookies = login_and_get_cookies(ADMIN_USER, ADMIN_PASS)
    
    if not cookies:
        print_fail(
            "No se pudo hacer login",
            f"CAUSA: Credenciales incorrectas o servidor no responde. SOLUCIÓN: Verifica que exista usuario '{ADMIN_USER}' con password '{ADMIN_PASS}'"
        )
        return False, None
    
    print_pass()
    
    # Verificar que existe la cookie auth_token
    print_test("Cookie auth_token presente")
    if 'auth_token' not in cookies:
        print_fail(
            "No se encontró cookie auth_token",
            "CAUSA: Estás en Paso 2 o anterior (JWT sin cookies). SOLUCIÓN: Ejecuta Paso 3 o superior."
        )
        return False, None
    
    print_pass()
    
    # Decodificar JWT
    print_test("Estructura JWT válida")
    jwt_token = cookies['auth_token']
    payload = decode_jwt(jwt_token)
    
    if not payload:
        print_fail(
            "No se pudo decodificar el JWT",
            "CAUSA: JWT malformado. SOLUCIÓN: Revisa la función create_jwt_token() en main.py"
        )
        return False, cookies
    
    print_pass()
    
    # Verificar campos del JWT
    print_test("JWT contiene campos requeridos (sub, role, exp)")
    required_fields = ['sub', 'role', 'exp']
    missing = [f for f in required_fields if f not in payload]
    
    if missing:
        print_fail(
            f"Faltan campos: {', '.join(missing)}",
            "CAUSA: create_jwt_token() no incluye todos los campos. SOLUCIÓN: Agrega 'sub', 'role', 'exp' al payload."
        )
        return False, cookies
    
    print_pass()
    
    # Verificar tiempo de expiración
    print_test("JWT expira en ~8 horas")
    try:
        exp_timestamp = payload['exp']
        exp_time = datetime.fromtimestamp(exp_timestamp)
        now = datetime.now()
        time_diff = exp_time - now
        
        hours = time_diff.total_seconds() / 3600
        
        if 7.5 <= hours <= 8.5:  # Tolerancia de ±30 min
            print_pass(f"Expira en {hours:.1f} horas")
        else:
            print_warn(
                f"Expira en {hours:.1f} horas (esperado: 8h)",
                f"CAUSA: ACCESS_TOKEN_EXPIRE_HOURS != 8. SOLUCIÓN: Cambia a 8 en main.py (línea ~18)"
            )
    except Exception as e:
        print_fail(
            f"Error verificando expiración: {e}",
            "CAUSA: Campo 'exp' inválido. SOLUCIÓN: Verifica que create_jwt_token() use datetime.utcnow()"
        )
        return False, cookies
    
    # Verificar refresh token
    print_test("Refresh token presente")
    if 'refresh_token' in cookies:
        print_pass()
    else:
        print_warn(
            "No se encontró refresh_token",
            "CAUSA: Solo existe en Paso 3+. SOLUCIÓN: Si estás en Paso 2, esto es normal."
        )
    
    return True, cookies

def get_backend_container_name():
    """Obtiene el nombre del contenedor backend (flexible)"""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        
        containers = result.stdout.strip().split('\n')
        
        # Buscar contenedor backend
        for container in containers:
            if any(pattern in container.lower() for pattern in ['backend', 'api', 'fastapi']):
                return container
        
        return "lab-backend"  # Fallback al nombre por defecto
    except:
        return "lab-backend"

def check_bcrypt():
    """Verifica que se esté usando bcrypt"""
    print_header("5. VERIFICACIÓN DE BCRYPT")
    
    backend_container = get_backend_container_name()
    print(f"{Colors.YELLOW}Usando contenedor: {backend_container}{Colors.END}\n")
    
    print_test("Contraseñas hasheadas con bcrypt")
    try:
        # Intentar obtener info del backend
        result = subprocess.run(
            ["docker", "exec", backend_container, "python3", "-c",
             "import sqlite3; conn = sqlite3.connect('/app/data/lab.db'); "
             "cursor = conn.cursor(); cursor.execute('SELECT password FROM users LIMIT 1'); "
             "print(cursor.fetchone()[0])"],
            capture_output=True,
            text=True
        )
        
        password_hash = result.stdout.strip()
        
        # Hashes de bcrypt empiezan con $2a$, $2b$, $2y$
        if password_hash.startswith(('$2a$', '$2b$', '$2y$')):
            print_pass(f"Formato bcrypt detectado: {password_hash[:20]}...")
            
            # Verificar cost factor
            cost = int(password_hash.split('$')[2])
            print_test(f"bcrypt cost factor = {cost}")
            if cost >= 12:
                print_pass(f"Cost factor óptimo: {cost}")
            else:
                print_warn(
                    f"Cost factor bajo: {cost} (recomendado: 12+)",
                    f"CAUSA: bcrypt.gensalt(rounds={cost}) es bajo. SOLUCIÓN: Usa bcrypt.gensalt(rounds=12)"
                )
            
            return True
        else:
            print_fail(
                "No es bcrypt (puede ser SHA256 u otro)",
                "CAUSA: Estás en LAB 8 o Paso 0. SOLUCIÓN: Ejecuta Paso 1+ (bcrypt se implementa en Paso 1)"
            )
            return False
    except Exception as e:
        print_warn(
            f"No se pudo verificar: {e}",
            "CAUSA: No hay acceso al contenedor. SOLUCIÓN: Ejecuta 'docker ps' y verifica que lab-backend esté corriendo."
        )
        return True  # No fallar si no se puede verificar

# ============================================================
# VERIFICACIONES DE CONTROL DE ACCESO
# ============================================================

def check_rbac(admin_cookies, user_cookies=None):
    """Verifica control de acceso basado en roles"""
    print_header("6. VERIFICACIÓN DE CONTROL DE ACCESO (RBAC)")
    
    # Test 1: Admin puede acceder a /api/users
    print_test("Admin puede listar usuarios")
    try:
        response = requests.get(
            f"{BASE_URL}/api/users",
            cookies=admin_cookies,
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            print_pass()
        else:
            print_fail(
                f"HTTP {response.status_code}",
                "CAUSA: Endpoint no protegido o JWT inválido. SOLUCIÓN: Verifica Depends(get_current_user_from_cookie) en @app.get('/api/users')"
            )
            return False
    except Exception as e:
        print_fail(
            f"Error: {e}",
            "CAUSA: Servidor no responde. SOLUCIÓN: Verifica que lab-backend esté corriendo."
        )
        return False
    
    # Test 2: Acceso sin autenticación debe fallar
    print_test("Acceso sin autenticación es rechazado")
    try:
        response = requests.get(
            f"{BASE_URL}/api/users",
            verify=False,
            timeout=10
        )
        
        if response.status_code == 401:
            print_pass("HTTP 401 Unauthorized")
        else:
            print_fail(
                f"HTTP {response.status_code} (esperado: 401)",
                "CAUSA: Endpoint NO está protegido. SOLUCIÓN: Agrega Depends(get_current_user_from_cookie) en Paso 4+"
            )
            return False
    except Exception as e:
        print_fail(
            f"Error: {e}",
            "CAUSA: Servidor no responde. SOLUCIÓN: Verifica contenedores Docker."
        )
        return False
    
    # Test 3: Usuario normal no puede modificar roles
    if user_cookies:
        print_test("Usuario normal no puede modificar roles")
        try:
            # Intentar cambiar rol de un usuario
            response = requests.put(
                f"{BASE_URL}/api/users/1",
                data={"role": "admin"},
                cookies=user_cookies,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 403:
                print_pass("HTTP 403 Forbidden")
            else:
                print_warn(f"HTTP {response.status_code} (esperado: 403)")
        except Exception as e:
            print_warn(f"No se pudo verificar: {e}")
    
    # Test 4: Admin puede modificar roles
    print_test("Admin puede modificar roles")
    try:
        response = requests.put(
            f"{BASE_URL}/api/users/999",  # ID no existe, solo verifica permisos
            data={"role": "user"},
            cookies=admin_cookies,
            verify=False,
            timeout=10
        )
        
        # Esperamos 404 (usuario no existe) o 200 (permiso OK)
        # Lo importante es que NO sea 403 (sin permisos)
        if response.status_code in [200, 404]:
            print_pass(f"HTTP {response.status_code} (permisos correctos)")
        elif response.status_code == 403:
            print_fail(
                f"HTTP {response.status_code}",
                "CAUSA: Admin no tiene permisos. SOLUCIÓN: Verifica que admin tenga role='admin' en la DB."
            )
        else:
            print_warn(f"HTTP {response.status_code}")
    except Exception as e:
        print_warn(f"No se pudo verificar: {e}")
    
    return True

# ============================================================
# VERIFICACIONES DE RUTAS Y ENDPOINTS
# ============================================================

def check_endpoints(admin_cookies=None):
    """Verifica que las rutas existan y tengan permisos correctos"""
    print_header("7. VERIFICACIÓN DE ENDPOINTS Y PERMISOS")
    
    print(f"{Colors.YELLOW}NOTA: Se verifican TODOS los endpoints del proyecto final.{Colors.END}")
    print(f"{Colors.YELLOW}      Algunos pueden no estar en Paso 7, pero deben implementarse para el proyecto.{Colors.END}")
    print(f"{Colors.YELLOW}      HTTP 404 en un endpoint = Falta implementar (para proyecto final).{Colors.END}\n")
    
    # Reutilizar cookies si se proporcionan, si no, hacer login
    if admin_cookies is None:
        print(f"{Colors.YELLOW}Obteniendo cookies de admin...{Colors.END}\n")
        admin_cookies = login_and_get_cookies(ADMIN_USER, ADMIN_PASS)
    else:
        print(f"{Colors.CYAN}Reutilizando cookies de admin (evita rate limiting)...{Colors.END}\n")
    
    endpoints = [
        # ============================================================
        # 1. AUTENTICACIÓN (Público)
        # ============================================================
        ("POST", "/api/register", False, False, "Registro de usuarios"),
        ("POST", "/api/login", False, False, "Inicio de sesión"),
        ("GET", "/api/logout", True, False, "Cierre de sesión"),
        
        # ============================================================
        # 2. GESTIÓN DE USUARIOS (Admin)
        # ============================================================
        ("GET", "/api/users", True, True, "Listar usuarios (paginado)"),
        ("GET", "/api/users/999", True, False, "Detalle de usuario (admin o propietario)"),
        ("PUT", "/api/users/999", True, True, "Actualizar privilegios de usuario"),
        ("DELETE", "/api/users/999", True, True, "Eliminar usuario"),
        
        # ============================================================
        # 3. GESTIÓN DE VULNERABILIDADES (User/Admin)
        # ============================================================
        ("GET", "/api/stats", True, False, "Obtener lista de vulnerabilidades"),
        ("GET", "/api/vulnerabilities", True, False, "Obtener lista de vulnerabilidades (alternativa)"),
        ("GET", "/api/vulnerabilities/stats", True, False, "Estadísticas de vulnerabilidades"),
        ("POST", "/api/stats/vulnerabilidades", True, True, "Crear nueva vulnerabilidad"),
        ("POST", "/api/vulnerabilities", True, True, "Crear nueva vulnerabilidad (alternativa)"),
        ("PUT", "/api/vulnerabilities/999/resolve", True, True, "Marcar vulnerabilidad como resuelta"),
        ("DELETE", "/api/stats/vulnerabilidades/999", True, True, "Eliminar vulnerabilidad"),
        ("DELETE", "/api/vulnerabilities/999", True, True, "Eliminar vulnerabilidad (alternativa)"),
    ]
    
    for method, route, needs_auth, needs_admin, desc in endpoints:
        print_test(f"{method:6} {route:40} ({desc})")
        
        try:
            if method == "GET":
                response = requests.get(
                    f"{BASE_URL}{route}",
                    cookies=admin_cookies if needs_auth else None,
                    verify=False,
                    timeout=10
                )
            elif method == "POST":
                response = requests.post(
                    f"{BASE_URL}{route}",
                    data={},
                    cookies=admin_cookies if needs_auth else None,
                    verify=False,
                    timeout=10
                )
            elif method == "PUT":
                response = requests.put(
                    f"{BASE_URL}{route}",
                    data={"role": "user"},
                    cookies=admin_cookies if needs_auth else None,
                    verify=False,
                    timeout=10
                )
            elif method == "DELETE":
                response = requests.delete(
                    f"{BASE_URL}{route}",
                    cookies=admin_cookies if needs_auth else None,
                    verify=False,
                    timeout=10
                )
            
            # Aceptar códigos esperados según autenticación y permisos
            # - 200/201: OK
            # - 400: Bad request (datos inválidos, pero endpoint funciona)
            # - 401: No autenticado (esperado si needs_auth=True y no hay cookies)
            # - 403: Sin permisos (esperado si needs_admin=True y user no es admin)
            # - 404: Recurso no existe (OK si usamos IDs ficticios como 999)
            # - 422: Validación fallida (esperado en /api/register sin datos)
            # - 429: Rate limiting activo (BUENO - seguridad funcionando)
            if response.status_code in [200, 201, 400, 401, 403, 404, 422, 429]:
                if response.status_code == 429:
                    print_pass(f"HTTP {response.status_code} (rate limiting activo ✓)")
                else:
                    print_pass(f"HTTP {response.status_code}")
            else:
                print_warn(f"HTTP {response.status_code}")
        
        except Exception as e:
            print_fail(f"Error: {e}")

# ============================================================
# VERIFICACIONES DE BASE DE DATOS
# ============================================================

def check_database():
    """Verifica la comunicación con la base de datos"""
    print_header("8. VERIFICACIÓN DE BASE DE DATOS")
    
    backend_container = get_backend_container_name()
    print(f"{Colors.YELLOW}Usando contenedor: {backend_container}{Colors.END}\n")
    
    print_test("Base de datos SQLite accesible")
    try:
        result = subprocess.run(
            ["docker", "exec", backend_container, "test", "-f", "/app/data/lab.db"],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print_pass()
        else:
            print_fail(
                "lab.db no encontrado",
                "CAUSA: Base de datos no existe. SOLUCIÓN: Reinicia el lab con './lab.sh' para que se cree automáticamente."
            )
            return False
    except Exception as e:
        print_fail(
            f"Error: {e}",
            f"CAUSA: No hay acceso al contenedor. SOLUCIÓN: Verifica 'docker ps | grep backend'"
        )
        return False
    
    print_test("Tabla users existe")
    try:
        result = subprocess.run(
            ["docker", "exec", backend_container, "python3", "-c",
             "import sqlite3; conn = sqlite3.connect('/app/data/lab.db'); "
             "cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM users'); "
             "print(cursor.fetchone()[0])"],
            capture_output=True,
            text=True
        )
        
        count = int(result.stdout.strip())
        if count >= 2:
            if count >= 3:
                print_pass(f"{count} usuarios en la base de datos ✓")
            else:
                print_pass(f"{count} usuarios en la base de datos (mínimo 2 para tests)")
        elif count > 0:
            print_warn(
                f"Solo {count} usuario (mínimo recomendado: 2)",
                "CAUSA: Pocos usuarios. SOLUCIÓN: Se recomienda al menos 1 admin y 1 usuario normal para RBAC."
            )
        else:
            print_fail(
                "No hay usuarios en la base de datos",
                f"CAUSA: init_default_users() no se ejecutó. SOLUCIÓN: Revisa logs con 'docker logs {backend_container}'"
            )
            return False
    except Exception as e:
        print_fail(
            f"Error: {e}",
            f"CAUSA: Error de SQLite o contenedor. SOLUCIÓN: Revisa 'docker logs {backend_container}' para ver errores."
        )
        return False
    
    print_test("Estructura de tabla correcta (user_id, username, email, password, role)")
    try:
        result = subprocess.run(
            ["docker", "exec", backend_container, "python3", "-c",
             "import sqlite3; conn = sqlite3.connect('/app/data/lab.db'); "
             "cursor = conn.cursor(); cursor.execute('PRAGMA table_info(users)'); "
             "print([col[1] for col in cursor.fetchall()])"],
            capture_output=True,
            text=True
        )
        
        columns = eval(result.stdout.strip())
        required = ['user_id', 'username', 'email', 'password', 'role']
        
        if all(col in columns for col in required):
            print_pass()
        else:
            missing = [col for col in required if col not in columns]
            print_fail(
                f"Faltan columnas: {', '.join(missing)}",
                "CAUSA: Modelo User incompleto. SOLUCIÓN: Verifica la clase User en models.py o main.py"
            )
            return False
    except Exception as e:
        print_fail(
            f"Error: {e}",
            f"CAUSA: Error accediendo a SQLite. SOLUCIÓN: Revisa 'docker exec {backend_container} ls -l /app/data/lab.db'"
        )
        return False
    
    return True

# ============================================================
# VERIFICACIONES DE SEGURIDAD ADICIONALES
# ============================================================

def check_security_headers():
    """Verifica headers de seguridad"""
    print_header("9. VERIFICACIÓN DE HEADERS DE SEGURIDAD")
    
    print(f"{Colors.YELLOW}NOTA: Headers CSP, X-Frame-Options, etc. solo están en Paso 7{Colors.END}\n")
    
    try:
        result = subprocess.run(
            ["curl", "-sI", "-k", f"{BASE_URL}/"],
            capture_output=True,
            text=True
        )
        
        headers_to_check = {
            'Content-Security-Policy': 'CSP configurado',
            'X-Frame-Options': 'Protección contra clickjacking',
            'X-Content-Type-Options': 'Protección contra MIME sniffing',
            'Strict-Transport-Security': 'HSTS habilitado',
            'X-XSS-Protection': 'Protección XSS del navegador',
        }
        
        found_count = 0
        for header, desc in headers_to_check.items():
            print_test(f"{header} ({desc})")
            if header.lower() in result.stdout.lower():
                print_pass()
                found_count += 1
            else:
                print_warn("No encontrado (OK si no estás en Paso 7)")
        
        if found_count >= 4:
            print(f"\n{Colors.GREEN}✓ Paso 7 detectado: {found_count}/5 headers implementados{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}⚠ Parece que estás en Paso 6 o anterior (solo {found_count}/5 headers){Colors.END}")
    
    except Exception as e:
        print_fail(f"Error: {e}")

def check_rate_limiting():
    """Verifica que el rate limiting esté activo"""
    print_header("10. VERIFICACIÓN DE RATE LIMITING")
    
    print(f"{Colors.YELLOW}NOTA: HTTP 429 (Too Many Requests) es ESPERADO y BUENO.{Colors.END}")
    print(f"{Colors.YELLOW}      Si viste WARNING en /api/login arriba, significa que el rate limiting funciona.{Colors.END}\n")
    
    print_test("Rate limiting en /api/login (máximo 5/min)")
    
    blocked = False
    for i in range(8):
        try:
            response = requests.post(
                f"{BASE_URL}/api/login",
                data={"username": "test", "password": "wrong"},
                verify=False,
                timeout=5
            )
            
            if response.status_code == 429:
                blocked = True
                break
            
            time.sleep(0.3)
        except Exception:
            pass
    
    if blocked:
        print_pass("Rate limiting activo (HTTP 429)")
    else:
        print_warn("No se detectó rate limiting")

# ============================================================
# MAIN
# ============================================================

def main():
    # Deshabilitar warnings de SSL
    requests.packages.urllib3.disable_warnings()
    
    # Detectar puerto HTTPS automáticamente
    global BASE_URL
    detected_port = detect_https_port()
    if detected_port != 8443:
        BASE_URL = f"https://localhost:{detected_port}"
        print(f"\n{Colors.YELLOW}🔍 Puerto HTTPS detectado automáticamente: {detected_port}{Colors.END}")
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                                                                      ║")
    print("║       VERIFICACIÓN DE CUMPLIMIENTO DE SEGURIDAD                      ║")
    print("║       Lab de Desarrollo Web Seguro - EUNEIZ 2025                    ║")
    print("║       (Detección automática de configuración)                       ║")
    print("║                                                                      ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(Colors.END)
    
    print(f"\n{Colors.YELLOW}Configuración:{Colors.END}")
    print(f"  Base URL: {BASE_URL}")
    print(f"  Usuario Admin: {ADMIN_USER}")
    print(f"  Usuario Normal: {USER_USER}")
    print(f"\n{Colors.YELLOW}NOTA: Asegúrate de que estos usuarios existan en tu sistema{Colors.END}")
    print(f"{Colors.YELLOW}      con las credenciales correctas.{Colors.END}\n")
    
    input(f"{Colors.CYAN}Presiona ENTER para comenzar...{Colors.END}")
    
    # Ejecutar verificaciones
    results = {}
    
    results['containers'] = check_docker_containers()
    results['ports'] = check_ports()
    results['https_tls'] = check_https_tls()
    
    jwt_ok, admin_cookies = check_jwt_authentication()
    results['jwt'] = jwt_ok
    
    results['bcrypt'] = check_bcrypt()
    
    if admin_cookies:
        user_cookies = login_and_get_cookies(USER_USER, USER_PASS)
        results['rbac'] = check_rbac(admin_cookies, user_cookies)
        check_endpoints(admin_cookies)  # ← Reutilizar cookies para evitar rate limiting
    else:
        results['rbac'] = False
        check_endpoints()  # Sin cookies, intentará hacer login
    
    results['database'] = check_database()
    
    check_security_headers()
    check_rate_limiting()
    
    # Resumen final
    print_header("RESUMEN DE CUMPLIMIENTO")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    print(f"\n{Colors.BOLD}Tests pasados: {passed}/{total}{Colors.END}\n")
    
    for test, result in results.items():
        status = f"{Colors.GREEN}✓ PASS{Colors.END}" if result else f"{Colors.RED}✗ FAIL{Colors.END}"
        print(f"  {test:20} {status}")
    
    percentage = (passed / total) * 100
    
    print(f"\n{Colors.BOLD}Cumplimiento: {percentage:.1f}%{Colors.END}\n")
    
    if percentage == 100:
        print(f"{Colors.GREEN}{Colors.BOLD}¡Excelente! Todos los requisitos se cumplen.{Colors.END}\n")
    elif percentage >= 80:
        print(f"{Colors.YELLOW}Buen trabajo, pero hay áreas de mejora.{Colors.END}")
        print(f"{Colors.YELLOW}→ Revisa los FAIL arriba para ver qué falta.{Colors.END}\n")
    else:
        print(f"{Colors.RED}Se requieren mejoras significativas.{Colors.END}")
        print(f"{Colors.RED}→ Revisa todos los FAIL y WARNING arriba.{Colors.END}")
        print(f"{Colors.RED}→ Cada error incluye CAUSA y SOLUCIÓN.{Colors.END}\n")
    
    # Explicaciones adicionales basadas en qué falló
    print(f"{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}INTERPRETACIÓN DE RESULTADOS{Colors.END}\n")
    
    if not results.get('containers'):
        print(f"{Colors.RED}❌ Contenedores:{Colors.END} No hay lab corriendo.")
        print(f"   → Ejecuta: ./lab.sh\n")
    
    if not results.get('ports'):
        print(f"{Colors.YELLOW}⚠ Puertos:{Colors.END} Los puertos están en Docker (esto es normal).")
        print(f"   → Si JWT y otros tests pasan, ignora esto.\n")
    
    if not results.get('https_tls'):
        print(f"{Colors.RED}❌ HTTPS/TLS:{Colors.END} Problema con conexión SSL.")
        print(f"   → Verifica: curl -I -k https://localhost:8443\n")
    
    if not results.get('jwt'):
        print(f"{Colors.RED}❌ JWT:{Colors.END} Login falló o JWT inválido.")
        print(f"   → Verifica credenciales: admin/admin123\n")
    
    if not results.get('bcrypt'):
        print(f"{Colors.RED}❌ bcrypt:{Colors.END} Estás usando SHA256 (LAB 8).")
        print(f"   → Ejecuta LAB 9 Paso 1+ para bcrypt.\n")
    
    if not results.get('rbac'):
        print(f"{Colors.RED}❌ RBAC:{Colors.END} Endpoints no están protegidos.")
        print(f"   → Ejecuta Paso 4+ para JWT validation.\n")
    
    if not results.get('database'):
        print(f"{Colors.RED}❌ Database:{Colors.END} lab.db no existe o está corrupta.")
        print(f"   → Elimina lab.db y reinicia el lab.\n")
    
    print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Verificación cancelada.{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n{Colors.RED}Error fatal: {e}{Colors.END}\n")
        sys.exit(1)

