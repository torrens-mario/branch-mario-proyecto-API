## COMANDOS DE VERIFICACIÓN CON CURL
### Lab de Desarrollo Web Seguro - EUNEIZ 2025

**Este documento contiene todos los comandos curl para verificar manualmente el cumplimiento de seguridad.**

⚠️ **IMPORTANTE**: 
- Debes tener usuarios reales en tu sistema.
- Por defecto: `admin/admin123` y `user1/user123`
- **Sustituye con TUS CREDENCIALES REALES** si son diferentes.

---

## 📋 ÍNDICE

1. [Verificación de HTTPS, TLS y HTTP/2](#1-verificación-de-https-tls-y-http2)
2. [Verificación de Autenticación JWT](#2-verificación-de-autenticación-jwt)
3. [Verificación de bcrypt](#3-verificación-de-bcrypt)
4. [Verificación de Control de Acceso (RBAC)](#4-verificación-de-control-de-acceso-rbac)
5. [Verificación de Endpoints y Permisos](#5-verificación-de-endpoints-y-permisos)
6. [Verificación de Headers de Seguridad](#6-verificación-de-headers-de-seguridad)
7. [Verificación de Rate Limiting](#7-verificación-de-rate-limiting)
8. [Verificación de Base de Datos](#8-verificación-de-base-de-datos)
9. [Verificación de Contenedores](#9-verificación-de-contenedores)

---

## 1. Verificación de HTTPS, TLS y HTTP/2

### 1.1 Verificar HTTPS está activo

```bash
curl -I https://localhost:8443 -k

# Resultado esperado:
# HTTP/2 200
# server: nginx
# ...
```

**Explicación**:
- `-I`: Solo muestra headers (HEAD request)
- `-k`: Ignora verificación de certificado SSL (para desarrollo)
- Si ves `HTTP/2`, está usando HTTP/2
- Si ves `HTTP/1.1`, está usando HTTP/1.1

---

### 1.2 Verificar TLS 1.3

```bash
openssl s_client -connect localhost:8443 -tls1_3 -brief

# Resultado esperado:
# CONNECTION ESTABLISHED
# Protocol version: TLSv1.3
# Ciphersuite: TLS_AES_256_GCM_SHA384
# ...
```

**Explicación**:
- Si conecta con éxito, TLS 1.3 está activo
- Si falla, puede estar usando TLS 1.2

---

### 1.3 Ver detalles del certificado SSL

```bash
openssl s_client -connect localhost:8443 -showcerts < /dev/null 2>&1 | \
  openssl x509 -text -noout

# Muestra:
# - Validity (validez del certificado)
# - Subject (para quién es el certificado)
# - Issuer (quién lo emitió)
```

---

### 1.4 Forzar HTTP/2

```bash
curl -I --http2 https://localhost:8443 -k

# Si responde con "HTTP/2 200", HTTP/2 está activo
```

---

## 2. Verificación de Autenticación JWT

### 2.1 Login como Admin y capturar cookies

```bash
# ⚠️ SUSTITUYE CON TUS CREDENCIALES REALES
curl -X POST https://localhost:8443/api/login \
  -F "username=admin" \
  -F "password=admin123" \
  -k -c /tmp/admin-cookies.txt -i

# Resultado esperado:
# HTTP/2 200
# set-cookie: auth_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Max-Age=28800
# set-cookie: refresh_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
# {
#   "success": true,
#   "message": "Inicio de sesión exitoso",
#   "user_id": 1,
#   "username": "admin",
#   "role": "admin"
# }
```

**Explicación**:
- `-c /tmp/admin-cookies.txt`: Guarda las cookies en un archivo
- `Max-Age=28800`: 8 horas (8 * 3600 segundos)
- `HttpOnly`: Cookie no accesible desde JavaScript
- `Secure`: Solo se envía por HTTPS
- `SameSite=Strict`: Protección contra CSRF

---

### 2.2 Login como Usuario Normal y capturar cookies

```bash
# ⚠️ SUSTITUYE CON TUS CREDENCIALES REALES
curl -X POST https://localhost:8443/api/login \
  -F "username=user1" \
  -F "password=user123" \
  -k -c /tmp/user-cookies.txt -i

# Resultado esperado: Similar al admin, pero con "role": "user"
```

---

### 2.3 Decodificar JWT para ver su contenido

```bash
# Extraer el auth_token de las cookies
TOKEN=$(grep auth_token /tmp/admin-cookies.txt | awk '{print $7}')

# Decodificar el payload (segunda parte del JWT)
echo $TOKEN | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq .

# Resultado esperado:
# {
#   "sub": 1,
#   "username": "admin",
#   "role": "admin",
#   "exp": 1732623456,  # Timestamp de expiración
#   "iat": 1732594656   # Timestamp de emisión
# }
```

**Explicación**:
- JWT tiene 3 partes: `header.payload.signature`
- El payload contiene los datos del usuario
- `exp`: Timestamp UNIX de cuando expira
- Para verificar 8h: `(exp - iat) / 3600` debe ser ~8

---

### 2.4 Calcular tiempo de expiración del JWT

```bash
# Extraer timestamps
TOKEN=$(grep auth_token /tmp/admin-cookies.txt | awk '{print $7}')
EXP=$(echo $TOKEN | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq -r '.exp')
IAT=$(echo $TOKEN | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq -r '.iat')

# Calcular horas
echo "Tiempo de expiración: $(( ($EXP - $IAT) / 3600 )) horas"

# Resultado esperado: 8 horas
```

---

### 2.5 Verificar que la cookie es HttpOnly

```bash
grep auth_token /tmp/admin-cookies.txt

# Resultado esperado:
# localhost  FALSE  /  TRUE  ....  #HttpOnly_auth_token  eyJ...
#                                   ↑ HttpOnly está presente
```

---

## 3. Verificación de bcrypt

### 3.1 Ver hashes de contraseñas en la base de datos

```bash
docker exec lab-backend python3 -c "
import sqlite3
conn = sqlite3.connect('/app/data/lab.db')
cursor = conn.cursor()
cursor.execute('SELECT username, password FROM users')
for user, pwd in cursor.fetchall():
    print(f'{user}: {pwd[:30]}...')
"

# Resultado esperado:
# admin: $2b$12$abc123...  ← bcrypt (empieza con $2b$12$)
# Profe: $2b$12$def456...
# user1: $2b$12$ghi789...
```

**Explicación de formato bcrypt**:
```
$2b$12$xyz...
 ↑  ↑   ↑
 │  │   └─ Hash + salt (22 caracteres de salt + 31 de hash)
 │  └───── Cost factor (12 = 2^12 = 4096 iteraciones)
 └──────── Algoritmo (2b = bcrypt)
```

---

### 3.2 Verificar cost factor de bcrypt

```bash
docker exec lab-backend python3 -c "
import sqlite3
conn = sqlite3.connect('/app/data/lab.db')
cursor = conn.cursor()
cursor.execute('SELECT password FROM users LIMIT 1')
pwd_hash = cursor.fetchone()[0]
cost = int(pwd_hash.split('$')[2])
print(f'bcrypt cost factor: {cost}')
print(f'Iteraciones: 2^{cost} = {2**cost}')
"

# Resultado esperado:
# bcrypt cost factor: 12
# Iteraciones: 2^12 = 4096
```

---

## 4. Verificación de Control de Acceso (RBAC)

### 4.1 Acceso sin autenticación (debe fallar)

```bash
curl -X GET https://localhost:8443/api/users -k -i

# Resultado esperado:
# HTTP/2 401 Unauthorized
# {
#   "detail": "No autenticado. Falta cookie de autenticación."
# }
```

---

### 4.2 Admin puede listar usuarios

```bash
curl -X GET https://localhost:8443/api/users \
  -k -b /tmp/admin-cookies.txt -i

# Resultado esperado:
# HTTP/2 200 OK
# {
#   "users": [...],
#   "authenticated_as": "admin"
# }
```

---

### 4.3 Usuario normal puede listar usuarios (también tiene permisos)

```bash
curl -X GET https://localhost:8443/api/users \
  -k -b /tmp/user-cookies.txt -i

# Resultado esperado:
# HTTP/2 200 OK (en este lab, los usuarios también pueden ver la lista)
```

---

### 4.4 Usuario normal NO puede cambiar roles (debe fallar)

```bash
curl -X PUT https://localhost:8443/api/users/2 \
  -F "role=admin" \
  -k -b /tmp/user-cookies.txt -i

# Resultado esperado:
# HTTP/2 403 Forbidden
# {
#   "detail": "Solo administradores pueden modificar roles de usuarios"
# }
```

---

### 4.5 Admin SÍ puede cambiar roles

```bash
curl -X PUT https://localhost:8443/api/users/3 \
  -F "role=user" \
  -k -b /tmp/admin-cookies.txt -i

# Resultado esperado:
# HTTP/2 200 OK
# {
#   "success": true,
#   "message": "Usuario actualizado exitosamente"
# }
```

---

### 4.6 Usuario normal NO puede eliminar usuarios (debe fallar)

```bash
curl -X DELETE https://localhost:8443/api/users/3 \
  -k -b /tmp/user-cookies.txt -i

# Resultado esperado:
# HTTP/2 403 Forbidden
```

---

### 4.7 Admin SÍ puede eliminar usuarios

```bash
# ⚠️ CUIDADO: Esto eliminará el usuario con ID 3
curl -X DELETE https://localhost:8443/api/users/3 \
  -k -b /tmp/admin-cookies.txt -i

# Resultado esperado:
# HTTP/2 200 OK
# {
#   "success": true,
#   "message": "Usuario eliminado exitosamente"
# }
```

---

## 5. Verificación de Endpoints y Permisos

### 5.1 Registro (público, no requiere autenticación)

```bash
curl -X POST https://localhost:8443/api/register \
  -F "username=nuevo_usuario" \
  -F "email=nuevo@test.com" \
  -F "password=Test123!" \
  -k -i

# Resultado esperado:
# HTTP/2 200 OK
# {
#   "success": true,
#   "message": "Usuario creado exitosamente"
# }
```

---

### 5.2 Login (público, no requiere autenticación)

```bash
curl -X POST https://localhost:8443/api/login \
  -F "username=admin" \
  -F "password=admin123" \
  -k -i

# Resultado esperado:
# HTTP/2 200 OK
```

---

### 5.3 Logout (requiere autenticación)

```bash
curl -X GET https://localhost:8443/api/logout \
  -k -b /tmp/admin-cookies.txt -i

# Resultado esperado:
# HTTP/2 200 OK
# set-cookie: auth_token=; Max-Age=0  ← Cookie eliminada
# set-cookie: refresh_token=; Max-Age=0
```

---

### 5.4 Listar vulnerabilidades (requiere autenticación)

```bash
curl -X GET https://localhost:8443/api/vulnerabilities \
  -k -b /tmp/admin-cookies.txt

# Resultado esperado:
# {
#   "vulnerabilities": [...],  # 25 CVEs
#   "metadata": {
#     "total_vulnerabilities": 25,
#     "pending": 15,
#     "resolved": 10,
#     ...
#   }
# }
```

---

### 5.5 Obtener estadísticas de vulnerabilidades

```bash
curl -X GET https://localhost:8443/api/vulnerabilities/stats \
  -k -b /tmp/admin-cookies.txt

# Resultado esperado:
# {
#   "total_vulnerabilities": 25,
#   "pending": 15,
#   "resolved": 10,
#   "critical": 8,
#   ...
# }
```

---

### 5.6 Resolver vulnerabilidad (solo admin)

```bash
curl -X PUT https://localhost:8443/api/vulnerabilities/1/resolve \
  -k -b /tmp/admin-cookies.txt -i

# Resultado esperado:
# HTTP/2 200 OK
# {
#   "success": true,
#   "message": "Vulnerabilidad marcada como resuelta",
#   "metadata": {...}  # Estadísticas actualizadas
# }
```

---

## 6. Verificación de Headers de Seguridad

### 6.1 Ver todos los headers de seguridad

```bash
curl -I https://localhost:8443 -k | grep -i -E \
  "content-security-policy|x-frame|x-content-type|strict-transport|x-xss|referrer|permissions"

# Resultado esperado (Paso 7):
# content-security-policy: default-src 'self'; script-src 'self'; ...
# x-frame-options: DENY
# x-content-type-options: nosniff
# x-xss-protection: 1; mode=block
# strict-transport-security: max-age=31536000; includeSubDomains
# referrer-policy: strict-origin-when-cross-origin
# permissions-policy: geolocation=(), microphone=(), camera=()...
```

---

### 6.2 Verificar Content Security Policy (CSP)

```bash
curl -I https://localhost:8443 -k | grep -i "content-security-policy"

# Paso 7 debe incluir:
# - default-src 'self'
# - script-src 'self' (sin 'unsafe-inline')
# - style-src 'self' 'unsafe-inline'
# - frame-ancestors 'none'
```

---

### 6.3 Verificar X-Frame-Options (anti-clickjacking)

```bash
curl -I https://localhost:8443 -k | grep -i "x-frame-options"

# Resultado esperado:
# x-frame-options: DENY  ← Previene carga en iframes
```

---

### 6.4 Verificar HSTS

```bash
curl -I https://localhost:8443 -k | grep -i "strict-transport"

# Resultado esperado:
# strict-transport-security: max-age=31536000; includeSubDomains
#                            ↑ 1 año en segundos
```

---

## 7. Verificación de Rate Limiting

### 7.1 Test de rate limiting en login (límite: 5/minuto)

```bash
echo "Probando rate limiting en /api/login..."
for i in {1..10}; do
  echo -n "Intento $i: "
  STATUS=$(curl -X POST https://localhost:8443/api/login \
    -F "username=test" \
    -F "password=wrong" \
    -k -s -o /dev/null -w "%{http_code}")
  echo "HTTP $STATUS"
  sleep 0.5
done

# Resultado esperado:
# Intentos 1-7: HTTP 401 (credenciales incorrectas, pasa rate limit)
# Intentos 8-10: HTTP 429 (bloqueado por rate limit)
```

**Explicación**:
- NGINX permite 5 peticiones/minuto con burst de 2
- Total: 7 intentos antes de bloquear
- HTTP 429 = Too Many Requests

---

### 7.2 Test de rate limiting en registro (límite: 3/minuto)

```bash
echo "Probando rate limiting en /api/register..."
for i in {1..6}; do
  echo -n "Intento $i: "
  STATUS=$(curl -X POST https://localhost:8443/api/register \
    -F "username=test$i" \
    -F "email=test$i@test.com" \
    -F "password=Test123!" \
    -k -s -o /dev/null -w "%{http_code}")
  echo "HTTP $STATUS"
  sleep 0.5
done

# Resultado esperado:
# Intentos 1-4: HTTP 200 o 400
# Intentos 5-6: HTTP 429
```

---

### 7.3 Ver mensaje de rate limiting

```bash
curl -X POST https://localhost:8443/api/login \
  -F "username=test" -F "password=test" \
  -k -i

# Después de exceder el límite:
# HTTP/2 429
# <html>
# <head><title>429 Too Many Requests</title></head>
# <body>
# <center><h1>429 Too Many Requests</h1></center>
# </body>
# </html>
```

---

## 8. Verificación de Base de Datos

### 8.1 Verificar que lab.db existe

```bash
docker exec lab-backend ls -lh /app/data/lab.db

# Resultado esperado:
# -rw-r--r-- 1 appuser appuser 20K Nov 25 14:30 /app/data/lab.db
```

---

### 8.2 Contar usuarios en la base de datos

```bash
docker exec lab-backend python3 -c "
import sqlite3
conn = sqlite3.connect('/app/data/lab.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM users')
print(f'Total de usuarios: {cursor.fetchone()[0]}')
"

# Resultado esperado:
# Total de usuarios: 3
```

---

### 8.3 Ver estructura de la tabla users

```bash
docker exec lab-backend python3 -c "
import sqlite3
conn = sqlite3.connect('/app/data/lab.db')
cursor = conn.cursor()
cursor.execute('PRAGMA table_info(users)')
for col in cursor.fetchall():
    print(f'{col[1]}: {col[2]}')
"

# Resultado esperado:
# user_id: INTEGER
# username: TEXT
# email: TEXT
# password: TEXT
# role: TEXT
# created_at: TEXT
```

---

### 8.4 Ver todos los usuarios (sin contraseñas)

```bash
docker exec lab-backend python3 -c "
import sqlite3
conn = sqlite3.connect('/app/data/lab.db')
cursor = conn.cursor()
cursor.execute('SELECT user_id, username, email, role, created_at FROM users')
for row in cursor.fetchall():
    print(f'{row[0]}: {row[1]} ({row[3]}) - {row[2]}')
"

# Resultado esperado:
# 1: admin (admin) - admin@lab.local
# 2: Profe (admin) - profe@euneiz.es
# 3: user1 (user) - user1@test.com
```

---

## 9. Verificación de Contenedores

### 9.1 Ver contenedores corriendo

```bash
docker ps --filter "name=lab-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Resultado esperado:
# NAMES          STATUS              PORTS
# lab-nginx      Up (healthy)        0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp
# lab-backend    Up (healthy)        8000/tcp
# lab-mitm       Up (healthy)        8000/tcp
# lab-database   Up                  -
```

---

### 9.2 Ver logs del backend

```bash
docker logs lab-backend --tail 50

# Debe mostrar:
# - Uvicorn running on http://0.0.0.0:8000
# - Application startup complete
# - Usuarios por defecto creados
# - Endpoints de vulnerabilidades disponibles
```

---

### 9.3 Ver logs de NGINX

```bash
docker logs lab-nginx --tail 50

# Debe mostrar accesos HTTPS:
# 172.20.0.1 - - [25/Nov/2025:14:30:00 +0000] "POST /api/login HTTP/2.0" 200 ...
```

---

### 9.4 Verificar salud del backend

```bash
docker exec lab-backend curl http://localhost:8000/health

# Resultado esperado:
# {"status":"healthy","timestamp":"2025-11-25T..."}
```

---

### 9.5 Ver volúmenes Docker

```bash
docker volume ls | grep lab-

# Resultado esperado:
# lab-backend-data
# lab-db-data
# lab-logs-data    ← NUEVO en Paso 7
```

---

### 9.6 Ver logs de seguridad (Paso 7)

```bash
docker exec lab-backend tail -20 /app/logs/security.log | jq .

# Resultado esperado (formato JSON):
# {
#   "timestamp": "2025-11-25T14:32:15.123456",
#   "event": "login_success",
#   "username": "admin",
#   "role": "admin",
#   "ip": "172.20.0.1",
#   "severity": "INFO"
# }
```

---

## 🎯 RESUMEN DE VERIFICACIONES

### Checklist Rápido

```bash
# 1. HTTPS + TLS 1.3 + HTTP/2
curl -I --http2 -k https://localhost:8443 | head -1
# ✓ Debe mostrar: HTTP/2 200

# 2. JWT con 8h
TOKEN=$(curl -X POST https://localhost:8443/api/login -F username=admin -F password=admin123 -k -c /tmp/cookies.txt -s | jq -r '.success')
EXP=$(grep auth_token /tmp/cookies.txt | awk '{print $7}' | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq -r '.exp')
IAT=$(grep auth_token /tmp/cookies.txt | awk '{print $7}' | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq -r '.iat')
echo "JWT expira en: $(( ($EXP - $IAT) / 3600 )) horas"
# ✓ Debe mostrar: 8 horas

# 3. bcrypt cost 12
docker exec lab-backend python3 -c "import sqlite3; conn=sqlite3.connect('/app/data/lab.db'); print(conn.execute('SELECT password FROM users LIMIT 1').fetchone()[0][:7])"
# ✓ Debe mostrar: $2b$12$ o $2a$12$

# 4. RBAC funciona
curl -X GET https://localhost:8443/api/users -k -s -o /dev/null -w "%{http_code}"
# ✓ Debe mostrar: 401 (sin autenticación)

curl -X GET https://localhost:8443/api/users -k -b /tmp/cookies.txt -s -o /dev/null -w "%{http_code}"
# ✓ Debe mostrar: 200 (con autenticación admin)

# 5. Headers de seguridad (Paso 7)
curl -I -k https://localhost:8443 | grep -c -E "content-security-policy|x-frame-options|strict-transport"
# ✓ Debe mostrar: 3 o más

# 6. Rate limiting
for i in {1..10}; do curl -X POST https://localhost:8443/api/login -F username=test -F password=test -k -s -o /dev/null -w "%{http_code}\n"; sleep 0.3; done | grep -c 429
# ✓ Debe mostrar: 2 o más (bloqueados)

# 7. Base de datos
docker exec lab-backend python3 -c "import sqlite3; print(sqlite3.connect('/app/data/lab.db').execute('SELECT COUNT(*) FROM users').fetchone()[0])"
# ✓ Debe mostrar: 3 o más

# 8. Contenedores
docker ps --filter "name=lab-" | wc -l
# ✓ Debe mostrar: 5 (header + 4 contenedores)
```

---

## 📚 REFERENCIAS

- **OWASP Top 10 (2021)**: https://owasp.org/Top10/
- **JWT Best Practices**: https://datatracker.ietf.org/doc/html/rfc8725
- **bcrypt**: https://en.wikipedia.org/wiki/Bcrypt
- **TLS 1.3**: https://datatracker.ietf.org/doc/html/rfc8446
- **HTTP/2**: https://datatracker.ietf.org/doc/html/rfc7540

---

**Autor**: Lab de Desarrollo Web Seguro - EUNEIZ 2025  
**Versión**: 1.0.0  
**Última actualización**: 25 de Noviembre de 2025

