#!/bin/sh
#
# Script para generar certificados SSL/TLS autofirmados
# Para uso educativo en laboratorio
#

echo "═══════════════════════════════════════════════════════════"
echo "  Generando certificados SSL/TLS autofirmados"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Generar clave privada RSA 2048 bits
openssl genrsa -out server.key 2048

# Generar certificado autofirmado (válido 365 días)
openssl req -new -x509 \
    -key server.key \
    -out server.crt \
    -days 365 \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=EUNEIZ/OU=Lab Seguridad/CN=localhost"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Certificados generados exitosamente"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Archivos creados:"
echo "    - server.key (clave privada)"
echo "    - server.crt (certificado)"
echo ""
echo "  ⚠️  IMPORTANTE: Estos son certificados AUTOFIRMADOS"
echo "      El navegador mostrará advertencia de seguridad"
echo "      En producción, usa certificados de CA confiable"
echo ""
echo "═══════════════════════════════════════════════════════════"


