#!/bin/sh
#
# Script de captura de tráfico con tcpdump (Educativo)
# Captura tráfico HTTP en el contenedor MITM
#

echo "═══════════════════════════════════════════════════════════"
echo "  Iniciando captura de tráfico (tcpdump)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Capturando tráfico en interfaz: eth0"
echo "  Archivos guardados en: /captures/"
echo "  SOLO PARA FINES EDUCATIVOS"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

# Crear timestamp para el nombre del archivo
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="/captures/capture_${TIMESTAMP}.pcap"

# Crear enlace simbólico "latest.pcap" apuntando al archivo actual
ln -sf "capture_${TIMESTAMP}.pcap" /captures/latest.pcap

# Capturar tráfico HTTP (puerto 8000)
# -i eth0: interfaz
# -s 0: capturar paquete completo
# -w: escribir a archivo
# port 8000: solo tráfico del backend

echo "[INFO] Iniciando tcpdump..."
echo "[INFO] Archivo: $CAPTURE_FILE"
echo "[INFO] Enlace simbólico: /captures/latest.pcap → capture_${TIMESTAMP}.pcap"
echo ""

tcpdump -i eth0 -s 0 -w "$CAPTURE_FILE" 'port 8000' 2>&1 | while read line; do
    echo "[tcpdump] $line"
done

# Si tcpdump termina (no debería), reiniciar
sleep 5
exec "$0"

