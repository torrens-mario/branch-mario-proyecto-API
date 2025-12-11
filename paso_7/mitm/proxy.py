#!/usr/bin/env python3
"""
Man-in-the-Middle Proxy Transparente (Educativo)
Reenvía tráfico entre NGINX y Backend, permitiendo captura con tcpdump
"""

import socket
import threading
import os
import sys

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 8000
BACKEND_HOST = os.getenv('BACKEND_HOST', 'backend')
BACKEND_PORT = int(os.getenv('BACKEND_PORT', '8000'))

print(f"""
╔══════════════════════════════════════════════════════════╗
║  Man-in-the-Middle Proxy (Educativo)                     ║
║  ⚠️  SOLO PARA FINES EDUCATIVOS EN LABORATORIO           ║
╠══════════════════════════════════════════════════════════╣
║  Escuchando en: {LISTEN_HOST}:{LISTEN_PORT}              ║
║  Redirigiendo a: {BACKEND_HOST}:{BACKEND_PORT}           ║
║                                                          ║
║  Este proxy intercepta y reenvía tráfico HTTP SIN        ║
║  cifrar, permitiendo captura con tcpdump.                ║
╚══════════════════════════════════════════════════════════╝
""")

def forward_data(source, destination, direction):
    """
    Reenvía datos entre source y destination
    direction: 'client->backend' o 'backend->client'
    """
    try:
        while True:
            data = source.recv(4096)
            if len(data) == 0:
                break
            
            # Logging (sin datos sensibles en producción)
            print(f"[{direction}] {len(data)} bytes")
            
            destination.sendall(data)
    except Exception as e:
        print(f"[Error] {direction}: {e}")
    finally:
        source.close()
        destination.close()


def handle_client(client_socket, client_address):
    """
    Maneja conexión de un cliente (NGINX)
    """
    print(f"[Conexión] Cliente conectado: {client_address}")
    
    try:
        # Conectar al backend real
        backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_socket.connect((BACKEND_HOST, BACKEND_PORT))
        print(f"[Conexión] Conectado al backend: {BACKEND_HOST}:{BACKEND_PORT}")
        
        # Crear hilos para reenvío bidireccional
        thread_client_to_backend = threading.Thread(
            target=forward_data,
            args=(client_socket, backend_socket, f"{client_address} → backend")
        )
        thread_backend_to_client = threading.Thread(
            target=forward_data,
            args=(backend_socket, client_socket, f"backend → {client_address}")
        )
        
        thread_client_to_backend.start()
        thread_backend_to_client.start()
        
        thread_client_to_backend.join()
        thread_backend_to_client.join()
        
    except Exception as e:
        print(f"[Error] Manejando cliente {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"[Desconexión] Cliente desconectado: {client_address}")


def main():
    """
    Servidor proxy principal
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(5)
        print(f"\n[Servidor] Escuchando en {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[Servidor] Proxy MITM activo - Tráfico HTTP sin cifrar\n")
        
        while True:
            client_socket, client_address = server_socket.accept()
            
            # Manejar cada cliente en un hilo separado
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[Servidor] Deteniendo proxy...")
    except Exception as e:
        print(f"[Error] Servidor: {e}")
    finally:
        server_socket.close()


if __name__ == '__main__':
    main()

