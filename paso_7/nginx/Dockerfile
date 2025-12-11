# Dockerfile para NGINX - Paso 5: HTTPS con TLS 1.3
FROM nginx:alpine

# Copiar configuración de NGINX
COPY nginx.conf /etc/nginx/nginx.conf

# Copiar certificados SSL (ya generados en paso_4)
COPY certs/server.crt /etc/nginx/certs/server.crt
COPY certs/server.key /etc/nginx/certs/server.key

# Dar permisos correctos a los certificados
RUN chmod 644 /etc/nginx/certs/server.crt && \
    chmod 600 /etc/nginx/certs/server.key

# Exponer puertos
EXPOSE 80 443

# Comando por defecto (ejecutar como root para poder leer server.key)
CMD ["nginx", "-g", "daemon off;"]
