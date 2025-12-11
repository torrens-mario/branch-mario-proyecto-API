/**
 * Utilidades compartidas - Laboratorio de Desarrollo Web Seguro
 */

/**
 * Muestra un mensaje en el contenedor de mensajes
 * @param {string} message - Mensaje a mostrar
 * @param {string} type - Tipo: 'success', 'error', 'warning', 'info'
 * @param {number} duration - Duración en ms (0 = no auto-ocultar)
 */
function showMessage(message, type = 'info', duration = 5000) {
    const container = document.getElementById('message-container');
    if (!container) return;
    
    // Crear elemento de mensaje
    const messageEl = document.createElement('div');
    messageEl.className = `message message-${type}`;
    messageEl.textContent = message;
    
    // Añadir al contenedor
    container.appendChild(messageEl);
    
    // Auto-ocultar si se especificó duración
    if (duration > 0) {
        setTimeout(() => {
            messageEl.style.animation = 'fadeOut 0.3s ease';
            setTimeout(() => {
                messageEl.remove();
            }, 300);
        }, duration);
    }
}

/**
 * Limpia todos los mensajes
 */
function clearMessages() {
    const container = document.getElementById('message-container');
    if (container) {
        container.innerHTML = '';
    }
}

/**
 * Valida un email
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Valida un username (solo alfanuméricos y guiones bajos)
 * @param {string} username
 * @returns {boolean}
 */
function isValidUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,50}$/;
    return usernameRegex.test(username);
}

/**
 * Evalúa la fortaleza de una contraseña
 * @param {string} password
 * @returns {object} {score: 0-3, text: 'weak|medium|strong'}
 */
function getPasswordStrength(password) {
    let score = 0;
    
    if (!password) return { score: 0, text: 'Muy débil' };
    
    // Longitud
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    
    // Complejidad
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z\d]/.test(password)) score++;
    
    // Normalizar a 0-3
    score = Math.min(Math.floor(score / 2), 3);
    
    const strengths = {
        0: { text: 'Muy débil', level: 'weak' },
        1: { text: 'Débil', level: 'weak' },
        2: { text: 'Media', level: 'medium' },
        3: { text: 'Fuerte', level: 'strong' }
    };
    
    return strengths[score];
}

/**
 * Sanitiza una cadena HTML para prevenir XSS
 * @param {string} str
 * @returns {string}
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Realiza una petición POST simple (sin REST aún)
 * @param {string} url
 * @param {object} data
 * @returns {Promise<object>}
 */
async function postData(url, data) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams(data),
            credentials: 'include'  // ← PASO 3: Enviar cookies automáticamente
        });
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error en petición:', error);
        throw error;
    }
}

/**
 * Envía datos con PUT (para actualizaciones)
 * @param {string} url
 * @param {object} data
 * @returns {Promise<object>}
 */
async function putData(url, data) {
    try {
        const response = await fetch(url, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams(data),
            credentials: 'include'  // ← PASO 3: Enviar cookies automáticamente
        });
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error en petición PUT:', error);
        throw error;
    }
}

/**
 * Obtiene datos de una URL (GET)
 * @param {string} url
 * @returns {Promise<object>}
 */
async function getData(url) {
    try {
        const response = await fetch(url, {
            method: 'GET',
            credentials: 'include'  // ← PASO 3: Enviar cookies automáticamente
        });
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error en petición:', error);
        throw error;
    }
}

/**
 * Guarda datos en localStorage de forma segura
 * @param {string} key
 * @param {any} value
 */
function setStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
        console.error('Error guardando en localStorage:', error);
    }
}

/**
 * Obtiene datos de localStorage
 * @param {string} key
 * @returns {any|null}
 */
function getStorage(key) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : null;
    } catch (error) {
        console.error('Error leyendo de localStorage:', error);
        return null;
    }
}

/**
 * Elimina datos de localStorage
 * @param {string} key
 */
function removeStorage(key) {
    try {
        localStorage.removeItem(key);
    } catch (error) {
        console.error('Error eliminando de localStorage:', error);
    }
}

/**
 * Limpia todo el localStorage
 */
function clearStorage() {
    try {
        localStorage.clear();
    } catch (error) {
        console.error('Error limpiando localStorage:', error);
    }
}

/**
 * Verifica si el usuario está autenticado (PASO 3)
 * En Paso 3, el token está en cookie HttpOnly (no en localStorage)
 * Solo verificamos que hay datos de usuario guardados
 * La autenticación real la verifica el backend con la cookie
 * @returns {boolean}
 */
function isAuthenticated() {
    const user = getStorage('user');
    // PASO 3: NO buscamos user.token (está en cookie HttpOnly)
    // Solo verificamos que hay datos de usuario
    return user !== null && user.username;
}

/**
 * Redirige si no está autenticado
 */
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = 'index.html';
    }
}

/**
 * Redirige si ya está autenticado
 */
function requireGuest() {
    if (isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }
}

/**
 * Cierra la sesión del usuario (PASO 3)
 * Llama al backend para eliminar cookies y limpia localStorage
 */
async function logout() {
    try {
        // Llamar al backend para eliminar cookies HttpOnly
        await getData('/api/logout');
    } catch (error) {
        console.error('Error en logout:', error);
    } finally {
        // Limpiar localStorage (datos del usuario)
        clearStorage();
        // Redirigir al login
        window.location.href = 'index.html';
    }
}

/**
 * Establece el estado de carga de un botón
 * @param {HTMLButtonElement} button
 * @param {boolean} loading
 */
function setButtonLoading(button, loading) {
    if (loading) {
        button.classList.add('loading');
        button.disabled = true;
    } else {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

/**
 * Maneja errores de forma segura (sin exponer detalles internos)
 * @param {Error} error
 * @returns {string} Mensaje de error seguro para mostrar al usuario
 */
function getSafeErrorMessage(error) {
    // En producción, no expongas detalles del error
    // Por ahora en desarrollo mostramos el mensaje
    return error.message || 'Ha ocurrido un error. Por favor, inténtalo de nuevo.';
}

// Añadir animación fadeOut a los estilos globalmente
if (!document.querySelector('style[data-utils-styles]')) {
    const style = document.createElement('style');
    style.setAttribute('data-utils-styles', 'true');
    style.textContent = `
        @keyframes fadeOut {
            from {
                opacity: 1;
                transform: translateX(0);
            }
            to {
                opacity: 0;
                transform: translateX(-20px);
            }
        }
    `;
    document.head.appendChild(style);
}

