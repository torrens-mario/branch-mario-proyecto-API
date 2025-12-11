/**
 * Lógica de la página de login
 */

// Verificar que no esté ya autenticado
requireGuest();

// Referencias al DOM
const loginForm = document.getElementById('login-form');
const submitButton = loginForm.querySelector('button[type="submit"]');

// Event listener para el formulario
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Limpiar mensajes anteriores
    clearMessages();
    
    // Obtener valores del formulario
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    // Validación básica del lado del cliente
    if (!username || username.length < 3) {
        showMessage('El usuario debe tener al menos 3 caracteres', 'error');
        return;
    }
    
    if (!password || password.length < 8) {
        showMessage('La contraseña debe tener al menos 8 caracteres', 'error');
        return;
    }
    
    // Establecer estado de carga
    setButtonLoading(submitButton, true);
    
    try {
        // Realizar petición al backend
        const response = await postData('/api/login', {
            username: username,
            password: password
        });
        
        // Verificar respuesta
        if (response.success) {
            // PASO 3: Guardar solo datos del usuario (token está en cookie HttpOnly)
            setStorage('user', {
                user_id: response.user_id,
                username: response.username,
                email: response.email,
                role: response.role
                // ← token NO guardado (está en cookie HttpOnly, inaccesible desde JS)
            });
            
            showMessage('Inicio de sesión exitoso. Redirigiendo...', 'success', 2000);
            
            // Redirigir al dashboard después de 2 segundos
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 2000);
        } else {
            showMessage(response.message || 'Credenciales incorrectas', 'error');
            setButtonLoading(submitButton, false);
        }
    } catch (error) {
        console.error('Error en login:', error);
        showMessage('Error al conectar con el servidor. Verifica tu conexión.', 'error');
        setButtonLoading(submitButton, false);
    }
});

// Añadir evento para mostrar/ocultar contraseña (opcional)
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    
    // Focus automático en el campo de usuario
    document.getElementById('username').focus();
});

