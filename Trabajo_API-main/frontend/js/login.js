/**
 * Lógica de la página de login
 * VERSIÓN CORREGIDA: Manejo robusto de errores y respuestas
 */

requireGuest();

const loginForm = document.getElementById('login-form');
const submitButton = loginForm.querySelector('button[type="submit"]');

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    clearMessages();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (!username || username.length < 3) {
        showMessage('El usuario debe tener al menos 3 caracteres', 'error');
        return;
    }
    
    if (!password || password.length < 8) {
        showMessage('La contraseña debe tener al menos 8 caracteres', 'error');
        return;
    }
    
    setButtonLoading(submitButton, true);
    
    try {
        console.log('Intentando login con usuario:', username);
        
        // Crear FormData para OAuth2
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);
        
        // Realizar petición directa (no usar postData para login)
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: formData
        });
        
        console.log('Response status:', response.status);
        console.log('Response headers:', [...response.headers.entries()]);
        
        // Leer respuesta como texto primero
        const responseText = await response.text();
        console.log('Response text:', responseText);
        
        // Intentar parsear JSON
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error('Error parseando JSON:', parseError);
            console.error('Respuesta recibida:', responseText);
            
            if (responseText.includes('<!DOCTYPE') || responseText.includes('<html')) {
                throw new Error('La API no está respondiendo correctamente. Verifique que esté ejecutándose en http://localhost:8000');
            }
            
            throw new Error('Respuesta inválida del servidor');
        }
        
        if (!response.ok) {
            throw new Error(data.detail || 'Credenciales incorrectas');
        }
        
        console.log('Login response:', data);
        
        // Verificar que tenemos el token
        if (!data.access_token) {
            throw new Error('No se recibió token de acceso');
        }
        
        // Guardar token
        setStorage('token', data.access_token);
        
        // Obtener información del usuario
        try {
            const userInfo = await getData('/auth/me');
            setStorage('user', userInfo);
            console.log('User info:', userInfo);
        } catch (error) {
            console.warn('No se pudo obtener info del usuario:', error);
            // Guardar datos básicos
            setStorage('user', {
                username: username,
                role: 'user'
            });
        }
        
        showMessage('Inicio de sesión exitoso. Redirigiendo...', 'success', 2000);
        
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 2000);
        
    } catch (error) {
        console.error('Error en login:', error);
        
        let errorMessage = 'Error al iniciar sesión';
        
        if (error.message.includes('API no está respondiendo')) {
            errorMessage = 'No se puede conectar con el servidor. Verifique que la API esté ejecutándose.';
        } else if (error.message.includes('Credenciales')) {
            errorMessage = 'Usuario o contraseña incorrectos';
        } else {
            errorMessage = error.message || 'Error al conectar con el servidor';
        }
        
        showMessage(errorMessage, 'error');
        setButtonLoading(submitButton, false);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('username').focus();
});