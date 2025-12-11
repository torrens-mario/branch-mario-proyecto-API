/**
 * Lógica de la página de registro
 */

// Verificar que no esté ya autenticado
requireGuest();

// Referencias al DOM
const registerForm = document.getElementById('register-form');
const submitButton = registerForm.querySelector('button[type="submit"]');
const passwordInput = document.getElementById('password');
const passwordConfirmInput = document.getElementById('password-confirm');
const strengthContainer = document.getElementById('password-strength');
const strengthFill = document.getElementById('strength-fill');
const strengthText = document.getElementById('strength-text');

// Event listener para mostrar indicador de fortaleza de contraseña
passwordInput.addEventListener('input', () => {
    const password = passwordInput.value;
    
    if (password.length > 0) {
        strengthContainer.style.display = 'block';
        
        const strength = getPasswordStrength(password);
        
        // Actualizar barra de fortaleza
        strengthContainer.className = `password-strength strength-${strength.level}`;
        strengthText.textContent = strength.text;
    } else {
        strengthContainer.style.display = 'none';
    }
});

// Event listener para verificar que las contraseñas coincidan
passwordConfirmInput.addEventListener('input', () => {
    if (passwordConfirmInput.value.length > 0) {
        if (passwordInput.value !== passwordConfirmInput.value) {
            passwordConfirmInput.setCustomValidity('Las contraseñas no coinciden');
        } else {
            passwordConfirmInput.setCustomValidity('');
        }
    }
});

// Event listener para el formulario
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Limpiar mensajes anteriores
    clearMessages();
    
    // Obtener valores del formulario
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = passwordInput.value;
    const passwordConfirm = passwordConfirmInput.value;
    
    // Validaciones del lado del cliente
    if (!isValidUsername(username)) {
        showMessage('El usuario solo puede contener letras, números y guiones bajos (3-50 caracteres)', 'error');
        return;
    }
    
    if (!isValidEmail(email)) {
        showMessage('El formato del correo electrónico no es válido', 'error');
        return;
    }
    
    if (password.length < 8) {
        showMessage('La contraseña debe tener al menos 8 caracteres', 'error');
        return;
    }
    
    if (password !== passwordConfirm) {
        showMessage('Las contraseñas no coinciden', 'error');
        return;
    }
    
    // Verificar fortaleza de la contraseña
    const strength = getPasswordStrength(password);
    if (strength.level === 'weak') {
        showMessage('La contraseña es demasiado débil. Usa mayúsculas, minúsculas, números y símbolos.', 'warning');
        return;
    }
    
    // Establecer estado de carga
    setButtonLoading(submitButton, true);
    
    try {
        // Realizar petición al backend
        const response = await postData('/api/register', {
            username: username,
            email: email,
            password: password
        });
        
        // Verificar respuesta
        if (response.success) {
            // PASO 3: Guardar solo datos del usuario (token está en cookie HttpOnly)
            setStorage('user', {
                user_id: response.user_id,
                username: response.username,
                email: response.email,
                role: response.role || 'user'
                // ← token NO guardado (está en cookie HttpOnly, inaccesible desde JS)
            });
            
            showMessage('¡Registro exitoso! Redirigiendo al dashboard...', 'success', 2000);
            
            // Redirigir al dashboard después de 2 segundos
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 2000);
        } else {
            showMessage(response.message || 'Error al registrar el usuario', 'error');
            setButtonLoading(submitButton, false);
        }
    } catch (error) {
        console.error('Error en registro:', error);
        showMessage('Error al conectar con el servidor. Verifica tu conexión.', 'error');
        setButtonLoading(submitButton, false);
    }
});

// Focus automático al cargar
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('username').focus();
});

