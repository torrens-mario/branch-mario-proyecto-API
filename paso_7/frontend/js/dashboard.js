/**
 * Lógica del dashboard
 */

// Verificar que esté autenticado
requireAuth();

// Obtener datos del usuario
const user = getStorage('user');

// Compatibilidad: si tiene 'id' en lugar de 'user_id', convertirlo
if (user && user.id && !user.user_id) {
    user.user_id = user.id;
    setStorage('user', user); // Actualizar en localStorage
}

// Referencias al DOM
const userName = document.getElementById('user-name');
const userRole = document.getElementById('user-role');
const logoutButton = document.getElementById('btn-logout');
const navItems = document.querySelectorAll('.nav-item');
const contentViews = document.querySelectorAll('.content-view');

// Mostrar información del usuario
if (user) {
    userName.textContent = user.username;
    userRole.textContent = user.role === 'admin' ? 'Administrador' : 'Usuario';
    
    // Si es usuario normal, ocultar ciertas opciones
    if (user.role !== 'admin') {
        // En pasos posteriores, se ocultarán funciones de admin
    }
}

// Event listener para navegación entre vistas
navItems.forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        
        const viewName = item.getAttribute('data-view');
        
        // Remover clase active de todos los items
        navItems.forEach(nav => nav.classList.remove('active'));
        
        // Añadir clase active al item clickeado
        item.classList.add('active');
        
        // Ocultar todas las vistas
        contentViews.forEach(view => view.classList.remove('active'));
        
        // Mostrar la vista correspondiente
        const targetView = document.getElementById(`view-${viewName}`);
        if (targetView) {
            targetView.classList.add('active');
        }
        
        // Actualizar URL hash
        window.location.hash = viewName;
    });
});

// Event listener para el botón de logout
logoutButton.addEventListener('click', async (e) => {
    e.preventDefault();
    
    // Intentar cerrar sesión en el servidor
    try {
        await getData('/api/logout');
    } catch (error) {
        console.error('Error al cerrar sesión en el servidor:', error);
    }
    
    // Limpiar almacenamiento local y redirigir
    logout();
});

// Manejar navegación por hash (para volver a una vista específica)
window.addEventListener('load', () => {
    const hash = window.location.hash.substring(1);
    if (hash) {
        const navItem = document.querySelector(`[data-view="${hash}"]`);
        if (navItem) {
            navItem.click();
        }
    }
});

// Event listener para el botón "Nueva Vulnerabilidad" (funcionalidad futura)
const btnNewVuln = document.getElementById('btn-new-vuln');
if (btnNewVuln) {
    btnNewVuln.addEventListener('click', () => {
        alert('Funcionalidad "Nueva Vulnerabilidad" se implementará en el Paso 6');
    });
}

// Cargar lista de usuarios (solo para admin)
async function loadUsers() {
    const usersContainer = document.getElementById('users-list-container');
    const profileContainer = document.getElementById('user-profile-container');
    
    if (!usersContainer) return;
    
    // Ocultar perfil, mostrar lista de usuarios
    if (profileContainer) profileContainer.style.display = 'none';
    usersContainer.style.display = 'block';
    
    try {
        const response = await getData('/api/users');
        
        if (response.success) {
            const users = response.users;
            
            // Crear tabla de usuarios
            let tableHTML = `
                <table class="users-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Usuario</th>
                            <th>Email</th>
                            <th>Rol</th>
                            <th>Creado</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            users.forEach(u => {
                const roleClass = u.role === 'admin' ? 'role-admin' : 'role-user';
                const canDelete = u.username !== 'admin' && u.username !== 'Profe';
                
                tableHTML += `
                    <tr>
                        <td>${u.user_id}</td>
                        <td><strong>${sanitizeHTML(u.username)}</strong></td>
                        <td>${sanitizeHTML(u.email)}</td>
                        <td><span class="role-badge ${roleClass}">${u.role}</span></td>
                        <td>${new Date(u.created_at).toLocaleDateString()}</td>
                        <td class="actions-cell">
                            ${u.role === 'user' ? 
                                `<button class="btn-action btn-promote" onclick="changeUserRole(${u.user_id}, 'admin')">
                                    Hacer Admin
                                </button>` : 
                                `<button class="btn-action btn-demote" onclick="changeUserRole(${u.user_id}, 'user')">
                                    Quitar Admin
                                </button>`
                            }
                            ${canDelete ? 
                                `<button class="btn-action btn-delete" onclick="deleteUser(${u.user_id}, '${u.username}')">
                                    Eliminar
                                </button>` : 
                                `<button class="btn-action btn-delete" disabled>
                                    No eliminar
                                </button>`
                            }
                        </td>
                    </tr>
                `;
            });
            
            tableHTML += `
                    </tbody>
                </table>
            `;
            
            usersContainer.innerHTML = tableHTML;
        } else {
            usersContainer.innerHTML = `<p class="error-message">Error al cargar usuarios</p>`;
        }
    } catch (error) {
        console.error('Error cargando usuarios:', error);
        usersContainer.innerHTML = `<p class="error-message">Error al conectar con el servidor</p>`;
    }
}

// Cambiar rol de usuario
async function changeUserRole(userId, newRole) {
    if (!confirm(`¿Cambiar rol del usuario a "${newRole}"?`)) {
        return;
    }
    
    try {
        // PASO 4: Usar PUT (no POST) con Form data para actualizar rol
        const response = await putData(`/api/users/${userId}`, {
            role: newRole
        });
        
        if (response.success) {
            showMessage(`Rol actualizado a "${newRole}" correctamente`, 'success');
            await loadUsers(); // Recargar lista
        } else {
            showMessage(response.message || 'Error al actualizar rol', 'error');
        }
    } catch (error) {
        console.error('Error cambiando rol:', error);
        showMessage('Error al conectar con el servidor', 'error');
    }
}

// Eliminar usuario
async function deleteUser(userId, username) {
    if (!confirm(`¿Estás seguro de eliminar el usuario "${username}"?`)) {
        return;
    }
    
    try {
        // PASO 4: DELETE con cookies incluidas
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE',
            credentials: 'include'  // ← PASO 3: Enviar cookies automáticamente
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage(`Usuario "${username}" eliminado correctamente`, 'success');
            await loadUsers(); // Recargar lista
        } else {
            showMessage(data.message || 'Error al eliminar usuario', 'error');
        }
    } catch (error) {
        console.error('Error eliminando usuario:', error);
        showMessage('Error al conectar con el servidor', 'error');
    }
}

// Cargar perfil del usuario actual
async function loadCurrentUserProfile() {
    const profileContainer = document.getElementById('user-profile-container');
    const usersContainer = document.getElementById('users-list-container');
    
    if (!profileContainer) return;
    
    // Ocultar lista de usuarios, mostrar perfil
    if (usersContainer) usersContainer.style.display = 'none';
    profileContainer.style.display = 'block';
    
    try {
        const response = await getData(`/api/users/${user.user_id}`);
        
        if (response.success) {
            const u = response.user;
            
            let profileHTML = `
                <div class="profile-card">
                    <h3>Mi Perfil</h3>
                    <div class="profile-field">
                        <label>Usuario:</label>
                        <span>${sanitizeHTML(u.username)}</span>
                    </div>
                    <div class="profile-field">
                        <label>Email:</label>
                        <span>${sanitizeHTML(u.email)}</span>
                    </div>
                    <div class="profile-field">
                        <label>Hash de Contraseña:</label>
                        <code>${u.password_hash}</code>
                    </div>
                    <div class="profile-field">
                        <label>Rol:</label>
                        <span class="role-badge ${u.role === 'admin' ? 'role-admin' : 'role-user'}">${u.role}</span>
                    </div>
                    <div class="profile-field">
                        <label>Cuenta creada:</label>
                        <span>${new Date(u.created_at).toLocaleString()}</span>
                    </div>
                </div>
            `;
            
            profileContainer.innerHTML = profileHTML;
        } else {
            profileContainer.innerHTML = `<p class="error-message">Error al cargar perfil</p>`;
        }
    } catch (error) {
        console.error('Error cargando perfil:', error);
        profileContainer.innerHTML = `<p class="error-message">Error al conectar con el servidor</p>`;
    }
}

// Exponer funciones globalmente para onclick
window.changeUserRole = changeUserRole;
window.deleteUser = deleteUser;

// ============================================================
// DASHBOARD DE VULNERABILIDADES CVE (Paso 6)
// ============================================================

// Estado global CVE
let vulnerabilities = [];
let cveMetadata = {};
let progressChart = null;
let selectedVulnId = null;

/**
 * Carga todas las vulnerabilidades desde la API
 */
async function loadVulnerabilities() {
    try {
        showMessage('Cargando vulnerabilidades...', 'info', 2000);
        
        const response = await getData('/api/vulnerabilities');
        
        if (response.success) {
            vulnerabilities = response.vulnerabilities;
            cveMetadata = response.metadata;
            
            // Actualizar todas las secciones
            updateSummarySection();
            updateChartSection();
            updatePendingTable();
            updateResolvedTable();
            
            showMessage('Vulnerabilidades cargadas correctamente', 'success', 2000);
        } else {
            throw new Error(response.message || 'Error desconocido');
        }
    } catch (error) {
        console.error('Error cargando vulnerabilidades:', error);
        showMessage('Error al cargar vulnerabilidades: ' + error.message, 'error');
    }
}

/**
 * Actualiza la sección de resumen (Sección 1)
 */
function updateSummarySection() {
    document.getElementById('stat-total').textContent = cveMetadata.total_vulnerabilities || 0;
    document.getElementById('stat-pending').textContent = cveMetadata.pending || 0;
    document.getElementById('stat-resolved').textContent = cveMetadata.resolved || 0;
    document.getElementById('stat-critical').textContent = cveMetadata.critical || 0;
}

/**
 * Actualiza el gráfico circular (Sección 2)
 */
function updateChartSection() {
    const ctx = document.getElementById('progressChart').getContext('2d');
    
    // Destruir gráfico anterior si existe
    if (progressChart) {
        progressChart.destroy();
    }
    
    // Crear nuevo gráfico
    progressChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Pendientes', 'Resueltas'],
            datasets: [{
                data: [cveMetadata.pending || 0, cveMetadata.resolved || 0],
                backgroundColor: [
                    '#f59e0b', // Pendientes (amarillo/naranja)
                    '#10b981'  // Resueltas (verde)
                ],
                borderWidth: 3,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = cveMetadata.total_vulnerabilities || 0;
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    // Actualizar leyenda
    document.getElementById('legend-pending').textContent = cveMetadata.pending || 0;
    document.getElementById('legend-resolved').textContent = cveMetadata.resolved || 0;
}

/**
 * Actualiza la tabla de vulnerabilidades pendientes (Sección 3)
 * PASO 7: IMPLEMENTACIÓN SEGURA con createElement() - Sin XSS, sin onclick inline
 */
function updatePendingTable() {
    const tbody = document.getElementById('pending-table-body');
    const pending = vulnerabilities.filter(v => v.status === 'pending');
    
    // Ordenar por severidad (CRITICAL > HIGH > MEDIUM > LOW) y luego por CVSS score
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
    pending.sort((a, b) => {
        if (severityOrder[a.severity] !== severityOrder[b.severity]) {
            return severityOrder[a.severity] - severityOrder[b.severity];
        }
        return b.cvss_score - a.cvss_score;
    });
    
    // Limpiar tabla
    tbody.innerHTML = '';
    
    if (pending.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'loading';
        td.textContent = '¡No hay vulnerabilidades pendientes!';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    
    // Crear filas usando createElement() para seguridad total
    pending.forEach(vuln => {
        const tr = document.createElement('tr');
        
        // Columna 1: CVE (con link)
        const tdCve = document.createElement('td');
        const linkCve = document.createElement('a');
        linkCve.href = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(vuln.cve)}`;
        linkCve.target = '_blank';
        linkCve.rel = 'noopener noreferrer'; // PASO 7: Previene tabnabbing
        linkCve.className = 'cve-link';
        linkCve.textContent = vuln.cve; // textContent previene XSS automáticamente
        tdCve.appendChild(linkCve);
        tr.appendChild(tdCve);
        
        // Columna 2: Título
        const tdTitle = document.createElement('td');
        const strongTitle = document.createElement('strong');
        strongTitle.textContent = vuln.title; // PASO 7: No necesita sanitizeHTML()
        tdTitle.appendChild(strongTitle);
        tr.appendChild(tdTitle);
        
        // Columna 3: Severidad
        const tdSeverity = document.createElement('td');
        const spanSeverity = document.createElement('span');
        spanSeverity.className = `severity-badge severity-${vuln.severity.toLowerCase()}`;
        spanSeverity.textContent = vuln.severity; // PASO 7: Seguro
        tdSeverity.appendChild(spanSeverity);
        tr.appendChild(tdSeverity);
        
        // Columna 4: CVSS Score
        const tdCvss = document.createElement('td');
        const strongCvss = document.createElement('strong');
        strongCvss.textContent = vuln.cvss_score.toString(); // PASO 7: Seguro
        tdCvss.appendChild(strongCvss);
        tr.appendChild(tdCvss);
        
        // Columna 5: Categoría OWASP
        const tdCategory = document.createElement('td');
        tdCategory.className = 'owasp-category';
        tdCategory.textContent = vuln.category; // PASO 7: Seguro
        tr.appendChild(tdCategory);
        
        // Columna 6: Fecha Detectada
        const tdDate = document.createElement('td');
        tdDate.textContent = vuln.detected_date; // PASO 7: Seguro
        tr.appendChild(tdDate);
        
        // Columna 7: Acción (botón) - PASO 7: addEventListener en lugar de onclick
        const tdAction = document.createElement('td');
        const btnResolve = document.createElement('button');
        btnResolve.className = 'btn-resolve';
        btnResolve.textContent = 'Resolver';
        btnResolve.dataset.vulnId = vuln.id;  // Usar data attributes
        btnResolve.dataset.vulnCve = vuln.cve; // Usar data attributes
        btnResolve.addEventListener('click', () => {
            confirmResolve(parseInt(btnResolve.dataset.vulnId), btnResolve.dataset.vulnCve);
        });
        tdAction.appendChild(btnResolve);
        tr.appendChild(tdAction);
        
        tbody.appendChild(tr);
    });
}

/**
 * Actualiza la tabla de vulnerabilidades resueltas (Sección 4)
 * PASO 7: IMPLEMENTACIÓN SEGURA con createElement() - Sin XSS
 */
function updateResolvedTable() {
    const tbody = document.getElementById('resolved-table-body');
    const resolved = vulnerabilities.filter(v => v.status === 'resolved');
    
    // Ordenar por fecha de resolución (más reciente primero)
    resolved.sort((a, b) => {
        return new Date(b.resolved_date) - new Date(a.resolved_date);
    });
    
    // Limpiar tabla
    tbody.innerHTML = '';
    
    if (resolved.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'loading';
        td.textContent = 'No hay vulnerabilidades resueltas todavía';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    
    // Crear filas usando createElement() para seguridad total
    resolved.forEach(vuln => {
        const tr = document.createElement('tr');
        
        // Columna 1: CVE (con link)
        const tdCve = document.createElement('td');
        const linkCve = document.createElement('a');
        linkCve.href = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(vuln.cve)}`;
        linkCve.target = '_blank';
        linkCve.rel = 'noopener noreferrer'; // PASO 7: Previene tabnabbing
        linkCve.className = 'cve-link';
        linkCve.textContent = vuln.cve; // PASO 7: textContent previene XSS
        tdCve.appendChild(linkCve);
        tr.appendChild(tdCve);
        
        // Columna 2: Título
        const tdTitle = document.createElement('td');
        const strongTitle = document.createElement('strong');
        strongTitle.textContent = vuln.title; // PASO 7: Seguro
        tdTitle.appendChild(strongTitle);
        tr.appendChild(tdTitle);
        
        // Columna 3: Severidad
        const tdSeverity = document.createElement('td');
        const spanSeverity = document.createElement('span');
        spanSeverity.className = `severity-badge severity-${vuln.severity.toLowerCase()}`;
        spanSeverity.textContent = vuln.severity; // PASO 7: Seguro
        tdSeverity.appendChild(spanSeverity);
        tr.appendChild(tdSeverity);
        
        // Columna 4: CVSS Score
        const tdCvss = document.createElement('td');
        const strongCvss = document.createElement('strong');
        strongCvss.textContent = vuln.cvss_score.toString(); // PASO 7: Seguro
        tdCvss.appendChild(strongCvss);
        tr.appendChild(tdCvss);
        
        // Columna 5: Categoría OWASP
        const tdCategory = document.createElement('td');
        tdCategory.className = 'owasp-category';
        tdCategory.textContent = vuln.category; // PASO 7: Seguro
        tr.appendChild(tdCategory);
        
        // Columna 6: Fecha Detectada
        const tdDate = document.createElement('td');
        tdDate.textContent = vuln.detected_date; // PASO 7: Seguro
        tr.appendChild(tdDate);
        
        // Columna 7: Fecha Resuelta
        const tdResolved = document.createElement('td');
        const strongResolved = document.createElement('strong');
        strongResolved.style.color = '#10b981';
        strongResolved.textContent = vuln.resolved_date; // PASO 7: Seguro
        tdResolved.appendChild(strongResolved);
        tr.appendChild(tdResolved);
        
        tbody.appendChild(tr);
    });
}

/**
 * Muestra modal de confirmación antes de resolver
 */
function confirmResolve(vulnId, cve) {
    selectedVulnId = vulnId;
    const modal = document.getElementById('confirm-modal');
    const modalMessage = document.getElementById('modal-message');
    modalMessage.textContent = `¿Seguro que se ha resuelto la vulnerabilidad ${cve}?`;
    modal.classList.add('show');
}

/**
 * Resuelve la vulnerabilidad
 */
async function resolveVulnerability() {
    try {
        showMessage('Marcando vulnerabilidad como resuelta...', 'info', 2000);
        
        const response = await fetch(`/api/vulnerabilities/${selectedVulnId}/resolve`, {
            method: 'PUT',
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            console.log('Metadatos recibidos del backend:', data.metadata);
            
            // Actualizar metadatos locales CON LOS NUEVOS DEL BACKEND
            cveMetadata = {
                total_vulnerabilities: data.metadata.total_vulnerabilities,
                pending: data.metadata.pending,
                resolved: data.metadata.resolved,
                critical: data.metadata.critical
            };
            
            // Encontrar y actualizar la vulnerabilidad local
            const vuln = vulnerabilities.find(v => v.id === selectedVulnId);
            if (vuln) {
                vuln.status = 'resolved';
                vuln.resolved_date = data.vulnerability.resolved_date;
            }
            
            // Actualizar INMEDIATAMENTE todas las vistas con los nuevos metadatos
            console.log('Actualizando vistas con metadatos:', cveMetadata);
            updateSummarySection();
            updateChartSection();
            updatePendingTable();
            updateResolvedTable();
            
            showMessage('Vulnerabilidad resuelta correctamente', 'success', 3000);
        } else {
            throw new Error(data.message || 'Error desconocido');
        }
    } catch (error) {
        console.error('Error resolviendo vulnerabilidad:', error);
        showMessage('Error al resolver: ' + error.message, 'error');
    } finally {
        closeModal();
    }
}

/**
 * Cierra el modal
 */
function closeModal() {
    const modal = document.getElementById('confirm-modal');
    modal.classList.remove('show');
    selectedVulnId = null;
}

/**
 * Configurar event listeners para CVE dashboard
 */
function setupCVEListeners() {
    const modal = document.getElementById('confirm-modal');
    const btnConfirmYes = document.getElementById('btn-confirm-yes');
    const btnConfirmNo = document.getElementById('btn-confirm-no');
    const btnBackToTop = document.getElementById('btn-back-to-top');
    
    if (!btnConfirmYes || !btnConfirmNo) return;
    
    // Modal
    btnConfirmYes.addEventListener('click', resolveVulnerability);
    btnConfirmNo.addEventListener('click', closeModal);
    
    // Cerrar modal al hacer click fuera
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
    
    // Volver arriba
    if (btnBackToTop) {
        btnBackToTop.addEventListener('click', () => {
            const scrollContainer = document.querySelector('#view-vulnerabilidades .scroll-container');
            if (scrollContainer) {
                scrollContainer.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            }
        });
    }
}

// Exponer funciones CVE globalmente para onclick
window.confirmResolve = confirmResolve;

// ============================================================
// FIN DASHBOARD DE VULNERABILIDADES CVE
// ============================================================

// Cargar datos iniciales
document.addEventListener('DOMContentLoaded', async () => {
    console.log('Dashboard cargado para:', user.username);
    
    // Configurar listeners CVE
    setupCVEListeners();
    
    // Cargar datos según la vista actual
    const currentView = document.querySelector('.content-view.active');
    if (currentView) {
        const viewId = currentView.id;
        if (viewId === 'view-usuarios') {
            if (user.role === 'admin') {
                await loadUsers();
            } else {
                await loadCurrentUserProfile();
            }
        } else if (viewId === 'view-vulnerabilidades') {
            await loadVulnerabilities();
        }
    }
});

// Recargar datos al cambiar de vista
navItems.forEach(item => {
    const originalClickHandler = item.onclick;
    item.addEventListener('click', async (e) => {
        const viewName = item.getAttribute('data-view');
        
        // Esperar un poco para que la vista cambie
        setTimeout(async () => {
            if (viewName === 'usuarios') {
                if (user.role === 'admin') {
                    await loadUsers();
                } else {
                    await loadCurrentUserProfile();
                }
            } else if (viewName === 'vulnerabilidades') {
                await loadVulnerabilities();
            }
        }, 100);
    });
});

