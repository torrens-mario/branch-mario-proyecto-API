/**
 * Dashboard de Vulnerabilidades - Paso 6
 * Gestión de vulnerabilidades CVE con scroll infinito
 */

// Verificar autenticación
requireAuth();

// Estado global
let vulnerabilities = [];
let metadata = {};
let progressChart = null;
let selectedVulnId = null;

// Referencias DOM
const modal = document.getElementById('confirm-modal');
const modalMessage = document.getElementById('modal-message');
const btnConfirmYes = document.getElementById('btn-confirm-yes');
const btnConfirmNo = document.getElementById('btn-confirm-no');
const btnBackToTop = document.getElementById('btn-back-to-top');
const logoutLink = document.getElementById('logout-link');

// Cargar vulnerabilidades al inicio
document.addEventListener('DOMContentLoaded', () => {
    loadVulnerabilities();
    setupEventListeners();
});

/**
 * Carga todas las vulnerabilidades desde la API
 */
async function loadVulnerabilities() {
    try {
        showMessage('Cargando vulnerabilidades...', 'info', 2000);
        
        const response = await fetch(`${API_BASE}/api/vulnerabilities`, {
            method: 'GET',
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            vulnerabilities = data.vulnerabilities;
            metadata = data.metadata;
            
            // Actualizar todas las secciones
            updateSummarySection();
            updateChartSection();
            updatePendingTable();
            updateResolvedTable();
            
            showMessage('Vulnerabilidades cargadas correctamente', 'success', 2000);
        } else {
            throw new Error(data.message || 'Error desconocido');
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
    document.getElementById('stat-total').textContent = metadata.total_vulnerabilities || 0;
    document.getElementById('stat-pending').textContent = metadata.pending || 0;
    document.getElementById('stat-resolved').textContent = metadata.resolved || 0;
    document.getElementById('stat-critical').textContent = metadata.critical || 0;
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
                data: [metadata.pending || 0, metadata.resolved || 0],
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
                            const total = metadata.total_vulnerabilities || 0;
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    // Actualizar leyenda
    document.getElementById('legend-pending').textContent = metadata.pending || 0;
    document.getElementById('legend-resolved').textContent = metadata.resolved || 0;
}

/**
 * Actualiza la tabla de vulnerabilidades pendientes (Sección 3)
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
    
    if (pending.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading">¡No hay vulnerabilidades pendientes! 🎉</td></tr>';
        return;
    }
    
    tbody.innerHTML = pending.map(vuln => `
        <tr>
            <td>
                <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}" 
                   target="_blank" 
                   class="cve-link">${vuln.cve}</a>
            </td>
            <td><strong>${sanitizeHTML(vuln.title)}</strong></td>
            <td>
                <span class="severity-badge severity-${vuln.severity.toLowerCase()}">
                    ${vuln.severity}
                </span>
            </td>
            <td><strong>${vuln.cvss_score}</strong></td>
            <td class="owasp-category">${sanitizeHTML(vuln.category)}</td>
            <td>${vuln.detected_date}</td>
            <td>
                <button class="btn-resolve" onclick="confirmResolve(${vuln.id}, '${sanitizeHTML(vuln.cve)}')">
                    Resolver
                </button>
            </td>
        </tr>
    `).join('');
}

/**
 * Actualiza la tabla de vulnerabilidades resueltas (Sección 4)
 */
function updateResolvedTable() {
    const tbody = document.getElementById('resolved-table-body');
    const resolved = vulnerabilities.filter(v => v.status === 'resolved');
    
    // Ordenar por fecha de resolución (más reciente primero)
    resolved.sort((a, b) => {
        return new Date(b.resolved_date) - new Date(a.resolved_date);
    });
    
    if (resolved.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading">No hay vulnerabilidades resueltas todavía</td></tr>';
        return;
    }
    
    tbody.innerHTML = resolved.map(vuln => `
        <tr>
            <td>
                <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}" 
                   target="_blank" 
                   class="cve-link">${vuln.cve}</a>
            </td>
            <td><strong>${sanitizeHTML(vuln.title)}</strong></td>
            <td>
                <span class="severity-badge severity-${vuln.severity.toLowerCase()}">
                    ${vuln.severity}
                </span>
            </td>
            <td><strong>${vuln.cvss_score}</strong></td>
            <td class="owasp-category">${sanitizeHTML(vuln.category)}</td>
            <td>${vuln.detected_date}</td>
            <td><strong style="color: #10b981;">${vuln.resolved_date}</strong></td>
        </tr>
    `).join('');
}

/**
 * Muestra modal de confirmación antes de resolver
 */
function confirmResolve(vulnId, cve) {
    selectedVulnId = vulnId;
    modalMessage.textContent = `¿Seguro que se ha resuelto la vulnerabilidad ${cve}?`;
    modal.classList.add('show');
}

/**
 * Resuelve la vulnerabilidad
 */
async function resolveVulnerability() {
    try {
        showMessage('Marcando vulnerabilidad como resuelta...', 'info', 2000);
        
        const response = await fetch(`${API_BASE}/api/vulnerabilities/${selectedVulnId}/resolve`, {
            method: 'PUT',
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            // Actualizar metadatos locales
            metadata = data.metadata;
            
            // Encontrar y actualizar la vulnerabilidad local
            const vuln = vulnerabilities.find(v => v.id === selectedVulnId);
            if (vuln) {
                vuln.status = 'resolved';
                vuln.resolved_date = data.vulnerability.resolved_date;
            }
            
            // Actualizar todas las vistas
            updateSummarySection();
            updateChartSection();
            updatePendingTable();
            updateResolvedTable();
            
            showMessage('✅ Vulnerabilidad resuelta correctamente', 'success', 3000);
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
    modal.classList.remove('show');
    selectedVulnId = null;
}

/**
 * Configurar event listeners
 */
function setupEventListeners() {
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
    btnBackToTop.addEventListener('click', () => {
        document.querySelector('.scroll-container').scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
    
    // Logout
    logoutLink.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });
}

/**
 * Sanitiza HTML (heredada de utils.js pero por si acaso)
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

