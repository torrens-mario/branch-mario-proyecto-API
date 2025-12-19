/**
 * Lógica para gestión de vulnerabilidades
 * Archivo: frontend/js/vulnerabilities.js
 */

// Estado global de vulnerabilidades
let vulnerabilities = [];
let currentVulnId = null;
let affectedAssets = [];

// ========================================
// CARGA DE VULNERABILIDADES
// ========================================

async function loadVulnerabilities() {
    try {
        clearMessages();
        showMessage('Cargando vulnerabilidades...', 'info', 2000);
        
        const filterSeverity = document.getElementById('filter-vuln-severity')?.value || '';
        const filterSearch = document.getElementById('filter-vuln-search')?.value || '';
        
        let url = '/vulnerabilities/?skip=0&limit=100';
        if (filterSeverity) url += `&severity=${filterSeverity}`;
        if (filterSearch) url += `&search=${encodeURIComponent(filterSearch)}`;
        
        vulnerabilities = await getData(url);
        
        updateVulnerabilitiesTable();
        
        showMessage(`${vulnerabilities.length} vulnerabilidades cargadas`, 'success', 2000);
    } catch (error) {
        console.error('Error cargando vulnerabilidades:', error);
        showMessage('Error al cargar vulnerabilidades: ' + error.message, 'error');
        document.getElementById('vulns-table-body').innerHTML = 
            '<tr><td colspan="6" class="error-message">Error al cargar vulnerabilidades</td></tr>';
    }
}

function updateVulnerabilitiesTable() {
    const tbody = document.getElementById('vulns-table-body');
    
    if (vulnerabilities.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No hay vulnerabilidades registradas</td></tr>';
        return;
    }
    
    tbody.innerHTML = '';
    
    vulnerabilities.forEach(vuln => {
        const tr = document.createElement('tr');
        
        // CVE ID
        const tdCve = document.createElement('td');
        const spanCve = document.createElement('span');
        spanCve.className = 'cve-id';
        spanCve.textContent = vuln.cve_id;
        tdCve.appendChild(spanCve);
        tr.appendChild(tdCve);
        
        // Título
        const tdTitle = document.createElement('td');
        tdTitle.innerHTML = `<strong>${sanitizeHTML(vuln.title)}</strong>`;
        tr.appendChild(tdTitle);
        
        // Severidad
        const tdSeverity = document.createElement('td');
        const spanSeverity = document.createElement('span');
        spanSeverity.className = `badge badge-severity badge-${vuln.severity}-vuln`;
        spanSeverity.textContent = formatSeverity(vuln.severity);
        tdSeverity.appendChild(spanSeverity);
        tr.appendChild(tdSeverity);
        
        // Descripción
        const tdDesc = document.createElement('td');
        tdDesc.className = 'vuln-description';
        tdDesc.textContent = vuln.description || 'Sin descripción';
        tdDesc.title = vuln.description || '';
        tr.appendChild(tdDesc);
        
        // Enlaces
        const tdLinks = document.createElement('td');
        const linksDiv = document.createElement('div');
        linksDiv.className = 'vuln-links';
        
        if (vuln.cve_url) {
            const linkCve = document.createElement('a');
            linkCve.href = vuln.cve_url;
            linkCve.target = '_blank';
            linkCve.className = 'vuln-link';
            linkCve.textContent = 'CVE';
            linksDiv.appendChild(linkCve);
        }
        
        if (vuln.nvd_url) {
            const linkNvd = document.createElement('a');
            linkNvd.href = vuln.nvd_url;
            linkNvd.target = '_blank';
            linkNvd.className = 'vuln-link';
            linkNvd.textContent = 'NVD';
            linksDiv.appendChild(linkNvd);
        }
        
        tdLinks.appendChild(linksDiv);
        tr.appendChild(tdLinks);
        
        // Acciones
        const tdActions = document.createElement('td');
        tdActions.className = 'actions-cell';
        
        const currentUser = getStorage('user');
        const isAdmin = currentUser && currentUser.role === 'admin';
        
        if (isAdmin) {
            const btnView = document.createElement('button');
            btnView.className = 'btn-action btn-view';
            btnView.textContent = 'Ver Activos';
            btnView.addEventListener('click', () => viewAffectedAssets(vuln));
            tdActions.appendChild(btnView);
            
            const btnLink = document.createElement('button');
            btnLink.className = 'btn-action btn-edit';
            btnLink.textContent = 'Vincular';
            btnLink.addEventListener('click', () => openLinkVulnModal(vuln));
            tdActions.appendChild(btnLink);
        } else {
            const spanNoAccess = document.createElement('span');
            spanNoAccess.className = 'no-access';
            spanNoAccess.textContent = 'Solo lectura';
            tdActions.appendChild(spanNoAccess);
        }
        
        tr.appendChild(tdActions);
        tbody.appendChild(tr);
    });
}

// ========================================
// CREAR VULNERABILIDAD
// ========================================

async function createVulnerability(vulnData) {
    try {
        await postData('/vulnerabilities/', vulnData);
        showMessage('Vulnerabilidad creada correctamente', 'success');
        closeVulnModal();
        await loadVulnerabilities();
    } catch (error) {
        console.error('Error creando vulnerabilidad:', error);
        showMessage('Error al crear vulnerabilidad: ' + error.message, 'error');
    }
}

// ========================================
// VINCULAR VULNERABILIDAD A ACTIVO
// ========================================

async function openLinkVulnModal(vuln) {
    currentVulnId = vuln.id;
    
    // Cargar activos disponibles
    try {
        const assets = await getData('/assets/?skip=0&limit=500');
        
        const modal = document.getElementById('link-vuln-modal');
        document.getElementById('link-vuln-title').textContent = `Vincular: ${vuln.cve_id}`;
        
        const select = document.getElementById('asset-select');
        select.innerHTML = '<option value="">Seleccionar activo...</option>';
        
        assets.forEach(asset => {
            const option = document.createElement('option');
            option.value = asset.id;
            option.textContent = `${asset.name} - ${asset.location || 'Sin ubicación'}`;
            select.appendChild(option);
        });
        
        modal.classList.add('show');
    } catch (error) {
        showMessage('Error cargando activos: ' + error.message, 'error');
    }
}

async function linkVulnerabilityToAsset() {
    const assetId = document.getElementById('asset-select').value;
    
    if (!assetId) {
        showMessage('Debes seleccionar un activo', 'warning');
        return;
    }
    
    try {
        await postData(`/vulnerabilities/assets/${assetId}/vulnerabilities/${currentVulnId}`, {});
        showMessage('Vulnerabilidad vinculada correctamente', 'success');
        closeLinkVulnModal();
        await loadVulnerabilities();
    } catch (error) {
        console.error('Error vinculando vulnerabilidad:', error);
        showMessage('Error al vincular: ' + error.message, 'error');
    }
}

function closeLinkVulnModal() {
    document.getElementById('link-vuln-modal').classList.remove('show');
    currentVulnId = null;
}

// ========================================
// VER ACTIVOS AFECTADOS
// ========================================

async function viewAffectedAssets(vuln) {
    try {
        // Aquí necesitarías un endpoint para obtener los activos afectados por una vulnerabilidad
        // Por ahora mostramos un placeholder
        showMessage(`Funcionalidad en desarrollo para ${vuln.cve_id}`, 'info');
    } catch (error) {
        console.error('Error cargando activos afectados:', error);
        showMessage('Error al cargar activos afectados', 'error');
    }
}

// ========================================
// FUNCIONES DE FORMATO
// ========================================

function formatSeverity(severity) {
    const severities = {
        'critical': 'Crítico',
        'high': 'Alto',
        'medium': 'Medio',
        'low': 'Bajo'
    };
    return severities[severity] || severity;
}

// ========================================
// MODAL DE NUEVA VULNERABILIDAD
// ========================================

function openVulnModal() {
    document.getElementById('vuln-modal-title').textContent = 'Nueva Vulnerabilidad';
    document.getElementById('vuln-form').reset();
    document.getElementById('vuln-modal').classList.add('show');
}

function closeVulnModal() {
    document.getElementById('vuln-modal').classList.remove('show');
}

// ========================================
// INICIALIZACIÓN
// ========================================

// Event listeners para los botones
document.addEventListener('DOMContentLoaded', () => {
    const btnNewVuln = document.getElementById('btn-new-vuln');
    if (btnNewVuln) {
        btnNewVuln.addEventListener('click', openVulnModal);
    }
    
    const btnCancelVuln = document.getElementById('btn-cancel-vuln');
    if (btnCancelVuln) {
        btnCancelVuln.addEventListener('click', closeVulnModal);
    }
    
    const vulnForm = document.getElementById('vuln-form');
    if (vulnForm) {
        vulnForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const vulnData = {
                cve_id: document.getElementById('vuln-cve').value.trim(),
                title: document.getElementById('vuln-title').value.trim(),
                description: document.getElementById('vuln-description').value.trim(),
                severity: document.getElementById('vuln-severity').value,
                cve_url: document.getElementById('vuln-cve-url').value.trim() || null,
                nvd_url: document.getElementById('vuln-nvd-url').value.trim() || null
            };
            
            await createVulnerability(vulnData);
        });
    }
    
    const btnApplyVulnFilters = document.getElementById('btn-apply-vuln-filters');
    if (btnApplyVulnFilters) {
        btnApplyVulnFilters.addEventListener('click', loadVulnerabilities);
    }
    
    const btnLinkVuln = document.getElementById('btn-link-vuln');
    if (btnLinkVuln) {
        btnLinkVuln.addEventListener('click', linkVulnerabilityToAsset);
    }
    
    const btnCancelLink = document.getElementById('btn-cancel-link');
    if (btnCancelLink) {
        btnCancelLink.addEventListener('click', closeLinkVulnModal);
    }
});

// Exportar funciones para uso en dashboard.js
window.loadVulnerabilities = loadVulnerabilities;