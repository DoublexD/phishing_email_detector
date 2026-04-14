// Email Spoofing Detector - Frontend JavaScript

const API_BASE_URL = 'http://localhost:8000';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeTabs();
    loadInitialData();
});

// Tab Navigation
function initializeTabs() {
    const navButtons = document.querySelectorAll('.nav-button');
    
    navButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update nav buttons
    document.querySelectorAll('.nav-button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Load tab-specific data
    loadTabData(tabName);
}

function loadTabData(tabName) {
    switch(tabName) {
        case 'alerts':
            refreshAlerts();
            break;
        case 'models':
            refreshModels();
            break;
        case 'stats':
            refreshStats();
            break;
    }
}

// Load Initial Data
async function loadInitialData() {
    await updateHeaderStats();
    await refreshAlerts();
}

// Update Header Statistics
async function updateHeaderStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/stats`);
        const data = await response.json();
        
        document.getElementById('total-analyzed').textContent = data.total_analyzed;
        document.getElementById('suspicious-detected').textContent = data.suspicious_detected;
        document.getElementById('safe-emails').textContent = data.safe_emails;
        document.getElementById('detection-rate').textContent = 
            `${(data.detection_rate * 100).toFixed(1)}%`;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Alerts Tab
async function refreshAlerts() {
    const container = document.getElementById('alerts-container');
    const riskFilter = document.getElementById('risk-filter').value;
    
    container.innerHTML = '<div class="loading">Ładowanie alertów...</div>';
    
    try {
        const url = `${API_BASE_URL}/api/alerts?limit=50` + 
                    (riskFilter ? `&risk_level=${riskFilter}` : '');
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.alerts.length === 0) {
            container.innerHTML = '<div class="loading">Brak alertów</div>';
            return;
        }
        
        container.innerHTML = '';
        data.alerts.reverse().forEach(alert => {
            container.appendChild(createAlertCard(alert));
        });
        
        await updateHeaderStats();
    } catch (error) {
        console.error('Error loading alerts:', error);
        container.innerHTML = '<div class="error">Błąd ładowania alertów</div>';
    }
}

function createAlertCard(alert) {
    const card = document.createElement('div');
    card.className = `alert-card ${alert.risk_level}`;
    
    const fromEmail = alert.from?.email || 'Nieznany';
    const subject = alert.subject || 'Brak tematu';
    const timestamp = new Date(alert.timestamp).toLocaleString('pl-PL');
    
    card.innerHTML = `
        <div class="alert-header">
            <div>
                <div class="alert-title">🚨 ${fromEmail}</div>
                <div class="alert-info">Temat: ${subject}</div>
                <div class="alert-info">Czas: ${timestamp}</div>
                <div class="alert-info">Pewność: ${(alert.confidence * 100).toFixed(1)}%</div>
            </div>
            <span class="alert-badge ${alert.risk_level}">${alert.risk_level}</span>
        </div>
        <div class="alert-indicators">
            ${alert.spoofing_indicators.map(ind => 
                `<span class="indicator-tag">${ind}</span>`
            ).join('')}
        </div>
        <div style="margin-top: 1rem;">
            <strong>Rekomendacja:</strong> ${alert.recommendation}
        </div>
    `;
    
    return card;
}

// Analyze Tab
async function analyzeEmail() {
    const emailInput = document.getElementById('email-input').value;
    const analyzeAuth = document.getElementById('analyze-auth').checked;
    const resultDiv = document.getElementById('analysis-result');
    
    if (!emailInput.trim()) {
        alert('Proszę wkleić wiadomość e-mail');
        return;
    }
    
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<div class="loading">Analizowanie...</div>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email_string: emailInput,
                analyze_authentication: analyzeAuth
            })
        });
        
        if (!response.ok) {
            throw new Error('Błąd analizy');
        }
        
        const result = await response.json();
        displayAnalysisResult(result);
        
        // Refresh stats and alerts
        await updateHeaderStats();
        if (result.is_suspicious) {
            await refreshAlerts();
        }
    } catch (error) {
        console.error('Error analyzing email:', error);
        resultDiv.innerHTML = '<div class="error">Błąd podczas analizy wiadomości</div>';
    }
}

function displayAnalysisResult(result) {
    const resultDiv = document.getElementById('analysis-result');
    
    const icon = result.is_suspicious ? '⚠️' : '✅';
    const title = result.is_suspicious ? 'Wiadomość podejrzana!' : 'Wiadomość bezpieczna';
    const titleColor = result.is_suspicious ? '#f44336' : '#4caf50';
    
    let html = `
        <div class="result-header">
            <div class="result-icon">${icon}</div>
            <div class="result-title" style="color: ${titleColor}">${title}</div>
            <div class="result-confidence">
                Pewność: ${(result.confidence * 100).toFixed(1)}% | 
                Poziom ryzyka: ${result.risk_level}
            </div>
        </div>
    `;
    
    if (result.spoofing_indicators && result.spoofing_indicators.length > 0) {
        html += `
            <div class="result-section">
                <h3>Wykryte wskaźniki spoofingu</h3>
                <ul class="result-list">
                    ${result.spoofing_indicators.map(ind => 
                        `<li>⚠️ ${ind}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    if (result.authentication) {
        html += `
            <div class="result-section">
                <h3>Autentykacja</h3>
                <ul class="result-list">
                    <li>SPF: ${formatAuthResult(result.authentication.spf)}</li>
                    <li>DKIM: ${formatAuthResult(result.authentication.dkim)}</li>
                    <li>DMARC: ${formatAuthResult(result.authentication.dmarc)}</li>
                </ul>
            </div>
        `;
    }
    
    html += `
        <div class="result-section">
            <h3>Rekomendacja</h3>
            <p style="font-size: 1.2rem; font-weight: 600; color: ${titleColor}">
                ${result.recommendation}
            </p>
        </div>
    `;
    
    resultDiv.innerHTML = html;
}

function formatAuthResult(auth) {
    if (!auth) return 'Nie sprawdzono';
    
    if (auth.valid) {
        return '✅ Poprawne';
    } else if (auth.result === 'fail') {
        return '❌ Niepoprawne';
    } else if (auth.result === 'none') {
        return '⚪ Brak';
    } else {
        return `⚠️ ${auth.result}`;
    }
}

// Models Tab
async function refreshModels() {
    const modelsContainer = document.getElementById('models-container');
    const featuresContainer = document.getElementById('features-container');
    
    modelsContainer.innerHTML = '<div class="loading">Ładowanie...</div>';
    featuresContainer.innerHTML = '<div class="loading">Ładowanie...</div>';
    
    try {
        // Load models info
        const modelsResponse = await fetch(`${API_BASE_URL}/api/models`);
        const modelsData = await modelsResponse.json();
        
        modelsContainer.innerHTML = '';
        
        // Display loaded models
        const loadedModels = [
            {
                name: 'Random Forest Classifier',
                type: 'random_forest',
                loaded: modelsData.loaded.random_forest
            },
            {
                name: 'Isolation Forest (Anomaly Detection)',
                type: 'isolation_forest',
                loaded: modelsData.loaded.isolation_forest
            }
        ];
        
        loadedModels.forEach(model => {
            const card = createModelCard(model);
            modelsContainer.appendChild(card);
        });
        
        // Load feature importance
        const featuresResponse = await fetch(`${API_BASE_URL}/api/feature-importance?top_n=15`);
        const featuresData = await featuresResponse.json();
        
        featuresContainer.innerHTML = '';
        
        if (featuresData.features && featuresData.features.length > 0) {
            const maxImportance = Math.max(...featuresData.features.map(f => f.importance));
            
            featuresData.features.forEach(feature => {
                const item = createFeatureItem(feature, maxImportance);
                featuresContainer.appendChild(item);
            });
        } else {
            featuresContainer.innerHTML = '<div class="loading">Brak danych o cechach</div>';
        }
        
    } catch (error) {
        console.error('Error loading models:', error);
        modelsContainer.innerHTML = '<div class="error">Błąd ładowania informacji o modelach</div>';
    }
}

function createModelCard(model) {
    const card = document.createElement('div');
    card.className = 'model-card';
    
    const statusClass = model.loaded ? 'loaded' : 'not-loaded';
    const statusText = model.loaded ? '✅ Załadowany' : '❌ Nie załadowany';
    
    card.innerHTML = `
        <div class="model-header">
            <div class="model-name">🤖 ${model.name}</div>
            <span class="model-status ${statusClass}">${statusText}</span>
        </div>
        <div class="model-details">
            <div class="model-detail">
                <div class="detail-label">Typ</div>
                <div class="detail-value">${model.type}</div>
            </div>
        </div>
    `;
    
    return card;
}

function createFeatureItem(feature, maxImportance) {
    const item = document.createElement('div');
    item.className = 'feature-item';
    
    const percentage = (feature.importance / maxImportance * 100).toFixed(1);
    
    item.innerHTML = `
        <div class="feature-name">${feature.feature}</div>
        <div class="feature-bar">
            <div class="feature-bar-fill" style="width: ${percentage}%"></div>
        </div>
        <div class="feature-value">${feature.importance.toFixed(4)}</div>
    `;
    
    return item;
}

// Stats Tab
async function refreshStats() {
    const statsContainer = document.getElementById('stats-container');
    statsContainer.innerHTML = '<div class="loading">Ładowanie statystyk...</div>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/stats`);
        const data = await response.json();
        
        statsContainer.innerHTML = `
            <div class="models-container">
                <div class="model-card">
                    <h3>Ogólne statystyki</h3>
                    <div class="model-details">
                        <div class="model-detail">
                            <div class="detail-label">Przeanalizowane</div>
                            <div class="detail-value">${data.total_analyzed}</div>
                        </div>
                        <div class="model-detail">
                            <div class="detail-label">Podejrzane</div>
                            <div class="detail-value">${data.suspicious_detected}</div>
                        </div>
                        <div class="model-detail">
                            <div class="detail-label">Bezpieczne</div>
                            <div class="detail-value">${data.safe_emails}</div>
                        </div>
                        <div class="model-detail">
                            <div class="detail-label">Wskaźnik detekcji</div>
                            <div class="detail-value">${(data.detection_rate * 100).toFixed(1)}%</div>
                        </div>
                    </div>
                    ${data.last_updated ? 
                        `<p style="margin-top: 1rem; color: #666;">
                            Ostatnia aktualizacja: ${new Date(data.last_updated).toLocaleString('pl-PL')}
                        </p>` : ''
                    }
                </div>
                
                <div class="model-card">
                    <h3>Informacje o modelach</h3>
                    <div class="model-details">
                        <div class="model-detail">
                            <div class="detail-label">Liczba modeli</div>
                            <div class="detail-value">${data.model_info.total_models || 0}</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading stats:', error);
        statsContainer.innerHTML = '<div class="error">Błąd ładowania statystyk</div>';
    }
}

// Event listeners for filters
document.getElementById('risk-filter')?.addEventListener('change', refreshAlerts);

// Auto-refresh (every 30 seconds)
setInterval(() => {
    const activeTab = document.querySelector('.tab-content.active').id.replace('-tab', '');
    if (activeTab === 'alerts') {
        refreshAlerts();
    }
    updateHeaderStats();
}, 30000);

