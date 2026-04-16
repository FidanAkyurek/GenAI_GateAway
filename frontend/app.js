const API_BASE = '/api/v1';

// Simple fetch wrapper
const apiFetch = async (url, options = {}) => {
    try {
        const res = await fetch(url, options);
        return res;
    } catch (e) {
        console.error('Fetch Error:', e, url);
        return null;
    }
};

// =====================
// STATE
// =====================
let charts = { ratio: null, category: null };
let autoRefreshInterval = null;
let isAutoRefresh = false;

// Active filter state for Logs page
let activeActionFilter = '';    // '' | 'BLOCK' | 'ALLOW'
let activeCategoryFilter = '';  // '' | 'Safe' | 'Injection' | 'PII' | 'Blacklist'

// =====================
// DOM REFERENCES
// =====================
const navDashboard  = document.getElementById('nav-dashboard');
const navLogs       = document.getElementById('nav-logs');
const navSettings   = document.getElementById('nav-settings');
const viewDashboard = document.getElementById('view-dashboard');
const viewLogs      = document.getElementById('view-logs');
const viewSettings  = document.getElementById('view-settings');

const elements = {
    valTotal:      document.getElementById('valTotal'),
    valBlocked:    document.getElementById('valBlocked'),
    valAllowed:    document.getElementById('valAllowed'),
    valLatency:    document.getElementById('valLatency'),
    logsTableBody: document.getElementById('logsTableBody'),
    refreshBtn:    document.getElementById('refreshBtn')
};

const fullLogsTableBody = document.getElementById('fullLogsTableBody');
const logDetailModal    = document.getElementById('logDetailModal');
const closeModalBtn     = document.getElementById('closeModalBtn');

const mEl = {
    title:      document.getElementById('modalLogIdTitle'),
    date:       document.getElementById('mdlDate'),
    time:       document.getElementById('mdlTime'),
    user:       document.getElementById('mdlUser'),
    status:     document.getElementById('mdlStatus'),
    prompt:     document.getElementById('mdlPrompt'),
    warning:    document.getElementById('mdlWarning'),
    layer:      document.getElementById('mdlLayer'),
    scoreBar:   document.getElementById('mdlScoreBar'),
    scoreText:  document.getElementById('mdlScoreText'),
    category:   document.getElementById('mdlCategory'),
    btnValidate: document.getElementById('btnValidate'),
    btnFalsePos: document.getElementById('btnFalsePositive')
};

// Settings DOM
const sEl = {
    t1:            document.getElementById('tglLayer1'),
    t2:            document.getElementById('tglLayer2'),
    t3:            document.getElementById('tglLayer3'),
    stsL1:         document.getElementById('stsL1'),
    stsL2:         document.getElementById('stsL2'),
    stsL3:         document.getElementById('stsL3'),
    aiRange:       document.getElementById('aiThreshold'),
    aiVal:         document.getElementById('aiThresholdVal'),
    blacklistWrapper: document.getElementById('blacklistTags'),
    blacklistInput: document.getElementById('blacklistInput'),
    addWordBtn:    document.getElementById('addWordBtn'),
    saveRulesBtn:  document.getElementById('saveRulesBtn')
};

// =====================
// HELPERS
// =====================
const extractDateHTML = (isoString) => {
    const d = new Date(isoString);
    return {
        date: d.toLocaleDateString('tr-TR'),
        time: d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };
};

const escapeHTML = (str) => {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag]));
};

const encodeLogB64 = (logObj) => btoa(unescape(encodeURIComponent(JSON.stringify(logObj))));

// =====================
// ROUTING / TAB LOGIC
// =====================
function switchTab(tabName) {
    [navDashboard, navLogs, navSettings].forEach(el => el.classList.remove('active'));
    [viewDashboard, viewLogs, viewSettings].forEach(el => el.classList.remove('active'));

    if (tabName === 'dashboard') {
        navDashboard.classList.add('active');
        viewDashboard.classList.add('active');
        refreshDashboard();
    } else if (tabName === 'logs') {
        navLogs.classList.add('active');
        viewLogs.classList.add('active');
        fetchDetailedLogs();
    } else if (tabName === 'settings') {
        navSettings.classList.add('active');
        viewSettings.classList.add('active');
        fetchRules();
    }
}

// =====================
// DASHBOARD CHARTS
// =====================
function initCharts() {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Outfit', sans-serif";

    charts.ratio = new Chart(document.getElementById('ratioChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Engellenen', 'İzin Verilen'],
            datasets: [{ data: [0, 0], backgroundColor: ['#ef4444', '#10b981'], borderColor: '#1a1d27', borderWidth: 2 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } }, cutout: '75%' }
    });

    charts.category = new Chart(document.getElementById('categoryChart').getContext('2d'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Olay Sayısı', data: [], backgroundColor: '#6366f1', borderRadius: 4 }] },
        options: {
            responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false } }
            }
        }
    });
}

async function refreshDashboard() {
    try {
        const statsRes = await apiFetch(`${API_BASE}/stats`);
        if (!statsRes) return;
        const stats = await statsRes.json();
        elements.valTotal.innerText   = stats.total_requests || 0;
        elements.valBlocked.innerText = stats.blocked || 0;
        elements.valAllowed.innerText = stats.allowed || 0;
        elements.valLatency.innerText = (stats.avg_latency_ms || 0) + 'ms';
        charts.ratio.data.datasets[0].data = [stats.blocked || 0, stats.allowed || 0];
        charts.ratio.update();

        const logsRes = await apiFetch(`${API_BASE}/logs?limit=15`);
        if (!logsRes) return;
        const logsData = await logsRes.json();
        let html = '';
        const catCounts = {};

        if (logsData.logs && logsData.logs.length > 0) {
            logsData.logs.forEach(log => {
                const cat = log.category || 'Unknown';
                catCounts[cat] = (catCounts[cat] || 0) + 1;
                const dt = extractDateHTML(log.created_at);
                const badgeClass  = log.action === 'BLOCK' ? 'badge-block' : 'badge-allow';
                const actionText  = log.action === 'BLOCK' ? 'Engellendi' : 'İzin Verildi';
                html += `
                    <tr onclick="openLogModal('${encodeLogB64(log)}')" style="cursor:pointer;">
                        <td>${dt.time}</td>
                        <td style="font-family:monospace;opacity:0.8;">${escapeHTML(log.user_id)}</td>
                        <td><span class="prompt-text">${escapeHTML(log.masked_prompt)}</span></td>
                        <td><span class="layer-tag">${log.stopped_at_layer || '-'}</span></td>
                        <td>${escapeHTML(log.category)}</td>
                        <td><span class="badge ${badgeClass}">${actionText}</span></td>
                    </tr>`;
            });
        } else {
            html = `<tr><td colspan="6" class="text-center" style="padding:2rem;color:#94a3b8;">Henüz kayıt yok.</td></tr>`;
        }
        elements.logsTableBody.innerHTML = html;

        charts.category.data.labels   = Object.keys(catCounts);
        charts.category.data.datasets[0].data = Object.values(catCounts);
        charts.category.update();
    } catch (e) {
        console.error('Dashboard refresh error:', e);
    }
}

// =====================
// LOGS PAGE — FILTER PILLS
// =====================
function buildFilterUrl() {
    let url = `${API_BASE}/logs?limit=200`;
    if (activeActionFilter)   url += `&action=${activeActionFilter}`;
    if (activeCategoryFilter) url += `&category=${activeCategoryFilter}`;
    return url;
}

function updateFilterPillUI() {
    // Action pills
    document.querySelectorAll('.filter-pill[data-action]').forEach(pill => {
        const val = pill.dataset.action;
        pill.classList.toggle('active', activeActionFilter === val);
    });
    // Category pills
    document.querySelectorAll('.filter-pill[data-category]').forEach(pill => {
        const val = pill.dataset.category;
        pill.classList.toggle('active', activeCategoryFilter === val);
    });
}

async function fetchDetailedLogs() {
    fullLogsTableBody.innerHTML = `<tr><td colspan="6" class="text-center" style="padding:2rem;">Yükleniyor...</td></tr>`;

    try {
        const res = await apiFetch(buildFilterUrl());
        if (!res) return;
        const data = await res.json();
        let html = '';
        if (data.logs && data.logs.length > 0) {
            data.logs.forEach(log => {
                const dt = extractDateHTML(log.created_at);
                const badgeClass = log.action === 'BLOCK' ? 'badge-block' : 'badge-allow';
                const actionText = log.action === 'BLOCK' ? 'Engellendi' : 'İzin Verildi';
                html += `
                    <tr onclick="openLogModal('${encodeLogB64(log)}')" style="cursor:pointer;">
                        <td style="font-family:monospace;color:var(--primary);">${log.log_id.split('-')[0]}</td>
                        <td>${dt.date} ${dt.time}</td>
                        <td style="font-family:monospace;opacity:0.8;">${escapeHTML(log.user_id)}</td>
                        <td><span class="layer-tag">${log.stopped_at_layer || '-'}</span></td>
                        <td>${escapeHTML(log.category)}</td>
                        <td><span class="badge ${badgeClass}">${actionText}</span></td>
                    </tr>`;
            });
        } else {
            html = `<tr><td colspan="6" class="text-center" style="padding:2rem;color:#94a3b8;">Kritere uygun kayıt bulunamadı.</td></tr>`;
        }
        fullLogsTableBody.innerHTML = html;
    } catch (e) {
        console.error(e);
        fullLogsTableBody.innerHTML = `<tr><td colspan="6" class="text-center" style="color:var(--danger);padding:2rem;">Hata oluştu.</td></tr>`;
    }
}

// =====================
// LOG DETAIL MODAL
// =====================
function openLogModal(b64str) {
    const jsonStr = decodeURIComponent(escape(atob(b64str)));
    const log = JSON.parse(jsonStr);
    const dt = extractDateHTML(log.created_at);

    mEl.title.innerText = `Log Detayı: #${log.log_id.split('-')[0].toUpperCase()}`;
    mEl.date.innerText  = dt.date;
    mEl.time.innerText  = dt.time;
    mEl.user.innerText  = log.user_id;

    if (log.action === 'BLOCK') {
        mEl.status.innerHTML  = `<i data-lucide="minus-circle" style="width:16px;margin-right:4px;"></i> BLOKLANDI`;
        mEl.status.className  = 'badge badge-lg badge-block';
    } else {
        mEl.status.innerHTML  = `<i data-lucide="check-circle" style="width:16px;margin-right:4px;"></i> İZİN VERİLDİ`;
        mEl.status.className  = 'badge badge-lg badge-allow';
    }

    mEl.prompt.innerText = log.masked_prompt || '-';
    if (log.action === 'BLOCK') {
        mEl.warning.style.display = 'flex';
        if (log.category === 'PII') {
            mEl.warning.innerHTML  = `<i data-lucide="alert-triangle"></i> HASSAS VERİ TESPİT EDİLDİ`;
            mEl.warning.className  = 'warning-banner';
        } else {
            mEl.warning.innerHTML  = `<i data-lucide="skull"></i> GÜVENLİK TEHDİDİ TESPİT EDİLDİ`;
            mEl.warning.className  = 'warning-banner danger';
        }
    } else {
        mEl.warning.style.display = 'none';
    }

    mEl.layer.innerText = log.stopped_at_layer ? `${log.stopped_at_layer}` : 'Temiz';

    const scorePct = Math.round((log.ai_confidence_score || 0) * 100);
    mEl.scoreText.innerText = scorePct;
    mEl.category.innerText  = log.category || '-';

    mEl.scoreBar.style.width = '0%';
    setTimeout(() => {
        mEl.scoreBar.style.width = scorePct + '%';
        if (scorePct > 80)       mEl.scoreBar.style.background = 'linear-gradient(90deg,#ef4444,#f87171)';
        else if (scorePct > 50)  mEl.scoreBar.style.background = 'linear-gradient(90deg,#f59e0b,#fbbf24)';
        else                     mEl.scoreBar.style.background = 'linear-gradient(90deg,#10b981,#34d399)';
    }, 100);

    mEl.btnValidate.onclick = () => submitFeedback(log.log_id, 'safe', mEl.btnValidate);
    mEl.btnFalsePos.onclick = () => submitFeedback(log.log_id, 'false_positive', mEl.btnFalsePos);

    lucide.createIcons();
    logDetailModal.style.display = 'flex';
}

function closeLogModal() {
    logDetailModal.style.display = 'none';
}

async function submitFeedback(log_id, label, btnElement) {
    const originalText = btnElement.innerHTML;
    btnElement.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Kaydediliyor...`;
    lucide.createIcons();
    try {
        const res = await apiFetch(`${API_BASE}/feedback?log_id=${log_id}&correct_label=${label}`, { method: 'POST' });
        if (!res) return;
        btnElement.innerHTML = `<i data-lucide="check"></i> Teşekkürler`;
        lucide.createIcons();
        setTimeout(() => closeLogModal(), 1000);
    } catch (e) {
        console.error(e);
        btnElement.innerHTML = 'Hata!';
    }
}

// =====================
// SETTINGS / RULES
// =====================
let currentRules = { layer_regex: true, layer_deberta: true, layer_llm: false, ai_threshold: 0.75, blacklist: [] };

function renderTags() {
    sEl.blacklistWrapper.innerHTML = '';
    currentRules.blacklist.forEach(word => {
        const span = document.createElement('span');
        span.className = 'tag-pill';
        span.innerHTML = `${escapeHTML(word)} <i data-lucide="x-circle" class="remove-tag" onclick="removeTag('${escapeHTML(word)}')"></i>`;
        sEl.blacklistWrapper.appendChild(span);
    });
    lucide.createIcons();
}

function removeTag(word) {
    currentRules.blacklist = currentRules.blacklist.filter(w => w !== word);
    renderTags();
}

function addTag() {
    const val = sEl.blacklistInput.value.trim();
    if (val && !currentRules.blacklist.includes(val)) {
        val.split(',').forEach(w => {
            const clean = w.trim();
            if (clean && !currentRules.blacklist.includes(clean)) currentRules.blacklist.push(clean);
        });
        renderTags();
    }
    sEl.blacklistInput.value = '';
}

async function fetchRules() {
    try {
        const res = await apiFetch(`${API_BASE}/rules`);
        if (!res) return;
        currentRules = await res.json();

        sEl.t1.checked   = currentRules.layer_regex;
        sEl.stsL1.innerText  = currentRules.layer_regex    ? '[ON]' : '[OFF]';
        sEl.stsL1.className  = currentRules.layer_regex    ? 'layer-status on' : 'layer-status';

        sEl.t2.checked   = currentRules.layer_deberta;
        sEl.stsL2.innerText  = currentRules.layer_deberta  ? '[ON]' : '[OFF]';
        sEl.stsL2.className  = currentRules.layer_deberta  ? 'layer-status on' : 'layer-status';

        sEl.t3.checked   = currentRules.layer_llm;
        sEl.stsL3.innerText  = currentRules.layer_llm      ? '[ON]' : '[OFF]';
        sEl.stsL3.className  = currentRules.layer_llm      ? 'layer-status on' : 'layer-status';

        sEl.aiRange.value   = currentRules.ai_threshold;
        sEl.aiVal.innerText = currentRules.ai_threshold;

        renderTags();
    } catch (e) {
        console.error('Rules fetch error:', e);
    }
}

async function saveRules() {
    currentRules.layer_regex    = sEl.t1.checked;
    currentRules.layer_deberta  = sEl.t2.checked;
    currentRules.layer_llm      = sEl.t3.checked;
    currentRules.ai_threshold   = parseFloat(sEl.aiRange.value);

    const origHtml = sEl.saveRulesBtn.innerHTML;
    sEl.saveRulesBtn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Kaydediliyor...`;
    lucide.createIcons();

    try {
        const res = await apiFetch(`${API_BASE}/rules`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentRules)
        });
        if (res && res.ok) {
            sEl.saveRulesBtn.style.background = 'var(--success)';
            sEl.saveRulesBtn.innerHTML = `<i data-lucide="check"></i> Kaydedildi`;
            lucide.createIcons();
            sEl.stsL1.innerText = currentRules.layer_regex   ? '[ON]' : '[OFF]'; sEl.stsL1.className = currentRules.layer_regex   ? 'layer-status on' : 'layer-status';
            sEl.stsL2.innerText = currentRules.layer_deberta ? '[ON]' : '[OFF]'; sEl.stsL2.className = currentRules.layer_deberta ? 'layer-status on' : 'layer-status';
            sEl.stsL3.innerText = currentRules.layer_llm     ? '[ON]' : '[OFF]'; sEl.stsL3.className = currentRules.layer_llm     ? 'layer-status on' : 'layer-status';
        }
    } catch (e) {
        sEl.saveRulesBtn.innerHTML = 'Hata!';
    }

    setTimeout(() => {
        sEl.saveRulesBtn.innerHTML = origHtml;
        sEl.saveRulesBtn.style.background = 'var(--primary)';
        lucide.createIcons();
    }, 2000);
}

// Settings event bindings
sEl.aiRange.addEventListener('input', e => { sEl.aiVal.innerText = e.target.value; });
sEl.t1.addEventListener('change', e => { sEl.stsL1.innerText = e.target.checked ? '[ON]' : '[OFF]'; sEl.stsL1.className = e.target.checked ? 'layer-status on' : 'layer-status'; });
sEl.t2.addEventListener('change', e => { sEl.stsL2.innerText = e.target.checked ? '[ON]' : '[OFF]'; sEl.stsL2.className = e.target.checked ? 'layer-status on' : 'layer-status'; });
sEl.t3.addEventListener('change', e => { sEl.stsL3.innerText = e.target.checked ? '[ON]' : '[OFF]'; sEl.stsL3.className = e.target.checked ? 'layer-status on' : 'layer-status'; });
sEl.addWordBtn.addEventListener('click', addTag);
sEl.blacklistInput.addEventListener('keypress', e => { if (e.key === 'Enter') addTag(); });
sEl.saveRulesBtn.addEventListener('click', saveRules);

// =====================
// EVENT LISTENERS
// =====================
document.addEventListener('DOMContentLoaded', () => {

    // Nav routing
    navDashboard.onclick = e => { e.preventDefault(); switchTab('dashboard'); };
    navLogs.onclick      = e => { e.preventDefault(); switchTab('logs'); };
    navSettings.onclick  = e => { e.preventDefault(); switchTab('settings'); };

    // "Tümünü Gör" link dashboard → logs
    const viewAllLink = document.querySelector('.view-all');
    if (viewAllLink) {
        viewAllLink.addEventListener('click', e => { e.preventDefault(); switchTab('logs'); });
    }

    // Modal close
    closeModalBtn.addEventListener('click', closeLogModal);
    logDetailModal.addEventListener('click', e => { if (e.target === logDetailModal) closeLogModal(); });

    // Filter PILLS — action
    document.querySelectorAll('.filter-pill[data-action]').forEach(pill => {
        pill.addEventListener('click', () => {
            const val = pill.dataset.action;
            activeActionFilter = (activeActionFilter === val) ? '' : val;
            updateFilterPillUI();
            fetchDetailedLogs();
        });
    });

    // Filter PILLS — category
    document.querySelectorAll('.filter-pill[data-category]').forEach(pill => {
        pill.addEventListener('click', () => {
            const val = pill.dataset.category;
            activeCategoryFilter = (activeCategoryFilter === val) ? '' : val;
            updateFilterPillUI();
            fetchDetailedLogs();
        });
    });

    // Apply filters button (if present)
    const applyFiltersBtn = document.getElementById('applyFiltersBtn');
    if (applyFiltersBtn) applyFiltersBtn.addEventListener('click', fetchDetailedLogs);

    // Auto-refresh toggle
    elements.refreshBtn.addEventListener('click', () => {
        isAutoRefresh = !isAutoRefresh;
        if (isAutoRefresh) {
            elements.refreshBtn.classList.add('active-refresh');
            autoRefreshInterval = setInterval(refreshDashboard, 5000);
        } else {
            elements.refreshBtn.classList.remove('active-refresh');
            clearInterval(autoRefreshInterval);
        }
    });

    // Init
    initCharts();
    refreshDashboard();
    switchTab('dashboard');
});
