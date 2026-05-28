const API_BASE = '/api/v1';

async function apiFetch(path, opts = {}) {
  try {
    const res = await fetch(path, opts);
    return res;
  } catch (e) {
    console.error('Network error:', e, path);
    return null;
  }
}

const refs = {
  navDashboard: document.getElementById('nav-dashboard'),
  navLogs: document.getElementById('nav-logs'),
  navSettings: document.getElementById('nav-settings'),
  viewDashboard: document.getElementById('view-dashboard'),
  viewLogs: document.getElementById('view-logs'),
  viewSettings: document.getElementById('view-settings'),
  valTotal: document.getElementById('valTotal'),
  valBlocked: document.getElementById('valBlocked'),
  valAllowed: document.getElementById('valAllowed'),
  valLatency: document.getElementById('valLatency'),
  logsTableBody: document.getElementById('logsTableBody'),
  fullLogsTableBody: document.getElementById('fullLogsTableBody'),
  ratioChart: document.getElementById('ratioChart'),
  categoryChart: document.getElementById('categoryChart'),
  refreshBtn: document.getElementById('refreshBtn'),
  logDetailModal: document.getElementById('logDetailModal'),
  closeModalBtn: document.getElementById('closeModalBtn'),
  modalTitle: document.getElementById('modalLogIdTitle'),
  mdlDate: document.getElementById('mdlDate'),
  mdlTime: document.getElementById('mdlTime'),
  mdlUser: document.getElementById('mdlUser'),
  mdlStatus: document.getElementById('mdlStatus'),
  mdlPrompt: document.getElementById('mdlPrompt'),
  mdlWarning: document.getElementById('mdlWarning'),
  mdlLayer: document.getElementById('mdlLayer'),
  mdlScoreBar: document.getElementById('mdlScoreBar'),
  mdlScoreText: document.getElementById('mdlScoreText'),
  mdlCategory: document.getElementById('mdlCategory'),
  btnValidate: document.getElementById('btnValidate'),
  btnFalsePositive: document.getElementById('btnFalsePositive'),
  t1: document.getElementById('tglLayer1'),
  t2: document.getElementById('tglLayer2'),
  t3: document.getElementById('tglLayer3'),
  stsL1: document.getElementById('stsL1'),
  stsL2: document.getElementById('stsL2'),
  stsL3: document.getElementById('stsL3'),
  aiRange: document.getElementById('aiThreshold'),
  aiVal: document.getElementById('aiThresholdVal'),
  blacklistWrapper: document.getElementById('blacklistTags'),
  blacklistInput: document.getElementById('blacklistInput'),
  addWordBtn: document.getElementById('addWordBtn'),
  saveRulesBtn: document.getElementById('saveRulesBtn')
};

let charts = { ratio: null, category: null };

function extractDate(iso) {
  const date = new Date(iso);
  return {
    date: date.toLocaleDateString('tr-TR'),
    time: date.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  };
}

function safeEncode(obj) {
  return btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
}

function safeDecode(str) {
  return JSON.parse(decodeURIComponent(escape(atob(str))));
}

function updateLayerStatus() {
  refs.stsL1.innerText = refs.t1.checked ? '✅ Aktif' : '❌ Pasif';
  refs.stsL2.innerText = refs.t2.checked ? '✅ Aktif' : '❌ Pasif';
  refs.stsL3.innerText = refs.t3.checked ? '✅ Aktif' : '❌ Pasif';
}

async function openLogModal(data) {
  const log = typeof data === 'string' ? safeDecode(data) : data;
  const dt = extractDate(log.created_at || new Date().toISOString());
  refs.modalTitle.innerText = `Log Detayı: #${(log.log_id || '').split('-')[0]}`;
  refs.mdlDate.innerText = dt.date;
  refs.mdlTime.innerText = dt.time;
  refs.mdlUser.innerText = log.user_id || '-';
  refs.mdlPrompt.innerText = log.masked_prompt || '-';
  refs.mdlLayer.innerText = log.stopped_at_layer || '-';
  refs.mdlCategory.innerText = log.category || '-';
  const pct = Math.round((log.ai_confidence_score || 0) * 100);
  refs.mdlScoreText.innerText = pct;
  refs.mdlScoreBar.style.width = pct + '%';
  refs.mdlStatus.innerText = log.action === 'BLOCK' ? 'BLOKLANDI' : 'İZİN VERİLDİ';
  refs.mdlStatus.className = `badge badge-lg ${log.action === 'BLOCK' ? 'badge-block' : 'badge-allow'}`;
  refs.mdlWarning.style.display = log.action === 'BLOCK' ? 'flex' : 'none';
  refs.btnValidate.onclick = () => submitFeedback(log.log_id, 'safe', refs.btnValidate);
  refs.btnFalsePositive.onclick = () => submitFeedback(log.log_id, 'false_positive', refs.btnFalsePositive);
  refs.logDetailModal.style.display = 'flex';
  if (window.lucide) lucide.createIcons();
}

function closeLogModal() {
  refs.logDetailModal.style.display = 'none';
}

async function submitFeedback(logId, type, btn) {
  const original = btn.innerHTML;
  btn.innerHTML = 'Kaydediliyor...';
  try {
    const res = await apiFetch(`${API_BASE}/feedback?log_id=${encodeURIComponent(logId)}&feedback_type=${encodeURIComponent(type)}`, { method: 'POST' });
    if (!res || !res.ok) throw new Error('Feedback failed');
    btn.innerHTML = 'Teşekkürler';
    setTimeout(closeLogModal, 1200);
  } catch (error) {
    console.error(error);
    btn.innerHTML = 'Hata';
    setTimeout(() => { btn.innerHTML = original; }, 1500);
  }
}

async function initCharts() {
  if (!refs.ratioChart || !refs.categoryChart) return;
  Chart.defaults.color = '#94a3b8';
  charts.ratio = new Chart(refs.ratioChart.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Engellenen', 'İzin Verilen'],
      datasets: [{ data: [0, 0], backgroundColor: ['#ef4444', '#10b981'], borderWidth: 0 }]
    },
    options: { cutout: '70%', responsive: true, maintainAspectRatio: false }
  });
  charts.category = new Chart(refs.categoryChart.getContext('2d'), {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Olay Sayısı', data: [], backgroundColor: '#6366f1' }] },
    options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
  });
}

async function refreshDashboard() {
  const statsRes = await apiFetch(`${API_BASE}/stats`);
  if (!statsRes) return;
  const stats = await statsRes.json();
  refs.valTotal.innerText = stats.total_requests || 0;
  refs.valBlocked.innerText = stats.blocked || 0;
  refs.valAllowed.innerText = stats.allowed || 0;
  refs.valLatency.innerText = `${stats.avg_latency_ms || 0}ms`;
  if (charts.ratio) {
    charts.ratio.data.datasets[0].data = [stats.blocked || 0, stats.allowed || 0];
    charts.ratio.update();
  }
  const logsRes = await apiFetch(`${API_BASE}/logs?limit=10`);
  if (!logsRes) return;
  const logs = await logsRes.json();
  let html = '';
  if (logs.logs && logs.logs.length) {
    logs.logs.forEach(log => {
      const dt = extractDate(log.created_at || new Date().toISOString());
      html += `<tr style="cursor:pointer;" onclick='openLogModal("${safeEncode(log)}")'>
        <td>${dt.time}</td>
        <td>${log.user_id || '-'}</td>
        <td>${(log.masked_prompt || '-').slice(0, 80)}</td>
        <td>${log.stopped_at_layer || '-'}</td>
        <td>${log.category || '-'}</td>
        <td>${log.action || '-'}</td>
      </tr>`;
    });
  } else {
    html = '<tr><td colspan="6" class="text-center">Henüz kayıt yok.</td></tr>';
  }
  refs.logsTableBody.innerHTML = html;
  if (charts.category) {
    const counts = {};
    (logs.logs || []).forEach(log => { counts[log.category] = (counts[log.category] || 0) + 1; });
    charts.category.data.labels = Object.keys(counts);
    charts.category.data.datasets[0].data = Object.values(counts);
    charts.category.update();
  }
}

function buildFilterUrl() {
  let url = `${API_BASE}/logs?limit=200`;
  if (window._actionFilter) url += `&action=${window._actionFilter}`;
  if (window._categoryFilter) url += `&category=${window._categoryFilter}`;
  return url;
}

async function fetchDetailedLogs() {
  refs.fullLogsTableBody.innerHTML = '<tr><td colspan="6" class="text-center">Yükleniyor...</td></tr>';
  const res = await apiFetch(buildFilterUrl());
  if (!res) return;
  const data = await res.json();
  let html = '';
  if (data.logs && data.logs.length) {
    data.logs.forEach(log => {
      const dt = extractDate(log.created_at || new Date().toISOString());
      html += `<tr style="cursor:pointer;" onclick='openLogModal("${safeEncode(log)}")'>
        <td>${(log.log_id || '').split('-')[0]}</td>
        <td>${dt.date} ${dt.time}</td>
        <td>${log.user_id || '-'}</td>
        <td>${log.stopped_at_layer || '-'}</td>
        <td>${log.category || '-'}</td>
        <td>${log.action || '-'}</td>
      </tr>`;
    });
  } else {
    html = '<tr><td colspan="6" class="text-center">Kayıt bulunamadı.</td></tr>';
  }
  refs.fullLogsTableBody.innerHTML = html;
}

function renderBlacklist(words) {
  refs.blacklistWrapper.innerHTML = '';
  (words || []).forEach(word => {
    const tag = document.createElement('div');
    tag.className = 'blacklist-tag';
    tag.innerHTML = `${word} <button class="tag-remove">✕</button>`;
    tag.querySelector('.tag-remove').onclick = () => removeBlacklist(word);
    refs.blacklistWrapper.appendChild(tag);
  });
}

async function fetchRules() {
  const res = await apiFetch(`${API_BASE}/config`);
  if (!res) return;
  const cfg = await res.json();
  refs.t1.checked = !!cfg.layer_regex;
  refs.t2.checked = !!cfg.layer_deberta;
  refs.t3.checked = !!cfg.layer_llm;
  refs.stsL1.innerText = cfg.layer_regex ? '[ON]' : '[OFF]';
  refs.stsL2.innerText = cfg.layer_deberta ? '[ON]' : '[OFF]';
  refs.stsL3.innerText = cfg.layer_llm ? '[ON]' : '[OFF]';
  refs.aiRange.value = cfg.ai_threshold || 0.75;
  refs.aiVal.innerText = refs.aiRange.value;
  renderBlacklist(cfg.blacklist || []);
}

async function addBlacklist() {
  const word = refs.blacklistInput.value.trim();
  if (!word) return alert('Kelime girin');
  const res = await apiFetch(`${API_BASE}/config/blacklist?operation=add&word=${encodeURIComponent(word)}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Kelime eklenemedi');
  const data = await res.json();
  renderBlacklist(data.blacklist || []);
  refs.blacklistInput.value = '';
}

async function removeBlacklist(word) {
  if (!confirm(`"${word}" silinsin mi?`)) return;
  const res = await apiFetch(`${API_BASE}/config/blacklist?operation=remove&word=${encodeURIComponent(word)}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Kelime silinemedi');
  const data = await res.json();
  renderBlacklist(data.blacklist || []);
}

async function saveThreshold() {
  const value = parseFloat(refs.aiRange.value);
  const res = await apiFetch(`${API_BASE}/config/threshold?threshold=${value}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Threshold kaydedilemedi');
  alert('Threshold kaydedildi');
}

async function toggleLayer(n) {
  const params = new URLSearchParams();
  if (n === 1) params.append('layer1', refs.t1.checked);
  if (n === 2) params.append('layer2', refs.t2.checked);
  if (n === 3) params.append('layer3', refs.t3.checked);
  const res = await apiFetch(`${API_BASE}/config/layers?${params.toString()}`, { method: 'PUT' });
  if (!res || !res.ok) return alert('Layer güncellenemedi');
  fetchRules();
}

window.addEventListener('DOMContentLoaded', async () => {
  refs.navDashboard.addEventListener('click', e => { e.preventDefault(); refs.viewDashboard.classList.add('active'); refs.viewLogs.classList.remove('active'); refs.viewSettings.classList.remove('active'); refreshDashboard(); });
  refs.navLogs.addEventListener('click', e => { e.preventDefault(); refs.viewLogs.classList.add('active'); refs.viewDashboard.classList.remove('active'); refs.viewSettings.classList.remove('active'); fetchDetailedLogs(); });
  refs.navSettings.addEventListener('click', e => { e.preventDefault(); refs.viewSettings.classList.add('active'); refs.viewDashboard.classList.remove('active'); refs.viewLogs.classList.remove('active'); fetchRules(); });

  document.querySelectorAll('.filter-pill[data-action]').forEach(pill => pill.addEventListener('click', () => { window._actionFilter = pill.dataset.action; fetchDetailedLogs(); }));
  document.querySelectorAll('.filter-pill[data-category]').forEach(pill => pill.addEventListener('click', () => { window._categoryFilter = pill.dataset.category; fetchDetailedLogs(); }));

  refs.closeModalBtn.addEventListener('click', closeLogModal);
  refs.logDetailModal.addEventListener('click', e => { if (e.target === refs.logDetailModal) closeLogModal(); });
  refs.addWordBtn.addEventListener('click', addBlacklist);
  refs.blacklistInput.addEventListener('keypress', e => { if (e.key === 'Enter') addBlacklist(); });
  refs.saveRulesBtn.addEventListener('click', saveThreshold);
  refs.t1.addEventListener('change', () => { updateLayerStatus(); toggleLayer(1); });
  refs.t2.addEventListener('change', () => { updateLayerStatus(); toggleLayer(2); });
  refs.t3.addEventListener('change', () => { updateLayerStatus(); toggleLayer(3); });
  refs.aiRange.addEventListener('input', () => { refs.aiVal.innerText = refs.aiRange.value; });
  refs.refreshBtn.addEventListener('click', () => {
    if (window._autoRefresh) { clearInterval(window._autoRefresh); window._autoRefresh = null; refs.refreshBtn.classList.remove('active-refresh'); }
    else { refs.refreshBtn.classList.add('active-refresh'); window._autoRefresh = setInterval(refreshDashboard, 5000); }
  });

  await initCharts();
  refreshDashboard();
});
