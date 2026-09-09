/**
 * popup.js — Extension Popup Logic
 *
 * Communicates with background.js via chrome.runtime.sendMessage.
 * Reads/writes settings via chrome.storage.sync.
 */

const DEFAULT_BACKEND = 'http://localhost:8000';

// ─── LOAD STATE ON OPEN ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadToggleState();
  await loadSettings();
  await loadStats();
});

// ─── ENABLED TOGGLE ───────────────────────────────────────────────────────────
const toggle = document.getElementById('enabled-toggle');
const toggleLabel = document.getElementById('toggle-label');
const statusText = document.getElementById('status-text');

async function loadToggleState() {
  chrome.storage.sync.get(['enabled'], (result) => {
    const enabled = result.enabled !== false;
    toggle.checked = enabled;
    updateToggleUI(enabled);
  });
}

toggle.addEventListener('change', () => {
  const enabled = toggle.checked;
  chrome.storage.sync.set({ enabled });
  updateToggleUI(enabled);
});

function updateToggleUI(enabled) {
  toggleLabel.textContent = enabled ? 'ON' : 'OFF';
  statusText.textContent = enabled
    ? 'Active — protecting your AI sessions'
    : 'Paused — data is not being scanned';
}

// ─── STATS ────────────────────────────────────────────────────────────────────
async function loadStats() {
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
    if (!response) return;

    document.getElementById('total-count').textContent = response.total || 0;

    const recent = response.recent || [];

    // Count file incidents
    const fileCount = recent.filter(i => i.is_file).length;
    document.getElementById('file-count').textContent = fileCount;

    // Session incidents (last hour)
    const oneHourAgo = Date.now() - 3600000;
    const sessionCount = recent.filter(i => i.timestamp > oneHourAgo).length;
    document.getElementById('session-count').textContent = sessionCount;

    // Render incident list
    renderIncidents(recent.slice(0, 8));
  });
}

function renderIncidents(incidents) {
  const list = document.getElementById('incident-list');

  if (!incidents || incidents.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        No incidents yet. Start chatting!
      </div>
    `;
    return;
  }

  list.innerHTML = incidents.map(incident => {
    const dotClass = incident.risk_score >= 70 ? 'dot-critical'
                   : incident.risk_score >= 40 ? 'dot-high' : 'dot-medium';
    const cats = (incident.categories || []).slice(0, 3).join(', ');
    const time = formatTime(incident.timestamp);
    const tool = incident.ai_tool || 'unknown';
    const isFile = incident.is_file ? ' · 📎 file' : '';

    return `
      <div class="incident-item">
        <div class="incident-dot ${dotClass}"></div>
        <div style="flex:1;min-width:0;">
          <div class="incident-cats">${cats || 'Unknown'}</div>
          <div class="incident-meta">${time}${isFile} · Risk: ${incident.risk_score}/100</div>
        </div>
        <span class="incident-tool">${tool}</span>
      </div>
    `;
  }).join('');
}

function formatTime(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return new Date(ts).toLocaleDateString();
}

// ─── SETTINGS ─────────────────────────────────────────────────────────────────
async function loadSettings() {
  chrome.storage.sync.get(['backendUrl'], (result) => {
    document.getElementById('backend-url').value = result.backendUrl || DEFAULT_BACKEND;
  });
}

document.getElementById('save-settings').addEventListener('click', () => {
  const url = document.getElementById('backend-url').value.trim() || DEFAULT_BACKEND;
  chrome.storage.sync.set({ backendUrl: url }, () => {
    const btn = document.getElementById('save-settings');
    btn.textContent = '✓ Saved';
    setTimeout(() => { btn.textContent = 'Save Settings'; }, 1500);
  });
});

// ─── BUTTONS ──────────────────────────────────────────────────────────────────
document.getElementById('settings-btn').addEventListener('click', () => {
  const panel = document.getElementById('settings-panel');
  panel.classList.toggle('open');
});

document.getElementById('clear-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'CLEAR_STATS' }, () => {
    loadStats();
  });
});

document.getElementById('dashboard-btn').addEventListener('click', () => {
  chrome.storage.sync.get(['backendUrl'], (result) => {
    const url = result.backendUrl || DEFAULT_BACKEND;
    chrome.tabs.create({ url });
  });
});
