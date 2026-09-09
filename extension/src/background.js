/**
 * background.js — Extension Service Worker
 *
 * RESPONSIBILITIES:
 * 1. Receive LOG_INCIDENT messages from content_script.js
 * 2. POST sanitized metadata to the FastAPI backend
 * 3. Update the extension badge (shows incident count)
 * 4. Store recent incidents in chrome.storage.local for the popup
 * 5. Generate anonymized user hash (never store real identity)
 *
 * NOTE: Service workers don't have access to DOM or window.
 * They only run when needed and terminate when idle.
 */

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
// Default backend URL — user can change this in the popup settings
const DEFAULT_BACKEND = 'http://localhost:8000';

async function getBackendUrl() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['backendUrl'], (result) => {
      resolve(result.backendUrl || DEFAULT_BACKEND);
    });
  });
}

async function isExtensionEnabled() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['enabled'], (result) => {
      resolve(result.enabled !== false); // Default: enabled
    });
  });
}

// ─── INCIDENT COUNTER ─────────────────────────────────────────────────────────
let incidentCount = 0;

async function loadIncidentCount() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['totalIncidents'], (result) => {
      incidentCount = result.totalIncidents || 0;
      resolve(incidentCount);
    });
  });
}

async function incrementIncidentCount() {
  incidentCount++;
  chrome.storage.local.set({ totalIncidents: incidentCount });
  // Update badge on extension icon
  chrome.action.setBadgeText({ text: incidentCount > 99 ? '99+' : String(incidentCount) });
  chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
}

// Load existing count on startup
loadIncidentCount().then((count) => {
  if (count > 0) {
    chrome.action.setBadgeText({ text: count > 99 ? '99+' : String(count) });
    chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
  }
});

// ─── USER HASH ────────────────────────────────────────────────────────────────
/**
 * We never store real user identity. We generate a stable random hash
 * per installation. The backend gets this hash — it can count incidents
 * per user (for admin dashboard) without knowing who the user is.
 */
async function getUserHash() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['userHash'], (result) => {
      if (result.userHash) {
        resolve(result.userHash);
      } else {
        // Generate new random hash
        const hash = Array.from(crypto.getRandomValues(new Uint8Array(8)))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        chrome.storage.local.set({ userHash: hash });
        resolve(hash);
      }
    });
  });
}

// ─── MESSAGE HANDLER ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'LOG_INCIDENT') {
    handleIncident(message.payload, sender.tab);
    sendResponse({ ok: true });
  }

  if (message.type === 'GET_STATS') {
    chrome.storage.local.get(['recentIncidents', 'totalIncidents'], (result) => {
      sendResponse({
        total: result.totalIncidents || 0,
        recent: result.recentIncidents || []
      });
    });
    return true; // Keep channel open for async response
  }

  if (message.type === 'CLEAR_STATS') {
    chrome.storage.local.set({ totalIncidents: 0, recentIncidents: [] });
    incidentCount = 0;
    chrome.action.setBadgeText({ text: '' });
    sendResponse({ ok: true });
  }

  return true;
});

// ─── INCIDENT HANDLER ─────────────────────────────────────────────────────────
async function handleIncident(payload, tab) {
  const enabled = await isExtensionEnabled();
  if (!enabled) return;

  const userHash = await getUserHash();
  const backendUrl = await getBackendUrl();

  // Build the incident object — NO raw text, only metadata
  const incident = {
    user_hash: userHash,
    categories: payload.categories || [],
    risk_score: payload.riskScore || 0,
    ai_tool: payload.aiTool || 'unknown',
    is_file: payload.isFile || false,
    file_type: payload.fileType || null,
    action_taken: payload.actionTaken || 'tokenized',
  };

  // Store locally for popup display
  storeIncidentLocally(incident);
  incrementIncidentCount();

  // POST to backend (fire-and-forget, never block the page)
  try {
    await fetch(`${backendUrl}/api/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incident),
    });
  } catch (err) {
    // Backend might not be running — that's OK, local storage still works
    console.debug('[PromptShield] Backend unreachable:', err.message);
  }
}

// ─── LOCAL STORAGE ────────────────────────────────────────────────────────────
function storeIncidentLocally(incident) {
  chrome.storage.local.get(['recentIncidents'], (result) => {
    const recent = result.recentIncidents || [];
    recent.unshift({ ...incident, timestamp: Date.now() });
    // Keep only last 100 incidents
    if (recent.length > 100) recent.splice(100);
    chrome.storage.local.set({ recentIncidents: recent });
  });
}
