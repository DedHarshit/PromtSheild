/**
 * content_script.js — Extension isolated world.
 *
 * RESPONSIBILITIES:
 * 1. Inject injected.js into the PAGE's JS context (so it can override fetch)
 * 2. Listen for postMessage from injected.js → forward to background.js
 * 3. Watch for file uploads → scan them → show redaction modal
 * 4. Inject the warning modal CSS + HTML into the page DOM
 *
 * WHY TWO SEPARATE FILES (injected.js + content_script.js)?
 * Extension content scripts run in an "isolated world" — they can touch
 * the DOM but share ZERO global state with the page's JS. To override
 * window.fetch (which lives in the page's JS context), we must inject
 * a <script> tag. That's injected.js. This file bridges the two worlds.
 */

(function () {
  'use strict';

  // ─── 1. INJECT injected.js INTO PAGE CONTEXT ────────────────────────────────
  function injectScript() {
    const script = document.createElement('script');
    // chrome.runtime.getURL gives us the extension-local file URL
    script.src = chrome.runtime.getURL('src/injected.js');
    script.onload = () => script.remove(); // Clean up after injection
    (document.head || document.documentElement).appendChild(script);
  }

  injectScript();

  // ─── 2. LISTEN FOR MESSAGES FROM injected.js ────────────────────────────────
  /**
   * injected.js communicates via window.postMessage (the only way to
   * communicate from page context → content script).
   * We filter by source: 'promptshield-injected' to avoid conflicts.
   */
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data?.source?.startsWith('promptshield')) return;

    if (event.data.type === 'INCIDENT') {
      // Forward to background.js (which will send to backend API)
      chrome.runtime.sendMessage({
        type: 'LOG_INCIDENT',
        payload: event.data.payload
      });

      // Show non-intrusive toast notification in the page
      showToast(event.data.payload);
    }
  });

  // ─── 3. FILE UPLOAD INTERCEPTION ────────────────────────────────────────────
  /**
   * We need to catch when users upload files to AI tools.
   * Strategy: use MutationObserver to find file <input> elements as they
   * appear in the DOM, then add change listeners to them.
   */

  // Detection patterns (same as injected.js but here for file scanning)
  const FILE_PATTERNS = [
    { name: 'AWS_KEY',     pattern: /\bAKIA[A-Z0-9]{16}\b/g,                                severity: 'critical' },
    { name: 'GITHUB_TOKEN', pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,255}\b/g,                    severity: 'critical' },
    { name: 'OPENAI_KEY',  pattern: /\bsk-[a-zA-Z0-9]{20,60}\b/g,                           severity: 'critical' },
    { name: 'GOOGLE_API_KEY', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,                                                   severity: 'critical' },
    { name: 'SLACK_TOKEN',    pattern: /\bxox[bpoas]-[0-9A-Za-z\-]{10,72}\b/g,                                        severity: 'critical' },
    { name: 'PRIVATE_KEY', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,    severity: 'critical' },
    { name: 'JWT',         pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g, severity: 'high' },
    { name: 'CREDIT_CARD', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/g,    severity: 'critical' },
    { name: 'SSN',         pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                               severity: 'critical' },
    { name: 'PASSWORD',    pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,                severity: 'high' },
    { name: 'API_SECRET',  pattern: /(?:secret|api[_-]?key|token)\s*[:=]\s*[^\s,;'"]{8,}/gi, severity: 'high' },
    { name: 'DB_CONN',     pattern: /(?:mongodb|postgresql|mysql|redis):\/\/[^\s"']+/gi,      severity: 'high' },
    { name: 'EMAIL',       pattern: /\b[a-zA-Z0-9._%+-]{2,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, severity: 'medium' },
  ];

  function scanText(text) {
    const findings = [];
    let riskScore = 0;
    const scoreMap = { critical: 40, high: 25, medium: 10, low: 5 };

    for (const detector of FILE_PATTERNS) {
      detector.pattern.lastIndex = 0;
      const matches = text.match(detector.pattern);
      if (matches) {
        findings.push({ name: detector.name, count: matches.length, severity: detector.severity });
        riskScore = Math.min(100, riskScore + scoreMap[detector.severity] * Math.min(matches.length, 3));
      }
    }
    return { findings, riskScore };
  }

  function redactText(text) {
    let redacted = text;
    for (const detector of FILE_PATTERNS) {
      detector.pattern.lastIndex = 0;
      redacted = redacted.replace(detector.pattern, `[${detector.name}_REDACTED]`);
    }
    return redacted;
  }

  // Track file inputs we've already attached listeners to
  const attachedInputs = new WeakSet();

  function attachFileInputListener(input) {
    if (attachedInputs.has(input)) return;
    attachedInputs.add(input);

    input.addEventListener('change', async (event) => {
      const file = event.target.files?.[0];
      if (!file) return;

      // Only scan text-based files (PDF needs special handling)
      const textTypes = ['text/', 'application/json', 'application/javascript',
                         'application/x-python', 'text/x-python', 'text/csv',
                         'application/xml', 'application/x-sh'];
      const isTextFile = textTypes.some(t => file.type.startsWith(t)) || 
                         /\.(txt|js|py|ts|json|csv|xml|sh|md|yaml|yml|env|config|conf|ini|toml)$/i.test(file.name);
      const isPDF = file.type === 'application/pdf' || file.name.endsWith('.pdf');

      if (isTextFile) {
        await handleTextFile(file, input);
      } else if (isPDF) {
        await handlePDFFile(file, input);
      }
      // For Word/Excel: show a warning that we detected an upload
    });
  }

  async function handleTextFile(file, input) {
    const text = await readFileAsText(file);
    const { findings, riskScore } = scanText(text);

    if (findings.length === 0) return; // Clean file, proceed normally

    // Show modal asking user what to do
    showFileModal(file.name, findings, riskScore, () => {
      // User chose REDACT: create redacted version and replace input
      const redactedText = redactText(text);
      const redactedFile = new File([redactedText], file.name, { type: file.type });
      replaceFileInput(input, redactedFile);

      // Log file incident
      chrome.runtime.sendMessage({
        type: 'LOG_INCIDENT',
        payload: {
          categories: findings.map(f => f.name),
          riskScore,
          aiTool: detectCurrentTool(),
          actionTaken: 'file_redacted',
          isFile: true,
          fileType: file.name.split('.').pop(),
        }
      });
    }, () => {
      // User chose BLOCK: clear the file input
      input.value = '';
      chrome.runtime.sendMessage({
        type: 'LOG_INCIDENT',
        payload: {
          categories: findings.map(f => f.name),
          riskScore,
          aiTool: detectCurrentTool(),
          actionTaken: 'file_blocked',
          isFile: true,
          fileType: file.name.split('.').pop(),
        }
      });
    });
  }

  async function handlePDFFile(file, input) {
    // Basic PDF text extraction: PDFs store text in content streams
    // This handles simple text-based PDFs (not scanned images)
    const arrayBuffer = await readFileAsArrayBuffer(file);
    const text = extractTextFromPDF(arrayBuffer);

    if (!text || text.length < 10) {
      // Could not extract text (scanned PDF), show generic warning
      showToast({ categories: ['UNKNOWN_FILE_CONTENT'], riskScore: 50, aiTool: detectCurrentTool() });
      return;
    }

    const { findings, riskScore } = scanText(text);
    if (findings.length === 0) return;

    showFileModal(file.name, findings, riskScore, () => {
      // Redact text version and create new "sanitized" file
      const redactedText = redactText(text);
      const redactedFile = new File([redactedText], file.name.replace('.pdf', '_redacted.txt'), { type: 'text/plain' });
      replaceFileInput(input, redactedFile);

      chrome.runtime.sendMessage({
        type: 'LOG_INCIDENT',
        payload: {
          categories: findings.map(f => f.name),
          riskScore,
          aiTool: detectCurrentTool(),
          actionTaken: 'pdf_redacted',
          isFile: true,
          fileType: 'pdf',
        }
      });
    }, () => {
      input.value = '';
    });
  }

  // ─── 4. PDF TEXT EXTRACTION ─────────────────────────────────────────────────
  /**
   * Basic PDF text extraction without pdf.js.
   * Works for text-based PDFs by finding BT...ET content streams.
   * For production, replace with pdf.js for full support.
   */
  function extractTextFromPDF(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let str = '';
    // Convert to Latin-1 string for regex matching
    for (let i = 0; i < Math.min(bytes.length, 500000); i++) {
      str += String.fromCharCode(bytes[i]);
    }

    // Extract text objects between BT (begin text) and ET (end text)
    const textObjects = str.match(/BT[\s\S]*?ET/g) || [];
    const texts = [];

    for (const obj of textObjects) {
      // Match Tj (show text) and TJ (show text with adjustments) operators
      const matches = obj.match(/\(((?:[^()\\]|\\.)*)\)\s*Tj/g) || [];
      for (const match of matches) {
        const text = match.replace(/\((.*)\)\s*Tj/s, '$1')
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '')
          .replace(/\\t/g, ' ')
          .replace(/\\\(/g, '(')
          .replace(/\\\)/g, ')');
        texts.push(text);
      }
    }

    return texts.join(' ');
  }

  // ─── 5. FILE INPUT HELPERS ──────────────────────────────────────────────────
  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  }

  function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  function replaceFileInput(input, newFile) {
    try {
      const dataTransfer = new DataTransfer();
      dataTransfer.items.add(newFile);
      input.files = dataTransfer.files;
      // Trigger change event so the page knows about the new file
      input.dispatchEvent(new Event('change', { bubbles: true }));
    } catch (e) {
      console.debug('[PromptShield] Could not replace file input:', e);
    }
  }

  function detectCurrentTool() {
    const hostname = window.location.hostname;
    if (hostname.includes('openai') || hostname.includes('chatgpt')) return 'chatgpt';
    if (hostname.includes('claude')) return 'claude';
    if (hostname.includes('gemini')) return 'gemini';
    if (hostname.includes('copilot')) return 'copilot';
    return 'unknown';
  }

  // ─── 6. DOM OBSERVER FOR FILE INPUTS ────────────────────────────────────────
  /**
   * ChatGPT/Claude add file inputs dynamically when you click the upload button.
   * We watch for new file input elements appearing in the DOM.
   */
  function scanForFileInputs(root) {
    const inputs = root.querySelectorAll('input[type="file"]');
    inputs.forEach(attachFileInputListener);
  }

  scanForFileInputs(document); // Scan on load

  const domObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'INPUT' && node.type === 'file') {
            attachFileInputListener(node);
          } else {
            scanForFileInputs(node);
          }
        }
      }
    }
  });

  domObserver.observe(document.documentElement, { childList: true, subtree: true });

  // ─── 7. TOAST NOTIFICATION ──────────────────────────────────────────────────
  injectStyles();

  function showToast(payload) {
    const existing = document.getElementById('ps-toast');
    if (existing) existing.remove();

    const categories = payload.categories || [];
    const score = payload.riskScore || 0;
    const color = score >= 70 ? '#dc2626' : score >= 40 ? '#d97706' : '#2563eb';

    const toast = document.createElement('div');
    toast.id = 'ps-toast';
    toast.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;">
        <div style="width:10px;height:10px;border-radius:50%;background:${color};flex-shrink:0;"></div>
        <div>
          <div style="font-weight:600;font-size:13px;color:#1a1a1a;">PromptShield — Data Tokenized</div>
          <div style="font-size:12px;color:#555;margin-top:2px;">${categories.join(', ')} · Risk: ${score}/100</div>
        </div>
        <div style="margin-left:auto;font-size:11px;background:${color}15;color:${color};padding:2px 8px;border-radius:99px;font-weight:600;">Protected</div>
      </div>
    `;
    toast.className = 'ps-toast-anim';
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), 4000);
  }

  // ─── 8. FILE WARNING MODAL ──────────────────────────────────────────────────
  function showFileModal(fileName, findings, riskScore, onRedact, onBlock) {
    const existing = document.getElementById('ps-modal-overlay');
    if (existing) existing.remove();

    const color = riskScore >= 70 ? '#dc2626' : '#d97706';
    const findingList = findings.map(f =>
      `<li style="margin:4px 0;color:#374151;font-size:13px;">
        <span style="font-weight:600;color:${f.severity === 'critical' ? '#dc2626' : '#d97706'}">● ${f.name}</span>
        &nbsp;(${f.count || 1} found, ${f.severity})
      </li>`
    ).join('');

    const overlay = document.createElement('div');
    overlay.id = 'ps-modal-overlay';
    overlay.style.cssText = `
      position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:2147483647;
      display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,sans-serif;
    `;

    overlay.innerHTML = `
      <div style="background:#fff;border-radius:14px;padding:28px;max-width:440px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.25);">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
          <div style="width:36px;height:36px;border-radius:50%;background:${color}15;display:flex;align-items:center;justify-content:center;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </div>
          <div>
            <div style="font-size:16px;font-weight:700;color:#111;">Sensitive Data Detected</div>
            <div style="font-size:12px;color:#888;margin-top:1px;">${fileName} · Risk Score: ${riskScore}/100</div>
          </div>
        </div>
        <p style="color:#4b5563;font-size:13px;margin:0 0 12px;">The file you're uploading contains sensitive information:</p>
        <ul style="list-style:none;margin:0 0 20px;padding:0 0 0 4px;">${findingList}</ul>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button id="ps-btn-redact" style="flex:1;padding:10px 16px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;min-width:120px;">
            Redact &amp; Upload
          </button>
          <button id="ps-btn-block" style="flex:1;padding:10px 16px;background:#f3f4f6;color:#374151;border:1px solid #e5e7eb;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;min-width:120px;">
            Cancel Upload
          </button>
          <button id="ps-btn-proceed" style="width:100%;padding:8px 16px;background:transparent;color:#9ca3af;border:none;border-radius:8px;font-size:12px;cursor:pointer;">
            Proceed anyway (dangerous)
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('ps-btn-redact').onclick = () => { overlay.remove(); onRedact(); };
    document.getElementById('ps-btn-block').onclick = () => { overlay.remove(); onBlock(); };
    document.getElementById('ps-btn-proceed').onclick = () => { overlay.remove(); };
    overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); onBlock(); } };
  }

  // ─── 9. INJECT CSS ──────────────────────────────────────────────────────────
  function injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
      #ps-toast {
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: #fff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 14px 18px;
        z-index: 2147483647;
        box-shadow: 0 4px 20px rgba(0,0,0,0.12);
        max-width: 340px;
        font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      }
      .ps-toast-anim {
        animation: ps-slidein 0.3s ease, ps-fadeout 0.4s ease 3.6s forwards;
      }
      @keyframes ps-slidein {
        from { opacity: 0; transform: translateY(12px); }
        to   { opacity: 1; transform: translateY(0); }
      }
      @keyframes ps-fadeout {
        from { opacity: 1; }
        to   { opacity: 0; }
      }
    `;
    document.documentElement.appendChild(style);
  }

})();
