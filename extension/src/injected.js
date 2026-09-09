/**
 * injected.js — Runs inside the PAGE's JavaScript context.
 *
 * WHY THIS FILE EXISTS:
 * Content scripts run in an "isolated world" — they share the DOM but
 * NOT the JS environment with the page. So to intercept window.fetch
 * (ChatGPT's actual fetch calls), we must inject a <script> tag into
 * the page. This file IS that script.
 *
 * DATA FLOW:
 * 1. User types prompt → ChatGPT's JS calls fetch()
 * 2. Our overridden fetch() runs FIRST
 * 3. We tokenize secrets (replace with [EMAIL_AB12], etc.)
 * 4. MODIFIED request goes to OpenAI — real secrets never leave browser
 * 5. Response comes back with tokens in it
 * 6. We restore tokens back to originals in the DOM (via MutationObserver)
 * 7. We postMessage metadata (no raw text) to content_script.js
 */

(function () {
  'use strict';

  // ─── 1. CONFIGURATION ──────────────────────────────────────────────────────
  const CONFIG = {
    // Domains where we should intercept traffic
    targetDomains: ['chat.openai.com', 'chatgpt.com', 'claude.ai', 'gemini.google.com', 'copilot.microsoft.com'],
    // API paths that contain the user's prompt
    promptPaths: ['/backend-api/conversation', '/api/chat', '/api/generate', '/chat'],
    // Risk scoring weights
    severityScore: { critical: 40, high: 25, medium: 10, low: 5 },
  };

  // ─── 2. DETECTION PATTERNS ─────────────────────────────────────────────────
  // Each detector: { pattern (regex), label (used in token), severity }
  const DETECTORS = [
    { name: 'AWS_KEY',      pattern: /\bAKIA[A-Z0-9]{16}\b/g,                                                            severity: 'critical' },
    { name: 'GITHUB_TOKEN', pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,255}\b/g,                    severity: 'critical' },
   { name: 'OPENAI_KEY', pattern: /\bsk-(?:proj-)?[a-zA-Z0-9]{20,}\b/g, severity: 'critical' },
    { name: 'GOOGLE_API_KEY', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,                                                   severity: 'critical' },
    { name: 'SLACK_TOKEN',    pattern: /\bxox[bpoas]-[0-9A-Za-z\-]{10,72}\b/g,                                        severity: 'critical' },
    { name: 'PRIVATE_KEY',  pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical' },
    { name: 'JWT',          pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,              severity: 'high' },
    { name: 'CREDIT_CARD',  pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, severity: 'critical' },
    { name: 'SSN',          pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                                                            severity: 'critical' },
    { name: 'PASSWORD',     pattern: /(?:password|passwd|pwd|pass)\s*[:=]\s*([^\s,;'"\\]{4,})/gi,                         severity: 'high' },
    { name: 'API_SECRET',   pattern: /(?:secret|api[_-]?key|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*([^\s,;'"\\]{8,})/gi, severity: 'high' },
    { name: 'DB_CONN',      pattern: /(?:mongodb|postgresql|mysql|redis):\/\/[^\s"']+/gi,                                  severity: 'high' },
    { name: 'EMAIL',        pattern: /\b[a-zA-Z0-9._%+-]{2,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,                          severity: 'medium' },
    { name: 'PHONE',        pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,                         severity: 'medium' },
    { name: 'IP_ADDR',      pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,   severity: 'low' },
  ];

  // ─── 3. TOKEN MAP ───────────────────────────────────────────────────────────
  // Maps token → original secret, stored in page memory only
  // Format: { "[EMAIL_AB12]": "john@company.com" }
  const TOKEN_MAP = {};

  function generateId() {
    // Short random ID: AB12 style, readable in prompts
    return Math.random().toString(36).substr(2, 4).toUpperCase();
  }

  // ─── 4. TOKENIZER ───────────────────────────────────────────────────────────
  /**
   * Scans text for sensitive data and replaces with reversible tokens.
   * Returns { sanitized: string, mapping: {token: original}, findings: [], riskScore: number }
   */
  function tokenize(text) {
    let sanitized = text;
    const findings = []; // { name, token, original } — for logging (no raw values sent to server)
    let riskScore = 0;

    for (const detector of DETECTORS) {
      // Reset regex state (important for global regexes used multiple times)
      detector.pattern.lastIndex = 0;

      sanitized = sanitized.replace(detector.pattern, (match) => {
        const token = `[${detector.name}_${generateId()}]`;
        TOKEN_MAP[token] = match; // Store mapping in memory
        findings.push({ name: detector.name, token, severity: detector.severity });
        riskScore = Math.min(100, riskScore + CONFIG.severityScore[detector.severity]);
        return token;
      });
    }

    return { sanitized, findings, riskScore, modified: findings.length > 0 };
  }

  // ─── 5. DE-TOKENIZER ────────────────────────────────────────────────────────
  /**
   * Replaces tokens back with original values in a string.
   * Used for DOM patching in MutationObserver.
   */
  function detokenize(text) {
    let result = text;
    for (const [token, original] of Object.entries(TOKEN_MAP)) {
      // Escape special regex chars in token (the brackets [ ] need escaping)
      const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      result = result.replace(new RegExp(escaped, 'g'), original);
    }
    return result;
  }

  // ─── 6. EXTRACT PROMPT FROM REQUEST BODY ────────────────────────────────────
  /**
   * Different AI tools format their request bodies differently.
   * This extracts the user message text from the body JSON.
   */
  function extractPromptText(bodyJson) {
    try {
      // ChatGPT format
      if (bodyJson.messages) {
        return bodyJson.messages.map(m => {
          // Modern ChatGPT sends content as an array of parts
          if (Array.isArray(m.content)) {
            return m.content
              .filter(part => part.type === 'text')
              .map(part => part.text || '')
              .join('\n');
          }
          // Older format: content is a plain string
          if (typeof m.content === 'string') return m.content;
          return JSON.stringify(m.content);
        }).join('\n');
      }
      // Claude format
      if (bodyJson.prompt) return bodyJson.prompt;
      if (bodyJson.query) return bodyJson.query;
      // Generic
      return JSON.stringify(bodyJson);
    } catch {
      return '';
    }
  }

  /**
   * Rebuilds the request body with tokenized content.
   */
  function patchBodyWithTokens(bodyJson, tokenMap) {
    const str = JSON.stringify(bodyJson);
    // Replace each original with its token
    let patched = str;
    for (const [token, original] of Object.entries(tokenMap)) {
      const escaped = original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      patched = patched.replace(new RegExp(escaped, 'g'), token);
    }
    return patched; // Return as string (JSON.stringify format)
  }

  // ─── 7. URL TARGETING ───────────────────────────────────────────────────────
  function isAIToolRequest(url) {
    try {
      const u = new URL(typeof url === 'string' ? url : url.url);
      return CONFIG.targetDomains.some(d => u.hostname.includes(d));
    } catch {
      return false;
    }
  }

  function getAITool(url) {
    try {
      const u = new URL(typeof url === 'string' ? url : url.url);
      if (u.hostname.includes('openai') || u.hostname.includes('chatgpt')) return 'chatgpt';
      if (u.hostname.includes('claude')) return 'claude';
      if (u.hostname.includes('gemini')) return 'gemini';
      if (u.hostname.includes('copilot')) return 'copilot';
      return 'unknown';
    } catch {
      return 'unknown';
    }
  }

  // ─── 8. FETCH OVERRIDE ──────────────────────────────────────────────────────
  /**
   * This is the heart of PromptShield.
   * We replace window.fetch with our own version that:
   * 1. Checks if the request is going to an AI tool
   * 2. Reads the body and tokenizes sensitive data
   * 3. Sends the MODIFIED body instead
   * 4. Notifies content_script about the incident
   */
  const originalFetch = window.fetch;

  window.fetch = async function (resource, init = {}) {
    const url = typeof resource === 'string' ? resource : resource?.url ?? '';

    // Only intercept POST requests to AI tools with a body
    if (init?.method?.toUpperCase() === 'POST' && isAIToolRequest(url) && init?.body) {
      try {
        const bodyStr = typeof init.body === 'string' ? init.body : null;
        if (bodyStr) {
          const bodyJson = JSON.parse(bodyStr);
          const text = extractPromptText(bodyJson);

          if (text.trim().length > 0) {
            const { sanitized, findings, riskScore, modified } = tokenize(text);

            if (modified) {
              // Build token→original map just for this request's findings
              const requestMapping = {};
              findings.forEach(f => { requestMapping[f.token] = TOKEN_MAP[f.token]; });

              // Patch the body with tokens
              const patchedBodyStr = patchBodyWithTokens(bodyJson, requestMapping);

              // Replace init.body with tokenized version
              init = { ...init, body: patchedBodyStr };

              // Notify content_script (only metadata, never raw text)
              window.postMessage({
                source: 'promptshield-injected',
                type: 'INCIDENT',
                payload: {
                  categories: [...new Set(findings.map(f => f.name))],
                  riskScore,
                  aiTool: getAITool(url),
                  actionTaken: 'tokenized',
                  isFile: false,
                }
              }, '*');
            }
          }
        }
      } catch (err) {
        // Never crash the page — silently fail
        console.debug('[PromptShield] Intercept error:', err.message);
      }
    }

    return originalFetch.call(this, resource, init);
  };

  // ─── 9. XHR OVERRIDE ────────────────────────────────────────────────────────
  /**
   * Some AI tools use XMLHttpRequest instead of fetch.
   * We patch it the same way.
   */
  const OriginalXHR = window.XMLHttpRequest;

  function PatchedXHR() {
    const xhr = new OriginalXHR();
    const originalOpen = xhr.open.bind(xhr);
    const originalSend = xhr.send.bind(xhr);

    let requestUrl = '';
    let requestMethod = '';

    xhr.open = function (method, url, ...args) {
      requestUrl = url;
      requestMethod = method;
      return originalOpen(method, url, ...args);
    };

    xhr.send = function (body) {
      if (requestMethod.toUpperCase() === 'POST' && isAIToolRequest(requestUrl) && body) {
        try {
          const bodyStr = typeof body === 'string' ? body : null;
          if (bodyStr) {
            const bodyJson = JSON.parse(bodyStr);
            const text = extractPromptText(bodyJson);
            if (text.trim().length > 0) {
              const { findings, riskScore, modified } = tokenize(text);
              if (modified) {
                const requestMapping = {};
                findings.forEach(f => { requestMapping[f.token] = TOKEN_MAP[f.token]; });
                const patchedBody = patchBodyWithTokens(bodyJson, requestMapping);
                body = patchedBody;

                window.postMessage({
                  source: 'promptshield-injected',
                  type: 'INCIDENT',
                  payload: {
                    categories: [...new Set(findings.map(f => f.name))],
                    riskScore,
                    aiTool: getAITool(requestUrl),
                    actionTaken: 'tokenized',
                    isFile: false,
                  }
                }, '*');
              }
            }
          }
        } catch (err) {
          console.debug('[PromptShield] XHR intercept error:', err.message);
        }
      }
      return originalSend(body);
    };

    return xhr;
  }

  // Copy over static properties and prototype
  PatchedXHR.prototype = OriginalXHR.prototype;
  Object.defineProperty(window, 'XMLHttpRequest', {
    value: PatchedXHR,
    writable: true,
    configurable: true
  });

  // ─── 10. MUTATION OBSERVER — TOKEN RESTORATION ──────────────────────────────
  /**
   * ChatGPT streams responses token-by-token into the DOM.
   * The response will contain our tokens like [EMAIL_AB12].
   * We watch the DOM for new text nodes and replace tokens with originals.
   * This happens ONLY in the user's view — original secrets were never sent.
   */
  const observer = new MutationObserver((mutations) => {
    if (Object.keys(TOKEN_MAP).length === 0) return; // Nothing to restore

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.TEXT_NODE) {
          const restored = detokenize(node.textContent);
          if (restored !== node.textContent) {
            node.textContent = restored;
          }
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          // Walk through all text nodes in the added element
          const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, null);
          let textNode;
          while ((textNode = walker.nextNode())) {
            const restored = detokenize(textNode.textContent);
            if (restored !== textNode.textContent) {
              textNode.textContent = restored;
            }
          }
        }
      }
    }
  });

  // Start observing once DOM is ready
  function startObserver() {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }

  if (document.body) {
    startObserver();
  } else {
    document.addEventListener('DOMContentLoaded', startObserver);
  }

  console.log('[PromptShield] Injected and active ✓');
})();
