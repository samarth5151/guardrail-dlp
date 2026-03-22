/**
 * Barclays DLP Guardian — Content Script v3
 *
 * KEY DESIGN:
 *  – Safe prompt  → event is NEVER stopped. Zero UI, zero delay. No flicker.
 *  – Unsafe prompt → event stopped quietly, server called, popup shown on BLOCK/WARN.
 *  – No loading/scanning overlay, ever.
 *  – CSP-safe: no inline onclick attributes.
 */

const DLP_API = 'http://localhost:8001/gateway/analyze';
const GUARD_FLAG = '__dlp_safe_pass__';  // marks re-fired events to skip

// ── Site configs ──────────────────────────────────────────────────────────────
const SITE_CONFIG = {
  'chatgpt.com': {
    inputSelectors: ['#prompt-textarea', 'div[contenteditable="true"][data-id]', 'textarea'],
    submitSelectors: ['button[data-testid="send-button"]', 'button[aria-label="Send prompt"]', 'button[aria-label="Send message"]'],
    destination: 'ChatGPT',
  },
  'chat.openai.com': {
    inputSelectors: ['#prompt-textarea', 'textarea'],
    submitSelectors: ['button[data-testid="send-button"]', 'button[aria-label="Send prompt"]'],
    destination: 'ChatGPT',
  },
  'gemini.google.com': {
    inputSelectors: ['div.ql-editor[contenteditable="true"]', 'rich-textarea div[contenteditable]', 'div[contenteditable="true"]'],
    submitSelectors: ['button[aria-label="Send message"]', 'button.send-button', 'button[mattooltip="Send message"]'],
    destination: 'Gemini',
  },
  'chat.deepseek.com': {
    inputSelectors: ['textarea#chat-input', 'textarea[placeholder]', 'div[contenteditable="true"]'],
    submitSelectors: ['button[aria-label="Send"]', 'div[role="button"].send-button', 'button.send-btn'],
    destination: 'DeepSeek',
  },
  'claude.ai': {
    inputSelectors: ['div[contenteditable="true"].ProseMirror', 'div.ProseMirror', 'div[contenteditable="true"]'],
    submitSelectors: ['button[aria-label="Send Message"]', 'button[aria-label="Send message"]', 'button[type="submit"]'],
    destination: 'Claude',
  },
};

// ── Fast local pre-check (pure regex, synchronous, <1ms) ─────────────────────
// ONLY returns true if it finds something that looks genuinely suspicious.
// Intentionally conservative to avoid false positives.
const FAST_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/,                                                          // AWS key
  /\bASIA[0-9A-Z]{16}\b/,                                                          // AWS session
  /\bsk-[A-Za-z0-9]{32,}\b/,                                                       // OpenAI key
  /\bsk-ant-[A-Za-z0-9\-]{32,}\b/,                                                 // Anthropic key
  /\bghp_[A-Za-z0-9]{36}\b/,                                                       // GitHub PAT
  /\bglpat-[A-Za-z0-9\-_]{20,}\b/,                                                 // GitLab token
  /\bAIza[0-9A-Za-z\-_]{35}\b/,                                                    // GCP key
  /\bxoxb-[0-9A-Za-z\-]{50,}\b/,                                                   // Slack token
  /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/,                               // SendGrid
  /\bsk_live_[A-Za-z0-9]{24,}\b/,                                                  // Stripe
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,                        // PEM key
  /eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}/,            // JWT
  /(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[=:]\s*\S{6,}/i,          // credential assignment
  /\b\d{3}-\d{2}-\d{4}\b/,                                                         // SSN
  /\b[A-Z]{2}[0-9]{6}[A-Z]\b/,                                                     // UK NI number
  /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}\b/,                                           // IBAN
  /(?:cvv|cvc|pin)\s*[=:]\s*\d{3,6}/i,                                             // CVV/PIN
  /account\s*(?:number|no|#)?\s*[=:]?\s*\d{8,12}/i,                               // bank account
  /\b(?:STRICTLY\s+CONFIDENTIAL|BARCLAYS\s+INTERNAL|BARCLAYS\s+CONFIDENTIAL)\b/i,  // markers
  // Password heuristic: 8-20 char token with upper+lower+digit+special
  // Uses a very specific pattern to avoid matching normal English words
  /(?<![A-Za-z])(?=[A-Za-z0-9!@#$%^&*\-_+=]{8,20}(?![A-Za-z0-9!@#$%^&*\-_+=]))(?=[^!@#$%^&*\-_+=]*[!@#$%^&*\-_+=])(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])(?=[^0-9]*[0-9])[A-Za-z0-9!@#$%^&*\-_+=]{8,20}/,
];

function localPreCheck(text) {
  return FAST_PATTERNS.some(pat => pat.test(text));
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function getHostConfig() {
  const host = window.location.hostname.replace('www.', '');
  return SITE_CONFIG[host] || null;
}

function getPromptText(config) {
  for (const sel of config.inputSelectors) {
    const el = document.querySelector(sel);
    if (!el) continue;
    const txt = (el.innerText || el.textContent || el.value || '').trim();
    if (txt) return txt;
  }
  return '';
}

// ── Server scan with 4s timeout, fail-open ────────────────────────────────────
async function scanWithServer(text, destination) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 4000);
  try {
    const res = await fetch(DLP_API, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: 'browser-user',
        department: 'general',
        role: 'employee',
        prompt: text,
        destination_model: destination.toLowerCase(),
      }),
    });
    clearTimeout(t);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch {
    clearTimeout(t);
    return { decision: 'PASS', risk_score: 0, risk_tier: 'low', block_reason: '', detected_types: [] };
  }
}

// ── Overlay helpers (CSP-safe, no inline onclick) ─────────────────────────────
function removeOverlay() {
  const el = document.getElementById('dlp-guardian-overlay');
  if (el) el.remove();
}

function makeOverlay(html) {
  removeOverlay();
  const wrap = document.createElement('div');
  wrap.id = 'dlp-guardian-overlay';
  wrap.innerHTML = html;
  document.body.appendChild(wrap);
  return wrap;
}

function showBlockOverlay(result, destination) {
  const types = (result.detected_types || []);
  const tagsHtml = types.length
    ? `<div class="dlp-types"><div class="dlp-types-label">Detected categories</div>
       <div class="dlp-tags">${types.map(t => `<span class="dlp-tag">${t}</span>`).join('')}</div></div>`
    : '';

  const wrap = makeOverlay(`
    <div class="dlp-modal dlp-modal-block">
      <div class="dlp-stripe"></div>
      <div class="dlp-header">
        <div class="dlp-header-left">
          <div class="dlp-shield">🛡️</div>
          <div>
            <div class="dlp-title">Prompt Blocked</div>
            <div class="dlp-subtitle">Barclays DLP Guardian</div>
          </div>
        </div>
        <button class="dlp-x" id="dlp-close-btn" aria-label="Close">✕</button>
      </div>
      <div class="dlp-body">
        <div class="dlp-hero dlp-hero-block">
          <div class="dlp-hero-icon">⛔</div>
          <div class="dlp-hero-text">Your message was blocked and <strong>never sent</strong> to ${destination}.</div>
        </div>
        <div class="dlp-reason-box">
          <div class="dlp-reason-label">Reason</div>
          <div class="dlp-reason-text">${result.block_reason || 'Sensitive data detected in your message.'}</div>
        </div>
        <div class="dlp-stats">
          <div class="dlp-stat-pill dlp-pill-block">⛔ BLOCKED</div>
          <div class="dlp-stat-pill dlp-pill-score">Risk: <b>${result.risk_score}/100</b></div>
          <div class="dlp-stat-pill dlp-pill-tier">${(result.risk_tier || 'high').toUpperCase()}</div>
        </div>
        ${tagsHtml}
        <div class="dlp-footer">
          This event has been recorded in the <strong>Barclays DLP Audit System</strong>.
          Contact your security team if this is a false positive.
        </div>
      </div>
    </div>
  `);

  wrap.querySelector('#dlp-close-btn').addEventListener('click', removeOverlay);
  wrap.addEventListener('click', (e) => { if (e.target === wrap) removeOverlay(); });
}

function showWarnOverlay(result, onProceed, onCancel) {
  const types = (result.detected_types || []);
  const tagsHtml = types.length
    ? `<div class="dlp-types"><div class="dlp-types-label">Detected categories</div>
       <div class="dlp-tags">${types.map(t => `<span class="dlp-tag">${t}</span>`).join('')}</div></div>`
    : '';

  const wrap = makeOverlay(`
    <div class="dlp-modal dlp-modal-warn">
      <div class="dlp-stripe dlp-stripe-warn"></div>
      <div class="dlp-header">
        <div class="dlp-header-left">
          <div class="dlp-shield">⚠️</div>
          <div>
            <div class="dlp-title">Caution: Sensitive Content</div>
            <div class="dlp-subtitle">Barclays DLP Guardian</div>
          </div>
        </div>
        <button class="dlp-x" id="dlp-close-btn" aria-label="Close">✕</button>
      </div>
      <div class="dlp-body">
        <div class="dlp-hero dlp-hero-warn">
          <div class="dlp-hero-icon">⚠️</div>
          <div class="dlp-hero-text">Potentially sensitive content detected. Please review before sending.</div>
        </div>
        <div class="dlp-reason-box">
          <div class="dlp-reason-label">Details</div>
          <div class="dlp-reason-text">${result.block_reason || 'Your message may contain sensitive information.'}</div>
        </div>
        <div class="dlp-stats">
          <div class="dlp-stat-pill dlp-pill-warn">⚠️ WARNING</div>
          <div class="dlp-stat-pill dlp-pill-score">Risk: <b>${result.risk_score}/100</b></div>
        </div>
        ${tagsHtml}
        <div class="dlp-actions">
          <button class="dlp-btn-cancel" id="dlp-cancel-btn">Cancel (Recommended)</button>
          <button class="dlp-btn-proceed" id="dlp-proceed-btn">Send Anyway</button>
        </div>
        <div class="dlp-footer">This event has been recorded in the <strong>Barclays DLP Audit System</strong>.</div>
      </div>
    </div>
  `);

  wrap.querySelector('#dlp-close-btn').addEventListener('click', () => { removeOverlay(); onCancel(); });
  wrap.querySelector('#dlp-cancel-btn').addEventListener('click', () => { removeOverlay(); onCancel(); });
  wrap.querySelector('#dlp-proceed-btn').addEventListener('click', () => { removeOverlay(); onProceed(); });
  wrap.addEventListener('click', (e) => { if (e.target === wrap) { removeOverlay(); onCancel(); } });
}

// ── Core decision flow ────────────────────────────────────────────────────────
let scanning = false;

async function runDlpCheck(text, config, submitFn) {
  // Step 1: synchronous fast check — if clean, return true (allow submit)
  if (!localPreCheck(text)) {
    return true; // safe, allow event to proceed naturally
  }

  // Step 2: suspicious — prevent submit, call server silently
  scanning = true;
  const result = await scanWithServer(text, config.destination);
  scanning = false;

  if (result.decision === 'BLOCK') {
    showBlockOverlay(result, config.destination);
    return false;
  }

  if (result.decision === 'WARN') {
    showWarnOverlay(result, submitFn, () => {});
    return false;
  }

  // PASS from server
  return true;
}

// ── Keyboard interceptor ──────────────────────────────────────────────────────
function attachKeyInterceptor(config) {
  document.addEventListener('keydown', async (e) => {
    // Skip if already scanning, shift+enter (newline), or marked as safe
    if (e[GUARD_FLAG] || e.shiftKey || e.key !== 'Enter' || scanning) return;

    const active = document.activeElement;
    const inInput = config.inputSelectors.some(sel => {
      const el = document.querySelector(sel);
      return el && (el === active || el.contains(active));
    });
    if (!inInput) return;

    const text = getPromptText(config);
    if (!text) return;

    // Fast check is synchronous — most safe prompts exit here instantly
    if (!localPreCheck(text)) return; // allow event to continue naturally

    // Suspicious — prevent and do server scan
    e.preventDefault();
    e.stopImmediatePropagation();

    const pass = await runDlpCheck(text, config, () => {
      // Fire a marked Enter that we won't intercept again
      const safeEvt = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true, cancelable: true });
      safeEvt[GUARD_FLAG] = true;
      active.dispatchEvent(safeEvt);
    });

    if (pass) {
      const safeEvt = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true, cancelable: true });
      safeEvt[GUARD_FLAG] = true;
      active.dispatchEvent(safeEvt);
    }
  }, true);
}

// ── Button interceptor ────────────────────────────────────────────────────────
function bindSubmitButton(btn, config) {
  if (btn.dataset.dlpBound === 'true') return;
  btn.dataset.dlpBound = 'true';

  btn.addEventListener('click', async (e) => {
    if (e[GUARD_FLAG] || scanning) return;

    const text = getPromptText(config);
    if (!text) return;

    // Fast synchronous check — exit cleanly with no interference for safe prompts
    if (!localPreCheck(text)) return;

    // Suspicious — prevent and scan
    e.preventDefault();
    e.stopImmediatePropagation();

    const pass = await runDlpCheck(text, config, () => {
      const safeClick = new MouseEvent('click', { bubbles: true, cancelable: true });
      safeClick[GUARD_FLAG] = true;
      btn.dispatchEvent(safeClick);
    });

    if (pass) {
      const safeClick = new MouseEvent('click', { bubbles: true, cancelable: true });
      safeClick[GUARD_FLAG] = true;
      btn.dispatchEvent(safeClick);
    }
  }, true);
}

function attachButtonInterceptor(config) {
  function tryBind() {
    config.submitSelectors.forEach(sel => {
      const btn = document.querySelector(sel);
      if (btn) bindSubmitButton(btn, config);
    });
  }
  tryBind();
  new MutationObserver(tryBind).observe(document.body, { childList: true, subtree: true });
}

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  const config = getHostConfig();
  if (!config) return;
  console.log('[DLP Guardian v3] Active on', window.location.hostname, '→', config.destination);
  attachKeyInterceptor(config);
  attachButtonInterceptor(config);
})();
