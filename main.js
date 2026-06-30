// ============================================================
// LLM Judge: Prompt A/B Test Evaluator (Full Edition)
// Supports: Google Gemini + Anthropic Claude
// Features: History, Export, Model Select, Temperature,
//           Multi-Run Consistency, Import/Export Test Suites
// ============================================================

const PROVIDERS = {
    gemini: {
        name: 'Gemini',
        models: ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-pro'],
        defaultModel: 'gemini-2.0-flash',
        keyName: 'gemini_api_key',
        getKeyUrl: 'https://aistudio.google.com/apikey',
        getKeyText: 'Get a free Gemini API key →'
    },
    claude: {
        name: 'Claude',
        models: ['claude-haiku-4-5-20251001', 'claude-sonnet-4-20250514', 'claude-opus-4-20250514'],
        defaultModel: 'claude-haiku-4-5-20251001',
        keyName: 'claude_api_key',
        getKeyUrl: 'https://console.anthropic.com/settings/keys',
        getKeyText: 'Get a Claude API key →'
    }
};

const HISTORY_KEY = 'llm_judge_history';
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 2000;
const SALT_KEY = 'llm_judge_salt';

// ============================================================
// Crypto — AES-GCM + PBKDF2 via Web Crypto API
// ============================================================
function b64Encode(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function b64Decode(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function getOrCreateSalt() {
    const stored = localStorage.getItem(SALT_KEY);
    if (stored) return b64Decode(stored);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    localStorage.setItem(SALT_KEY, b64Encode(salt));
    return salt;
}

async function deriveKey(passphrase, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(passphrase),
        { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
}

async function encryptValue(plaintext, passphrase) {
    const salt = await getOrCreateSalt();
    const key = await deriveKey(passphrase, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)
    );
    return JSON.stringify({ iv: b64Encode(iv), data: b64Encode(ciphertext) });
}

async function decryptValue(stored, passphrase) {
    const { iv, data } = JSON.parse(stored);
    const salt = await getOrCreateSalt();
    const key = await deriveKey(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64Decode(iv) }, key, b64Decode(data)
    );
    return new TextDecoder().decode(decrypted);
}

function isEncrypted(value) {
    if (!value) return false;
    try { const p = JSON.parse(value); return !!(p && p.iv && p.data); } catch { return false; }
}

function anyEncryptedKey() {
    return Object.values(PROVIDERS).some(p => isEncrypted(localStorage.getItem(p.keyName)));
}

// ============================================================
// State
// ============================================================
let activeProvider = localStorage.getItem('llm_judge_provider') || 'gemini';
let activeModel = localStorage.getItem('llm_judge_model') || PROVIDERS[activeProvider].defaultModel;
let apiKeys = { gemini: '', claude: '' }; // plaintext in memory only — never persisted
let sessionPassphrase = '';
let judgeProvider = localStorage.getItem('llm_judge_judge_provider') || activeProvider;
let judgeModel = localStorage.getItem('llm_judge_judge_model') || PROVIDERS[judgeProvider].defaultModel;
let lastResults = null;

// ============================================================
// DOM Ready
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    // Load legacy plain-text keys into memory (backward compat)
    Object.entries(PROVIDERS).forEach(([name, p]) => {
        const stored = localStorage.getItem(p.keyName);
        if (stored && !isEncrypted(stored)) apiKeys[name] = stored;
    });

    if (anyEncryptedKey()) {
        showModal('unlock');
    } else if (!apiKeys[activeProvider]) {
        showModal('setup');
    } else {
        document.getElementById('api-key-modal').classList.add('hidden');
        updateApiStatus(true);
        setTimeout(() => showToast('Tip: Click 🔑 to encrypt your stored API key with a passphrase.', 'info'), 1500);
    }

    // Modal
    document.querySelectorAll('#modal-provider-tabs .provider-tab').forEach(tab => {
        tab.addEventListener('click', () => setModalProvider(tab.dataset.provider));
    });
    document.getElementById('save-key-btn').addEventListener('click', saveApiKey);
    document.getElementById('change-key-btn').addEventListener('click', () => showModal(sessionPassphrase ? 'add' : 'setup'));
    document.getElementById('modal-enter-key-btn').addEventListener('click', () => showModal('setup'));
    document.getElementById('api-key-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') saveApiKey(); });
    document.getElementById('passphrase-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') saveApiKey(); });
    document.getElementById('passphrase-confirm-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') saveApiKey(); });

    // Provider switch
    document.querySelectorAll('#top-provider-switch .provider-chip').forEach(chip => {
        chip.addEventListener('click', () => switchProvider(chip.dataset.provider));
    });

    // Model select
    document.getElementById('model-select').addEventListener('change', (e) => {
        activeModel = e.target.value;
        localStorage.setItem('llm_judge_model', activeModel);
    });

    // Criteria
    document.getElementById('add-criterion-btn').addEventListener('click', () => addCriterion());
    document.getElementById('criteria-container').addEventListener('click', (e) => {
        if (e.target.closest('.btn-remove') && document.querySelectorAll('#criteria-container .criterion-row').length > 1) {
            e.target.closest('.criterion-row').remove();
        }
    });

    // Test cases
    document.getElementById('add-test-btn').addEventListener('click', addTestCase);
    document.getElementById('test-cases-container').addEventListener('click', (e) => {
        if (e.target.closest('.btn-remove')) { e.target.closest('.test-case-row').remove(); renumberTestCases(); }
    });

    // Import/Export test suites
    document.getElementById('import-tests-btn').addEventListener('click', () => document.getElementById('import-file-input').click());
    document.getElementById('import-file-input').addEventListener('change', importTestSuite);
    document.getElementById('export-tests-btn').addEventListener('click', exportTestSuite);

    // Settings toggle
    document.getElementById('toggle-settings').addEventListener('click', toggleSettings);
    document.getElementById('temperature-slider').addEventListener('input', (e) => {
        document.getElementById('temp-value').textContent = e.target.value;
    });
    document.getElementById('runs-per-test').addEventListener('input', (e) => {
        document.getElementById('runs-value').textContent = e.target.value;
    });

    // Judge model
    document.querySelectorAll('#judge-provider-switch .provider-chip').forEach(chip => {
        chip.addEventListener('click', () => switchJudgeProvider(chip.dataset.provider));
    });
    document.getElementById('judge-model-select').addEventListener('change', (e) => {
        judgeModel = e.target.value;
        localStorage.setItem('llm_judge_judge_model', judgeModel);
        localStorage.setItem(`llm_judge_judge_model_${judgeProvider}`, judgeModel);
    });
    syncJudgeProviderUI();
    populateJudgeModelSelect();

    // History
    document.getElementById('history-btn').addEventListener('click', openHistory);
    document.getElementById('close-history-btn').addEventListener('click', closeHistory);
    document.getElementById('history-overlay').addEventListener('click', closeHistory);
    document.getElementById('clear-history-btn').addEventListener('click', clearHistory);

    // Run & Export
    document.getElementById('run-btn').addEventListener('click', runEvaluation);
    document.getElementById('export-report-btn').addEventListener('click', exportReport);
    document.getElementById('share-results-btn').addEventListener('click', generateShareUrl);
    document.getElementById('reset-results-btn').addEventListener('click', resetResults);
    document.getElementById('share-banner-close').addEventListener('click', () => {
        document.getElementById('share-banner').style.display = 'none';
        history.replaceState(null, '', location.pathname);
    });

    // Theme
    document.getElementById('theme-btn').addEventListener('click', toggleTheme);
    applyTheme(localStorage.getItem('llm_judge_theme') || 'dark');

    // Init
    syncProviderUI();
    populateModelSelect();
    loadFromShareUrl();
});

// ============================================================
// Toast Notifications
// ============================================================
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ============================================================
// Theme
// ============================================================
function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    document.getElementById('theme-btn').textContent = theme === 'light' ? '🌙' : '☀️';
    localStorage.setItem('llm_judge_theme', theme);
}

function toggleTheme() {
    applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
}


// ============================================================
// Provider & Model Management
// ============================================================
function showModal(mode = 'setup') {
    const modal = document.querySelector('#api-key-modal .modal');
    modal.dataset.mode = mode;
    document.getElementById('api-key-modal').classList.remove('hidden');
    document.getElementById('modal-error').textContent = '';
    document.getElementById('passphrase-input').value = '';

    if (mode === 'unlock') {
        document.getElementById('modal-title').textContent = 'Unlock Your Keys';
        document.getElementById('modal-desc').textContent = 'Enter your passphrase to decrypt your stored API keys.';
        document.getElementById('save-key-btn').textContent = 'Unlock';
        document.getElementById('passphrase-input').placeholder = 'Enter your passphrase...';
    } else if (mode === 'add') {
        document.getElementById('modal-title').textContent = 'Add API Key';
        document.getElementById('modal-desc').textContent = 'Enter your API key for this provider. It will be encrypted with your existing passphrase.';
        document.getElementById('save-key-btn').textContent = 'Save & Continue';
        document.getElementById('api-key-input').value = '';
        setModalProvider(activeProvider);
    } else {
        document.getElementById('modal-title').textContent = 'Connect Your LLM';
        document.getElementById('modal-desc').textContent = 'Select your AI provider and enter your API key. It will be encrypted with a passphrase before storage.';
        document.getElementById('save-key-btn').textContent = 'Save & Continue';
        document.getElementById('api-key-input').value = '';
        document.getElementById('passphrase-input').placeholder = 'Set a passphrase to encrypt your key...';
        document.getElementById('passphrase-confirm-input').value = '';
        setModalProvider(activeProvider);
    }
}

function showModalError(msg) {
    document.getElementById('modal-error').textContent = msg;
}

function setModalProvider(provider) {
    document.querySelectorAll('#modal-provider-tabs .provider-tab').forEach(t => t.classList.toggle('active', t.dataset.provider === provider));
    document.getElementById('get-key-link').href = PROVIDERS[provider].getKeyUrl;
    document.getElementById('get-key-link').textContent = PROVIDERS[provider].getKeyText;
    document.getElementById('api-key-input').placeholder = `Enter your ${PROVIDERS[provider].name} API Key...`;
    document.getElementById('api-key-modal').dataset.selectedProvider = provider;
}

function switchProvider(provider) {
    activeProvider = provider;
    localStorage.setItem('llm_judge_provider', provider);
    activeModel = localStorage.getItem(`llm_judge_model_${provider}`) || PROVIDERS[provider].defaultModel;
    localStorage.setItem('llm_judge_model', activeModel);
    syncProviderUI();
    populateModelSelect();
    if (apiKeys[provider]) {
        updateApiStatus(true);
    } else {
        const stored = localStorage.getItem(PROVIDERS[provider].keyName);
        if (isEncrypted(stored) && sessionPassphrase) {
            // Silently decrypt the newly selected provider's key using the session passphrase
            decryptValue(stored, sessionPassphrase)
                .then(key => { apiKeys[provider] = key; updateApiStatus(true); })
                .catch(() => showModal('unlock'));
        } else if (sessionPassphrase) {
            showModal('add');
        } else {
            showModal('setup');
        }
    }
}

function syncProviderUI() {
    document.querySelectorAll('#top-provider-switch .provider-chip').forEach(chip => chip.classList.toggle('active', chip.dataset.provider === activeProvider));
}

function populateModelSelect() {
    const select = document.getElementById('model-select');
    select.innerHTML = '';
    PROVIDERS[activeProvider].models.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        if (m === activeModel) opt.selected = true;
        select.appendChild(opt);
    });
}

function syncJudgeProviderUI() {
    document.querySelectorAll('#judge-provider-switch .provider-chip').forEach(chip => chip.classList.toggle('active', chip.dataset.provider === judgeProvider));
}

function populateJudgeModelSelect() {
    const select = document.getElementById('judge-model-select');
    select.innerHTML = '';
    PROVIDERS[judgeProvider].models.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        if (m === judgeModel) opt.selected = true;
        select.appendChild(opt);
    });
}

function switchJudgeProvider(provider) {
    judgeProvider = provider;
    localStorage.setItem('llm_judge_judge_provider', provider);
    judgeModel = localStorage.getItem(`llm_judge_judge_model_${provider}`) || PROVIDERS[provider].defaultModel;
    localStorage.setItem('llm_judge_judge_model', judgeModel);
    syncJudgeProviderUI();
    populateJudgeModelSelect();
}

async function saveApiKey() {
    const modal = document.querySelector('#api-key-modal .modal');
    if (modal.dataset.mode === 'unlock') { await attemptUnlock(); return; }

    const provider = document.getElementById('api-key-modal').dataset.selectedProvider || activeProvider;
    const key = document.getElementById('api-key-input').value.trim();
    if (!key) { showModalError('Please enter your API key.'); return; }

    let passphrase;
    if (modal.dataset.mode === 'add' && sessionPassphrase) {
        passphrase = sessionPassphrase;
    } else {
        passphrase = document.getElementById('passphrase-input').value;
        const confirm = document.getElementById('passphrase-confirm-input').value;
        if (!passphrase) { showModalError('Please set a passphrase to encrypt your key.'); return; }
        if (passphrase.length < 6) { showModalError('Passphrase must be at least 6 characters.'); return; }
        if (passphrase !== confirm) { showModalError('Passphrases do not match.'); return; }
    }

    const btn = document.getElementById('save-key-btn');
    btn.disabled = true;
    btn.textContent = 'Encrypting...';
    try {
        const encrypted = await encryptValue(key, passphrase);
        localStorage.setItem(PROVIDERS[provider].keyName, encrypted);
        apiKeys[provider] = key;
        sessionPassphrase = passphrase;
        activeProvider = provider;
        localStorage.setItem('llm_judge_provider', provider);
        activeModel = PROVIDERS[provider].defaultModel;
        localStorage.setItem('llm_judge_model', activeModel);
        document.getElementById('api-key-modal').classList.add('hidden');
        syncProviderUI();
        populateModelSelect();
        updateApiStatus(true);
        showToast(`${PROVIDERS[provider].name} API key encrypted and saved!`, 'success');
    } catch (err) {
        showModalError('Encryption failed. Please try again.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Save & Continue';
    }
}

async function attemptUnlock() {
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase) { showModalError('Please enter your passphrase.'); return; }

    const btn = document.getElementById('save-key-btn');
    btn.disabled = true;
    btn.textContent = 'Unlocking...';
    try {
        for (const [name, p] of Object.entries(PROVIDERS)) {
            const stored = localStorage.getItem(p.keyName);
            if (isEncrypted(stored)) apiKeys[name] = await decryptValue(stored, passphrase);
        }
        sessionPassphrase = passphrase;
        document.getElementById('api-key-modal').classList.add('hidden');
        updateApiStatus(true);
        showToast('Keys unlocked!', 'success');
    } catch {
        showModalError('Incorrect passphrase. Please try again.');
        apiKeys = { gemini: '', claude: '' };
        sessionPassphrase = '';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Unlock';
    }
}

function updateApiStatus(connected) {
    const el = document.getElementById('api-status');
    el.textContent = connected ? `● ${PROVIDERS[activeProvider].name}` : '● Disconnected';
    el.style.color = connected ? '#10b981' : '#ef4444';
}

// ============================================================
// Settings
// ============================================================
function toggleSettings() {
    document.getElementById('settings-body').classList.toggle('open');
    document.getElementById('settings-chevron').classList.toggle('open');
}

// ============================================================
// Test Case Management
// ============================================================
function addTestCase() {
    const container = document.getElementById('test-cases-container');
    const count = container.children.length;
    const row = document.createElement('div');
    row.className = 'test-case-row';
    row.innerHTML = `<span class="test-case-num">${count + 1}</span><input type="text" class="test-case-input" placeholder="Enter a test input..." /><button class="btn-remove" title="Remove">✕</button>`;
    container.appendChild(row);
}

function renumberTestCases() {
    document.querySelectorAll('.test-case-row').forEach((row, i) => { row.querySelector('.test-case-num').textContent = i + 1; });
}

function getTestCases() {
    return Array.from(document.querySelectorAll('.test-case-input')).map(el => el.value.trim()).filter(v => v.length > 0);
}

// ============================================================
// Criteria Management
// ============================================================
function getCriteria() {
    return Array.from(document.querySelectorAll('#criteria-container .criterion-row')).map(row => ({
        name: row.querySelector('.criterion-name').value.trim(),
        description: row.querySelector('.criterion-desc').value.trim()
    })).filter(c => c.name);
}

function addCriterion(name = '', desc = '') {
    const container = document.getElementById('criteria-container');
    const row = document.createElement('div');
    row.className = 'criterion-row';
    row.innerHTML = `<input type="text" class="criterion-name" placeholder="e.g. Tone" /><input type="text" class="criterion-desc" placeholder="e.g. Professional and friendly throughout" /><button class="btn-remove" title="Remove">✕</button>`;
    row.querySelector('.criterion-name').value = name;
    row.querySelector('.criterion-desc').value = desc;
    container.appendChild(row);
}

function renderCriteriaFromData(arr) {
    const container = document.getElementById('criteria-container');
    container.innerHTML = '';
    (Array.isArray(arr) ? arr : [{ name: 'Overall', description: arr }]).forEach(c => addCriterion(c.name || '', c.description || ''));
    if (container.children.length === 0) addCriterion();
}

// ============================================================
// Import / Export Test Suites
// ============================================================
function exportTestSuite() {
    const suite = {
        criteria: getCriteria(),
        promptA: document.getElementById('prompt-a').value,
        promptB: document.getElementById('prompt-b').value,
        testCases: getTestCases()
    };
    const blob = new Blob([JSON.stringify(suite, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `llm-judge-suite-${Date.now()}.json`;
    a.click();
    showToast('Test suite exported!', 'success');
}

function importTestSuite(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const suite = JSON.parse(e.target.result);
            if (suite.criteria) renderCriteriaFromData(suite.criteria);
            if (suite.promptA) document.getElementById('prompt-a').value = suite.promptA;
            if (suite.promptB) document.getElementById('prompt-b').value = suite.promptB;
            if (suite.testCases && suite.testCases.length) {
                const container = document.getElementById('test-cases-container');
                container.innerHTML = '';
                suite.testCases.forEach((tc, i) => {
                    const row = document.createElement('div');
                    row.className = 'test-case-row';
                    row.innerHTML = `<span class="test-case-num">${i + 1}</span><input type="text" class="test-case-input" value="${escapeHtml(tc)}" /><button class="btn-remove" title="Remove">✕</button>`;
                    container.appendChild(row);
                });
            }
            showToast('Test suite imported!', 'success');
        } catch { showToast('Invalid JSON file.', 'error'); }
    };
    reader.readAsText(file);
    event.target.value = '';
}

// ============================================================
// History
// ============================================================
function openHistory() {
    document.getElementById('history-panel').classList.add('open');
    document.getElementById('history-overlay').classList.remove('hidden');
    renderHistory();
}

function closeHistory() {
    document.getElementById('history-panel').classList.remove('open');
    document.getElementById('history-overlay').classList.add('hidden');
}

function getHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
}

function saveToHistory(evalData) {
    const history = getHistory();
    history.unshift(evalData);
    if (history.length > 20) history.pop();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
}

function clearHistory() {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
    showToast('History cleared.', 'info');
}

function renderHistory() {
    const list = document.getElementById('history-list');
    const history = getHistory();
    const empty = document.getElementById('history-empty');

    list.innerHTML = '';
    if (history.length === 0) {
        list.appendChild(empty);
        empty.style.display = 'block';
        return;
    }

    history.forEach((item, idx) => {
        const div = document.createElement('div');
        div.className = 'history-item';
        const date = new Date(item.timestamp).toLocaleString();
        const winner = item.winner || 'N/A';
        div.innerHTML = `
            <div class="history-item-date">${date}</div>
            <div class="history-item-result">${winner}</div>
            <div class="history-item-meta">${item.provider} · ${item.model} · ${item.testCount} tests · Avg: ${item.avgA} vs ${item.avgB}${item.judgeModel ? ` · Judge: ${item.judgeModel}` : ''}</div>
        `;
        div.addEventListener('click', () => loadHistoryItem(item));
        list.appendChild(div);
    });
}

function loadHistoryItem(item) {
    if (item.criteria) renderCriteriaFromData(item.criteria);
    if (item.promptA) document.getElementById('prompt-a').value = item.promptA;
    if (item.promptB) document.getElementById('prompt-b').value = item.promptB;
    closeHistory();
    showToast('Loaded evaluation from history.', 'info');
}

// ============================================================
// API Calls with Retry
// ============================================================
async function fetchWithRetry(url, options, retries = MAX_RETRIES) {
    for (let attempt = 0; attempt <= retries; attempt++) {
        const res = await fetch(url, options);
        if (res.ok) return res;
        if (res.status === 429 && attempt < retries) {
            showToast(`Rate limited. Retrying in ${RETRY_DELAY_MS / 1000}s... (${attempt + 1}/${retries})`, 'info');
            await new Promise(r => setTimeout(r, RETRY_DELAY_MS * (attempt + 1)));
            continue;
        }
        const errText = await res.text();
        throw new Error(`API Error (${res.status}): ${errText}`);
    }
}

async function callLLM(systemPrompt, userMessage) {
    const temp = parseFloat(document.getElementById('temperature-slider').value);
    return activeProvider === 'gemini' ? callGemini(systemPrompt, userMessage, temp) : callClaude(systemPrompt, userMessage, temp);
}

async function callLLMJson(prompt) {
    return activeProvider === 'gemini' ? callGeminiJson(prompt) : callClaudeJson(prompt);
}

// Gemini
async function callGemini(systemPrompt, userMessage, temp) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${activeModel}:generateContent?key=${apiKeys.gemini}`;
    const body = { contents: [{ role: 'user', parts: [{ text: `${systemPrompt}\n\n---\n\nUser Input:\n${userMessage}` }] }], generationConfig: { temperature: temp, maxOutputTokens: 2048 } };
    const res = await fetchWithRetry(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || '[No response]';
}

async function callGeminiJson(prompt, model = activeModel) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKeys.gemini}`;
    const body = { contents: [{ role: 'user', parts: [{ text: prompt }] }], generationConfig: { temperature: 0.3, maxOutputTokens: 2048, responseMimeType: 'application/json' } };
    const res = await fetchWithRetry(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    return parseJsonSafely(data.candidates?.[0]?.content?.parts?.[0]?.text || '{}');
}

// Claude
async function callClaude(systemPrompt, userMessage, temp) {
    const url = 'https://api.anthropic.com/v1/messages';
    const body = { model: activeModel, max_tokens: 2048, temperature: temp, system: systemPrompt, messages: [{ role: 'user', content: userMessage }] };
    const headers = { 'Content-Type': 'application/json', 'x-api-key': apiKeys.claude, 'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' };
    const res = await fetchWithRetry(url, { method: 'POST', headers, body: JSON.stringify(body) });
    const data = await res.json();
    return data.content?.[0]?.text || '[No response]';
}

async function callClaudeJson(prompt, model = activeModel) {
    const url = 'https://api.anthropic.com/v1/messages';
    const body = { model, max_tokens: 2048, temperature: 0.3, messages: [{ role: 'user', content: prompt }, { role: 'assistant', content: '{' }] };
    const headers = { 'Content-Type': 'application/json', 'x-api-key': apiKeys.claude, 'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' };
    const res = await fetchWithRetry(url, { method: 'POST', headers, body: JSON.stringify(body) });
    const data = await res.json();
    return parseJsonSafely('{' + (data.content?.[0]?.text || '}'));
}

function parseJsonSafely(raw) {
    try { return JSON.parse(raw); } catch {
        const m = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
        if (m) return JSON.parse(m[1].trim());
        const s = raw.indexOf('{'), e = raw.lastIndexOf('}');
        if (s !== -1 && e !== -1) return JSON.parse(raw.substring(s, e + 1));
        throw new Error('Failed to parse JSON response');
    }
}

// ============================================================
// Judge
// ============================================================
async function callJudge(criteria, testInput, responseA, responseB) {
    const criteriaList = criteria.map((c, i) =>
        `${i + 1}. ${c.name}${c.description ? ' — ' + c.description : ''}`
    ).join('\n');

    const criteriaJsonSchema = criteria.map(c =>
        `    "${c.name}": { "scoreA": <0-10>, "scoreB": <0-10>, "reasoning": "<one sentence>" }`
    ).join(',\n');

    const judgePrompt = `You are an impartial, expert LLM Output Evaluator. Score two AI responses on each criterion independently.

CRITERIA (score each 0–10 separately):
${criteriaList}

TEST INPUT:
${testInput}

RESPONSE A:
${responseA}

RESPONSE B:
${responseB}

Evaluate strictly. Return ONLY valid JSON:
{
  "criteria": {
${criteriaJsonSchema}
  },
  "scoreA": <mean of all criteria scoreA values>,
  "scoreB": <mean of all criteria scoreB values>,
  "strengthsA": ["..."],
  "strengthsB": ["..."],
  "weaknessesA": ["..."],
  "weaknessesB": ["..."],
  "winner": "A" or "B" or "Tie",
  "reasoning": "One paragraph overall summary."
}`;

    return judgeProvider === 'gemini'
        ? callGeminiJson(judgePrompt, judgeModel)
        : callClaudeJson(judgePrompt, judgeModel);
}

// ============================================================
// Main Runner
// ============================================================
async function runEvaluation() {
    const criteria = getCriteria();
    const promptA = document.getElementById('prompt-a').value.trim();
    const promptB = document.getElementById('prompt-b').value.trim();
    const testCases = getTestCases();
    const runsPerTest = parseInt(document.getElementById('runs-per-test').value);

    if (!apiKeys[activeProvider]) { showModal(); return; }
    if (!apiKeys[judgeProvider]) {
        showToast(`Judge model requires a ${PROVIDERS[judgeProvider].name} API key. Click 🔑 to add it.`, 'error');
        return;
    }
    if (criteria.length === 0) { showToast('Please add at least one evaluation criterion.', 'error'); return; }
    if (!promptA) { showToast('Please enter Prompt A.', 'error'); return; }
    if (!promptB) { showToast('Please enter Prompt B.', 'error'); return; }
    if (testCases.length === 0) { showToast('Please enter at least one test case.', 'error'); return; }

    if (location.hash.startsWith('#share=')) history.replaceState(null, '', location.pathname);
    document.getElementById('share-banner').style.display = 'none';

    const runBtn = document.getElementById('run-btn');
    runBtn.disabled = true;
    runBtn.innerHTML = '<span class="run-icon">⏳</span> Running...';

    const progressSection = document.getElementById('progress-section');
    progressSection.style.display = 'block';
    document.getElementById('results-section').style.display = 'none';

    const totalSteps = testCases.length * runsPerTest * 3;
    let currentStep = 0;

    function updateProgress(detail) {
        currentStep++;
        document.getElementById('progress-bar').style.width = Math.round((currentStep / totalSteps) * 100) + '%';
        document.getElementById('progress-detail').textContent = detail;
    }

    const allResults = [];

    try {
        for (let i = 0; i < testCases.length; i++) {
            const testInput = testCases[i];
            const runResults = [];

            for (let run = 0; run < runsPerTest; run++) {
                const runLabel = runsPerTest > 1 ? ` (Run ${run + 1}/${runsPerTest})` : '';
                document.getElementById('progress-title').textContent = `Test ${i + 1}/${testCases.length}${runLabel} · Responder: ${PROVIDERS[activeProvider].name}`;

                updateProgress(`Prompt A → Test ${i + 1}${runLabel}`);
                const responseA = await callLLM(promptA, testInput);

                updateProgress(`Prompt B → Test ${i + 1}${runLabel}`);
                const responseB = await callLLM(promptB, testInput);

                updateProgress(`Judging with ${judgeModel}…`);
                const judgment = await callJudge(criteria, testInput, responseA, responseB);

                runResults.push({ responseA, responseB, judgment });
            }

            // Aggregate runs
            if (runsPerTest === 1) {
                allResults.push({ testInput, ...runResults[0] });
            } else {
                const avgScoreA = runResults.reduce((s, r) => s + (r.judgment.scoreA || 0), 0) / runsPerTest;
                const avgScoreB = runResults.reduce((s, r) => s + (r.judgment.scoreB || 0), 0) / runsPerTest;
                const scoresA = runResults.map(r => r.judgment.scoreA || 0);
                const scoresB = runResults.map(r => r.judgment.scoreB || 0);
                const consistencyA = 10 - stdDev(scoresA);
                const consistencyB = 10 - stdDev(scoresB);
                const winner = avgScoreA > avgScoreB ? 'A' : avgScoreB > avgScoreA ? 'B' : 'Tie';

                allResults.push({
                    testInput,
                    responseA: runResults[0].responseA,
                    responseB: runResults[0].responseB,
                    judgment: {
                        scoreA: Math.round(avgScoreA * 10) / 10,
                        scoreB: Math.round(avgScoreB * 10) / 10,
                        strengthsA: runResults[0].judgment.strengthsA,
                        strengthsB: runResults[0].judgment.strengthsB,
                        weaknessesA: runResults[0].judgment.weaknessesA,
                        weaknessesB: runResults[0].judgment.weaknessesB,
                        winner,
                        reasoning: runResults[0].judgment.reasoning,
                        consistencyA: Math.round(consistencyA * 10) / 10,
                        consistencyB: Math.round(consistencyB * 10) / 10,
                        runs: runsPerTest
                    }
                });
            }
        }

        progressSection.style.display = 'none';
        lastResults = allResults;
        renderResults(allResults);

        // Save to history
        const avgA = (allResults.reduce((s, r) => s + r.judgment.scoreA, 0) / allResults.length).toFixed(1);
        const avgB = (allResults.reduce((s, r) => s + r.judgment.scoreB, 0) / allResults.length).toFixed(1);
        const overallWinner = parseFloat(avgA) > parseFloat(avgB) ? '🏆 Prompt A Wins' : parseFloat(avgB) > parseFloat(avgA) ? '🏆 Prompt B Wins' : '🤝 Tie';
        saveToHistory({
            timestamp: Date.now(), provider: PROVIDERS[activeProvider].name, model: activeModel,
            judgeProvider: PROVIDERS[judgeProvider].name, judgeModel,
            testCount: testCases.length, avgA, avgB, winner: overallWinner,
            criteria, promptA, promptB
        });

        showToast('Evaluation complete!', 'success');
    } catch (err) {
        progressSection.style.display = 'none';
        showToast(err.message.substring(0, 150), 'error');
        console.error(err);
        if (err.message.includes('401') || err.message.includes('403')) { updateApiStatus(false); showModal(); }
    } finally {
        runBtn.disabled = false;
        runBtn.innerHTML = '<span class="run-icon">⚡</span> Run Evaluation';
    }
}

function stdDev(arr) {
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return Math.sqrt(arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length);
}

// ============================================================
// Render Results
// ============================================================
function renderResults(results) {
    const section = document.getElementById('results-section');
    section.style.display = 'block';

    let totalA = 0, totalB = 0, winsA = 0, winsB = 0, ties = 0;
    results.forEach(r => {
        totalA += r.judgment.scoreA || 0;
        totalB += r.judgment.scoreB || 0;
        if (r.judgment.winner === 'A') winsA++;
        else if (r.judgment.winner === 'B') winsB++;
        else ties++;
    });

    const avgA = (totalA / results.length).toFixed(1);
    const avgB = (totalB / results.length).toFixed(1);

    const avgScoreA = document.getElementById('avg-score-a');
    avgScoreA.textContent = avgA;
    avgScoreA.className = 'summary-value score-a';

    const avgScoreB = document.getElementById('avg-score-b');
    avgScoreB.textContent = avgB;
    avgScoreB.className = 'summary-value score-b';

    const verdict = document.getElementById('summary-verdict');
    if (parseFloat(avgA) > parseFloat(avgB)) { verdict.textContent = '🏆 Prompt A Wins'; verdict.className = 'summary-verdict verdict-a'; }
    else if (parseFloat(avgB) > parseFloat(avgA)) { verdict.textContent = '🏆 Prompt B Wins'; verdict.className = 'summary-verdict verdict-b'; }
    else { verdict.textContent = '🤝 Tie'; verdict.className = 'summary-verdict verdict-tie'; }

    document.getElementById('win-tally').innerHTML = `
        <span class="tally-item" style="color:var(--accent-a);">A Wins: ${winsA}</span>
        <span class="tally-item" style="color:var(--accent-b);">B Wins: ${winsB}</span>
        <span class="tally-item">Ties: ${ties}</span>`;

    // Consistency bar
    const cBar = document.getElementById('consistency-bar');
    const hasConsistency = results.some(r => r.judgment.runs && r.judgment.runs > 1);
    if (hasConsistency) {
        const avgCA = (results.reduce((s, r) => s + (r.judgment.consistencyA || 0), 0) / results.length).toFixed(1);
        const avgCB = (results.reduce((s, r) => s + (r.judgment.consistencyB || 0), 0) / results.length).toFixed(1);
        cBar.style.display = 'block';
        cBar.innerHTML = `📊 Consistency Scores (across ${results[0].judgment.runs} runs): <strong style="color:var(--accent-a)">A: ${avgCA}/10</strong> · <strong style="color:var(--accent-b)">B: ${avgCB}/10</strong>`;
    } else { cBar.style.display = 'none'; }

    // Judge attribution
    const isSameAsResponder = judgeProvider === activeProvider && judgeModel === activeModel;
    document.getElementById('judge-info').innerHTML = isSameAsResponder
        ? `⚖️ Self-judged · <strong>${judgeModel}</strong>`
        : `⚖️ Judged by <strong>${judgeModel}</strong> <span style="color:var(--text-dim)">(${PROVIDERS[judgeProvider].name})</span>`;

    // Cards
    const container = document.getElementById('results-container');
    container.innerHTML = '';

    results.forEach((r, i) => {
        const j = r.judgment;
        const wClass = j.winner === 'A' ? 'winner-a' : j.winner === 'B' ? 'winner-b' : 'winner-tie';
        const wText = j.winner === 'A' ? '🔵 A Wins' : j.winner === 'B' ? '🟡 B Wins' : '🤝 Tie';
        const scA = j.scoreA > j.scoreB ? 'score-high' : j.scoreA < j.scoreB ? 'score-low' : 'score-equal';
        const scB = j.scoreB > j.scoreA ? 'score-high' : j.scoreB < j.scoreA ? 'score-low' : 'score-equal';

        const criteriaEntries = j.criteria ? Object.entries(j.criteria) : [];
        const criteriaBreakdownHtml = criteriaEntries.length > 0 ? `
            <div class="crit-breakdown">
                <div class="crit-breakdown-head">
                    <span>Criterion</span>
                    <span style="color:var(--accent-a)">A</span>
                    <span style="color:var(--accent-b)">B</span>
                    <span>Reasoning</span>
                </div>
                ${criteriaEntries.map(([name, c]) => {
                    const csA = (c.scoreA||0) > (c.scoreB||0) ? 'score-high' : (c.scoreA||0) < (c.scoreB||0) ? 'score-low' : 'score-equal';
                    const csB = (c.scoreB||0) > (c.scoreA||0) ? 'score-high' : (c.scoreB||0) < (c.scoreA||0) ? 'score-low' : 'score-equal';
                    return `<div class="crit-score-row">
                        <span class="crit-name">${escapeHtml(name)}</span>
                        <span class="result-score ${csA}">${c.scoreA ?? '—'}/10</span>
                        <span class="result-score ${csB}">${c.scoreB ?? '—'}/10</span>
                        <span class="crit-reasoning">${escapeHtml(c.reasoning || '')}</span>
                    </div>`;
                }).join('')}
            </div>` : '';

        const card = document.createElement('div');
        card.className = 'result-card';
        card.innerHTML = `
            <div class="result-card-header">
                <span class="result-test-input">Test ${i + 1}: "${truncate(r.testInput, 70)}"</span>
                <span class="result-winner-badge ${wClass}">${wText}</span>
            </div>
            <div class="result-body">
                <div class="result-col">
                    <div class="result-col-header"><span class="result-col-label col-a">Prompt A</span><span class="result-score ${scA}">${j.scoreA}/10</span></div>
                    <div class="result-response">${escapeHtml(r.responseA)}</div>
                    <div class="result-feedback"><h5>Strengths</h5><ul class="feedback-list strengths">${(j.strengthsA||[]).map(s=>`<li>${escapeHtml(s)}</li>`).join('')}</ul></div>
                    <div class="result-feedback"><h5>Weaknesses</h5><ul class="feedback-list weaknesses">${(j.weaknessesA||[]).map(s=>`<li>${escapeHtml(s)}</li>`).join('')}</ul></div>
                </div>
                <div class="result-col">
                    <div class="result-col-header"><span class="result-col-label col-b">Prompt B</span><span class="result-score ${scB}">${j.scoreB}/10</span></div>
                    <div class="result-response">${escapeHtml(r.responseB)}</div>
                    <div class="result-feedback"><h5>Strengths</h5><ul class="feedback-list strengths">${(j.strengthsB||[]).map(s=>`<li>${escapeHtml(s)}</li>`).join('')}</ul></div>
                    <div class="result-feedback"><h5>Weaknesses</h5><ul class="feedback-list weaknesses">${(j.weaknessesB||[]).map(s=>`<li>${escapeHtml(s)}</li>`).join('')}</ul></div>
                </div>
            </div>
            ${criteriaBreakdownHtml}
            <div class="result-reasoning"><h5>Judge's Reasoning</h5><p>${escapeHtml(j.reasoning||'')}</p></div>`;
        container.appendChild(card);
    });

    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================
// Reset Results
// ============================================================
function resetResults() {
    lastResults = null;
    const section = document.getElementById('results-section');
    section.style.display = 'none';
    document.getElementById('results-container').innerHTML = '';
    if (location.hash.startsWith('#share=')) history.replaceState(null, '', location.pathname);
    document.getElementById('run-btn').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// ============================================================
// Export Report
// ============================================================
function exportReport() {
    if (!lastResults) { showToast('No results to export. Run an evaluation first.', 'error'); return; }

    const criteria = getCriteria();
    const avgA = (lastResults.reduce((s, r) => s + r.judgment.scoreA, 0) / lastResults.length).toFixed(1);
    const avgB = (lastResults.reduce((s, r) => s + r.judgment.scoreB, 0) / lastResults.length).toFixed(1);
    const overallWinner = parseFloat(avgA) > parseFloat(avgB) ? 'A' : parseFloat(avgB) > parseFloat(avgA) ? 'B' : 'Tie';
    let winsA = 0, winsB = 0, ties = 0;
    lastResults.forEach(r => {
        if (r.judgment.winner === 'A') winsA++;
        else if (r.judgment.winner === 'B') winsB++;
        else ties++;
    });

    const hasConsistency = lastResults.some(r => r.judgment.runs && r.judgment.runs > 1);
    const avgCA = hasConsistency ? (lastResults.reduce((s, r) => s + (r.judgment.consistencyA || 0), 0) / lastResults.length).toFixed(1) : null;
    const avgCB = hasConsistency ? (lastResults.reduce((s, r) => s + (r.judgment.consistencyB || 0), 0) / lastResults.length).toFixed(1) : null;

    // Per-criteria averages across all test cases
    const criteriaAvgHtml = (() => {
        if (!criteria.length) return '';
        const critAvgs = criteria.map(c => {
            const vals = lastResults.map(r => r.judgment.criteria?.[c.name]).filter(Boolean);
            if (!vals.length) return null;
            const aAvg = (vals.reduce((s, v) => s + (v.scoreA || 0), 0) / vals.length).toFixed(1);
            const bAvg = (vals.reduce((s, v) => s + (v.scoreB || 0), 0) / vals.length).toFixed(1);
            return { name: c.name, aAvg, bAvg };
        }).filter(Boolean);
        if (!critAvgs.length) return '';
        return `
        <div class="section">
            <h2 class="section-title">Criteria Breakdown</h2>
            <table class="crit-table">
                <thead><tr><th>Criterion</th><th class="col-a">Prompt A avg</th><th class="col-b">Prompt B avg</th><th>Edge</th></tr></thead>
                <tbody>
                    ${critAvgs.map(c => {
                        const aNum = parseFloat(c.aAvg), bNum = parseFloat(c.bAvg);
                        const edge = aNum > bNum ? `<span class="badge-a">A +${(aNum-bNum).toFixed(1)}</span>` : bNum > aNum ? `<span class="badge-b">B +${(bNum-aNum).toFixed(1)}</span>` : `<span class="badge-tie">Tie</span>`;
                        return `<tr>
                            <td class="crit-name-cell">${escapeHtml(c.name)}</td>
                            <td class="col-a score-cell">${scoreBar(c.aAvg)} ${c.aAvg}</td>
                            <td class="col-b score-cell">${scoreBar(c.bAvg)} ${c.bAvg}</td>
                            <td>${edge}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>
        </div>`;
    })();

    const promptA = document.getElementById('prompt-a').value.trim();
    const promptB = document.getElementById('prompt-b').value.trim();

    const testsHtml = lastResults.map((r, i) => {
        const j = r.judgment;
        const winLabel = j.winner === 'A' ? '<span class="badge-a">A Wins</span>' : j.winner === 'B' ? '<span class="badge-b">B Wins</span>' : '<span class="badge-tie">Tie</span>';
        const scA = j.scoreA > j.scoreB ? 'score-high' : j.scoreA < j.scoreB ? 'score-low' : '';
        const scB = j.scoreB > j.scoreA ? 'score-high' : j.scoreB < j.scoreA ? 'score-low' : '';

        const critRowsHtml = j.criteria ? Object.entries(j.criteria).map(([name, c]) => {
            const csA = (c.scoreA||0) > (c.scoreB||0) ? 'score-high' : (c.scoreA||0) < (c.scoreB||0) ? 'score-low' : '';
            const csB = (c.scoreB||0) > (c.scoreA||0) ? 'score-high' : (c.scoreB||0) < (c.scoreA||0) ? 'score-low' : '';
            return `<tr>
                <td class="crit-name-cell">${escapeHtml(name)}</td>
                <td class="col-a score-cell ${csA}">${c.scoreA ?? '—'}/10</td>
                <td class="col-b score-cell ${csB}">${c.scoreB ?? '—'}/10</td>
                <td class="reasoning-cell">${escapeHtml(c.reasoning || '')}</td>
            </tr>`;
        }).join('') : '';

        const mkFeedback = (label, items, cls) => items?.length
            ? `<div class="feedback-block ${cls}"><span class="fb-label">${label}</span>${items.map(s => `<span class="fb-item">${escapeHtml(s)}</span>`).join('')}</div>`
            : '';

        return `
        <div class="test-card">
            <div class="test-card-header">
                <span class="test-num">Test ${i + 1}</span>
                <span class="test-input-text">${escapeHtml(r.testInput)}</span>
                ${winLabel}
            </div>
            ${critRowsHtml ? `
            <table class="crit-table inner-crit-table">
                <thead><tr><th>Criterion</th><th class="col-a">A</th><th class="col-b">B</th><th>Reasoning</th></tr></thead>
                <tbody>${critRowsHtml}</tbody>
            </table>` : ''}
            <div class="response-grid">
                <div class="response-col">
                    <div class="response-header">
                        <span class="col-a-label">Prompt A</span>
                        <span class="score-pill ${scA}">${j.scoreA}/10</span>
                    </div>
                    <div class="response-body">${escapeHtml(r.responseA)}</div>
                    ${mkFeedback('Strengths', j.strengthsA, 'strengths')}
                    ${mkFeedback('Weaknesses', j.weaknessesA, 'weaknesses')}
                </div>
                <div class="response-col">
                    <div class="response-header">
                        <span class="col-b-label">Prompt B</span>
                        <span class="score-pill ${scB}">${j.scoreB}/10</span>
                    </div>
                    <div class="response-body">${escapeHtml(r.responseB)}</div>
                    ${mkFeedback('Strengths', j.strengthsB, 'strengths')}
                    ${mkFeedback('Weaknesses', j.weaknessesB, 'weaknesses')}
                </div>
            </div>
            ${j.reasoning ? `<div class="reasoning-block"><span class="reasoning-label">Judge's Reasoning</span> ${escapeHtml(j.reasoning)}</div>` : ''}
        </div>`;
    }).join('');

    const verdictColor = overallWinner === 'A' ? '#3b82f6' : overallWinner === 'B' ? '#f59e0b' : '#8b5cf6';
    const verdictText = overallWinner === 'A' ? '🏆 Prompt A Wins' : overallWinner === 'B' ? '🏆 Prompt B Wins' : '🤝 Tie';
    const isSameJudge = judgeProvider === activeProvider && judgeModel === activeModel;
    const judgeLabel = isSameJudge ? `${judgeModel} (self-judged)` : `${judgeModel} (${PROVIDERS[judgeProvider].name})`;

    function scoreBar(val) {
        const pct = Math.round(parseFloat(val) * 10);
        return `<span class="mini-bar"><span class="mini-bar-fill" style="width:${pct}%"></span></span>`;
    }

    const currentTheme = document.documentElement.dataset.theme || 'dark';

    const html = `<!DOCTYPE html>
<html lang="en" data-theme="${currentTheme}">
<head>
<meta charset="UTF-8">
<title>LLM Judge Report — ${new Date().toLocaleDateString()}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f1f5f9;--surface:#fff;--text:#0f172a;--muted:#475569;--dim:#94a3b8;
  --border:#e2e8f0;--border2:#f1f5f9;--raised:#f8fafc;--inset:#f4f6f9;
  --mini-bar-bg:#e2e8f0;
}
[data-theme="dark"]{
  --bg:#0d1117;--surface:#161b22;--text:#e6edf3;--muted:#8b949e;--dim:#6e7681;
  --border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.04);--raised:#1c2128;--inset:#21262d;
  --mini-bar-bg:rgba(255,255,255,0.1);
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;transition:background .2s,color .2s}
a{color:inherit}
.page{max-width:960px;margin:0 auto;padding:32px 24px 64px}
/* Theme toggle */
.theme-toggle{position:fixed;bottom:24px;right:24px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:50%;width:40px;height:40px;font-size:1.1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 16px rgba(0,0,0,0.2);transition:all .2s;z-index:99}
.theme-toggle:hover{transform:scale(1.1)}
/* Header */
.report-header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);color:#f1f5f9;border-radius:16px;padding:32px;margin-bottom:24px}
.report-header h1{font-size:1.6rem;font-weight:800;letter-spacing:-0.5px;margin-bottom:4px}
.report-meta{font-size:0.8rem;color:#94a3b8;margin-top:12px;display:flex;flex-wrap:wrap;gap:16px}
.report-meta span{display:flex;align-items:center;gap:6px}
.meta-dot{width:6px;height:6px;border-radius:50%;background:#3b82f6;display:inline-block}
/* Summary */
.summary-grid{display:grid;grid-template-columns:1fr auto 1fr;gap:0;background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:24px}
.summary-cell{padding:24px;text-align:center}
.summary-cell.verdict-cell{background:var(--raised);border-left:1px solid var(--border);border-right:1px solid var(--border);display:flex;flex-direction:column;align-items:center;justify-content:center}
.summary-label{font-size:0.7rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:8px}
.summary-score{font-size:3rem;font-weight:800;line-height:1;display:block}
.score-a-color{color:#3b82f6}.score-b-color{color:#f59e0b}
.verdict-text{font-size:1.3rem;font-weight:700;color:${verdictColor};margin-bottom:8px}
.tally{font-size:0.8rem;color:var(--muted);display:flex;gap:12px;margin-top:4px}
.tally-a{color:#3b82f6;font-weight:600}.tally-b{color:#f59e0b;font-weight:600}
/* Consistency */
.consistency-row{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px 16px;margin-bottom:24px;font-size:0.85rem;color:#1e40af}
[data-theme="dark"] .consistency-row{background:rgba(59,130,246,0.1);border-color:rgba(59,130,246,0.25);color:#93c5fd}
/* Prompts */
.prompts-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.prompt-box{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.prompt-box-header{padding:10px 14px;font-size:0.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid var(--border)}
.prompt-box-header.pa{background:#eff6ff;color:#3b82f6}
.prompt-box-header.pb{background:#fffbeb;color:#b45309}
[data-theme="dark"] .prompt-box-header.pa{background:rgba(59,130,246,0.12);color:#60a5fa}
[data-theme="dark"] .prompt-box-header.pb{background:rgba(245,158,11,0.12);color:#fbbf24}
.prompt-box-body{padding:12px 14px;font-size:0.82rem;color:var(--muted);white-space:pre-wrap;max-height:180px;overflow:auto}
/* Section */
.section{margin-bottom:24px}
.section-title{font-size:1rem;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:8px}
.section-title::before{content:'';display:block;width:3px;height:1em;background:#6366f1;border-radius:2px}
/* Tables */
.crit-table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:0.82rem}
.crit-table thead tr{background:var(--raised)}
.crit-table th{padding:10px 14px;text-align:left;font-weight:600;color:var(--muted);font-size:0.72rem;letter-spacing:.05em;text-transform:uppercase;border-bottom:1px solid var(--border)}
.crit-table td{padding:10px 14px;border-bottom:1px solid var(--border2);vertical-align:top}
.crit-table tr:last-child td{border-bottom:none}
.crit-name-cell{font-weight:600;color:var(--text)}
.score-cell{font-weight:700;font-size:0.85rem}
.col-a th,.col-a{color:#3b82f6}.col-b th,.col-b{color:#f59e0b}
.reasoning-cell{color:var(--muted);font-size:0.8rem}
.score-high{color:#16a34a!important}.score-low{color:#dc2626!important}
/* Mini bar */
.mini-bar{display:inline-block;width:40px;height:6px;background:var(--mini-bar-bg);border-radius:3px;vertical-align:middle;margin-right:4px;overflow:hidden}
.mini-bar-fill{display:block;height:100%;background:#6366f1;border-radius:3px}
/* Badges */
.badge-a,.badge-b,.badge-tie{display:inline-block;padding:2px 8px;border-radius:99px;font-size:0.72rem;font-weight:700}
.badge-a{background:#eff6ff;color:#3b82f6}.badge-b{background:#fffbeb;color:#b45309}.badge-tie{background:var(--raised);color:var(--muted)}
[data-theme="dark"] .badge-a{background:rgba(59,130,246,0.15);color:#60a5fa}
[data-theme="dark"] .badge-b{background:rgba(245,158,11,0.15);color:#fbbf24}
/* Test cards */
.test-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.test-card-header{background:var(--raised);padding:14px 18px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.test-num{font-size:0.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);white-space:nowrap}
.test-input-text{font-weight:600;color:var(--text);flex:1;font-size:0.88rem}
.inner-crit-table{border:none;border-radius:0;border-bottom:1px solid var(--border)}
.inner-crit-table th,.inner-crit-table td{border-bottom:1px solid var(--border2)}
/* Response grid */
.response-grid{display:grid;grid-template-columns:1fr 1fr}
.response-col{padding:16px 18px;border-right:1px solid var(--border2)}
.response-col:last-child{border-right:none}
.response-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.col-a-label{font-weight:700;font-size:0.78rem;color:#3b82f6;text-transform:uppercase;letter-spacing:.06em}
.col-b-label{font-weight:700;font-size:0.78rem;color:#f59e0b;text-transform:uppercase;letter-spacing:.06em}
.score-pill{font-size:0.78rem;font-weight:700;padding:2px 8px;border-radius:99px;background:var(--raised);color:var(--muted)}
.score-pill.score-high{background:#dcfce7;color:#16a34a}
.score-pill.score-low{background:#fee2e2;color:#dc2626}
[data-theme="dark"] .score-pill.score-high{background:rgba(22,163,74,0.2);color:#4ade80}
[data-theme="dark"] .score-pill.score-low{background:rgba(220,38,38,0.2);color:#f87171}
.response-body{font-size:0.82rem;color:var(--muted);white-space:pre-wrap;line-height:1.6;margin-bottom:10px}
/* Feedback */
.feedback-block{margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;align-items:flex-start}
.fb-label{font-size:0.68rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-right:4px;padding-top:2px;white-space:nowrap}
.strengths .fb-label{color:#16a34a}.weaknesses .fb-label{color:#dc2626}
.fb-item{font-size:0.75rem;padding:2px 7px;border-radius:99px}
.strengths .fb-item{background:#dcfce7;color:#166534}.weaknesses .fb-item{background:#fee2e2;color:#991b1b}
[data-theme="dark"] .strengths .fb-item{background:rgba(22,163,74,0.15);color:#4ade80}
[data-theme="dark"] .weaknesses .fb-item{background:rgba(220,38,38,0.15);color:#f87171}
/* Reasoning */
.reasoning-block{background:var(--inset);border-top:1px solid var(--border);padding:12px 18px;font-size:0.82rem;color:var(--muted);line-height:1.6}
.reasoning-label{font-weight:600;color:var(--text);margin-right:6px}
/* Footer */
.report-footer{text-align:center;margin-top:48px;font-size:0.75rem;color:var(--dim)}
@media print{.theme-toggle{display:none}.page{padding:16px}}
</style>
</head>
<body>
<button class="theme-toggle" onclick="var h=document.documentElement;var t=h.dataset.theme==='dark'?'light':'dark';h.dataset.theme=t;this.textContent=t==='dark'?'☀️':'🌙'" title="Toggle theme">${currentTheme === 'dark' ? '☀️' : '🌙'}</button>
<div class="page">

    <div class="report-header">
        <h1>⚖️ LLM Judge — Evaluation Report</h1>
        <div class="report-meta">
            <span><span class="meta-dot"></span> ${new Date().toLocaleString()}</span>
            <span><span class="meta-dot" style="background:#6366f1"></span> Responder: ${escapeHtml(PROVIDERS[activeProvider].name)} / ${escapeHtml(activeModel)}</span>
            <span><span class="meta-dot" style="background:#8b5cf6"></span> Judge: ${escapeHtml(judgeLabel)}</span>
            <span><span class="meta-dot" style="background:#10b981"></span> ${lastResults.length} test case${lastResults.length !== 1 ? 's' : ''} · ${criteria.length} criteri${criteria.length !== 1 ? 'a' : 'on'}</span>
        </div>
    </div>

    <div class="summary-grid">
        <div class="summary-cell">
            <span class="summary-label">Prompt A Average</span>
            <span class="summary-score score-a-color">${avgA}</span>
            <span style="font-size:0.75rem;color:var(--muted);margin-top:4px;display:block">out of 10</span>
        </div>
        <div class="summary-cell verdict-cell">
            <div class="verdict-text">${verdictText}</div>
            <div class="tally">
                <span class="tally-a">A: ${winsA}W</span>
                <span>·</span>
                <span class="tally-b">B: ${winsB}W</span>
                <span>·</span>
                <span>${ties} Tie${ties !== 1 ? 's' : ''}</span>
            </div>
        </div>
        <div class="summary-cell">
            <span class="summary-label">Prompt B Average</span>
            <span class="summary-score score-b-color">${avgB}</span>
            <span style="font-size:0.75rem;color:var(--muted);margin-top:4px;display:block">out of 10</span>
        </div>
    </div>

    ${hasConsistency ? `<div class="consistency-row">📊 Consistency across ${lastResults[0].judgment.runs} runs — Prompt A: <strong>${avgCA}/10</strong> · Prompt B: <strong>${avgCB}/10</strong></div>` : ''}

    <div class="prompts-grid">
        <div class="prompt-box">
            <div class="prompt-box-header pa">Prompt A — Baseline</div>
            <div class="prompt-box-body">${escapeHtml(promptA || '(not captured)')}</div>
        </div>
        <div class="prompt-box">
            <div class="prompt-box-header pb">Prompt B — Challenger</div>
            <div class="prompt-box-body">${escapeHtml(promptB || '(not captured)')}</div>
        </div>
    </div>

    ${criteriaAvgHtml}

    <div class="section">
        <h2 class="section-title">Test-by-Test Results</h2>
        ${testsHtml}
    </div>

    <div class="report-footer">Generated by <strong>LLM Judge</strong> — Prompt A/B Evaluator</div>
</div>
</body></html>`;

    function scoreBar(val) {
        const pct = Math.round(parseFloat(val) * 10);
        return `<span class="mini-bar"><span class="mini-bar-fill" style="width:${pct}%"></span></span>`;
    }

    const blob = new Blob([html], { type: 'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `llm-judge-report-${Date.now()}.html`;
    a.click();
    showToast('Report exported!', 'success');
}

// ============================================================
// URL Share — Compression + Encoding
// ============================================================
function uint8ToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function toBase64Url(b64) { return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); }
function fromBase64Url(b64u) {
    const pad = '=='.slice(0, (4 - b64u.length % 4) % 4);
    return b64u.replace(/-/g, '+').replace(/_/g, '/') + pad;
}

async function compressToBase64Url(obj) {
    const bytes = new TextEncoder().encode(JSON.stringify(obj));
    if (!window.CompressionStream) {
        return 'r' + toBase64Url(uint8ToBase64(bytes));
    }
    const cs = new CompressionStream('gzip');
    const writer = cs.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const compressed = new Uint8Array(await new Response(cs.readable).arrayBuffer());
    return 'g' + toBase64Url(uint8ToBase64(compressed));
}

async function decompressFromBase64Url(str) {
    const type = str[0];
    const bytes = Uint8Array.from(atob(fromBase64Url(str.slice(1))), c => c.charCodeAt(0));
    if (type !== 'g' || !window.DecompressionStream) {
        return JSON.parse(new TextDecoder().decode(bytes));
    }
    const ds = new DecompressionStream('gzip');
    const writer = ds.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const decompressed = await new Response(ds.readable).arrayBuffer();
    return JSON.parse(new TextDecoder().decode(decompressed));
}

// ============================================================
// URL Share — Generate & Load
// ============================================================
async function generateShareUrl() {
    if (!lastResults) { showToast('Run an evaluation first.', 'error'); return; }
    const btn = document.getElementById('share-results-btn');
    const orig = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = 'Generating…';
    try {
        const payload = {
            v: 1,
            meta: { provider: activeProvider, model: activeModel, judgeProvider, judgeModel, timestamp: Date.now() },
            criteria: getCriteria(),
            promptA: document.getElementById('prompt-a').value,
            promptB: document.getElementById('prompt-b').value,
            results: lastResults
        };
        const encoded = await compressToBase64Url(payload);
        const url = `${location.origin}${location.pathname}#share=${encoded}`;
        history.replaceState(null, '', `#share=${encoded}`);
        try {
            await navigator.clipboard.writeText(url);
            showToast('Share link copied to clipboard!', 'success');
        } catch {
            showToast('Link updated in address bar — copy it from there.', 'info');
        }
    } catch (err) {
        showToast('Could not generate share link.', 'error');
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = orig;
    }
}

async function loadFromShareUrl() {
    if (!location.hash.startsWith('#share=')) return;
    try {
        const payload = await decompressFromBase64Url(location.hash.slice(7));
        if (!payload?.results) return;
        if (payload.criteria) renderCriteriaFromData(payload.criteria);
        if (payload.promptA) document.getElementById('prompt-a').value = payload.promptA;
        if (payload.promptB) document.getElementById('prompt-b').value = payload.promptB;
        if (payload.meta?.judgeProvider) { judgeProvider = payload.meta.judgeProvider; syncJudgeProviderUI(); }
        if (payload.meta?.judgeModel) { judgeModel = payload.meta.judgeModel; populateJudgeModelSelect(); }
        lastResults = payload.results;
        renderResults(payload.results);
        showShareBanner(payload.meta);
    } catch {
        showToast('Could not load shared results. The link may be corrupted.', 'error');
        history.replaceState(null, '', location.pathname);
    }
}

function showShareBanner(meta) {
    const date = meta?.timestamp ? new Date(meta.timestamp).toLocaleString() : '';
    const provider = meta?.provider ? (PROVIDERS[meta.provider]?.name || meta.provider) : '';
    const model = meta?.model || '';
    const parts = ['Viewing shared evaluation', date && `from ${date}`, provider && model && `${provider} · ${model}`].filter(Boolean);
    document.getElementById('share-banner-text').textContent = parts.join(' · ');
    const banner = document.getElementById('share-banner');
    banner.style.display = 'flex';
    setTimeout(() => banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);
}

// ============================================================
// Utilities
// ============================================================
function escapeHtml(text) { const d = document.createElement('div'); d.textContent = text; return d.innerHTML; }
function truncate(str, max) { return str.length > max ? str.substring(0, max) + '...' : str; }
