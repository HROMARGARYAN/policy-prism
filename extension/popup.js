
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}
function saveBackendUrl(url) { chrome.storage.sync.set({ backendUrl: url }); }
async function loadBackendUrl() {
  return new Promise(resolve => { chrome.storage.sync.get(['backendUrl'], d => resolve(d.backendUrl || 'http://localhost:8788')); });
}
function sendToContent(cmd, payload) { chrome.tabs.query({active: true, currentWindow: true}, tabs => { chrome.tabs.sendMessage(tabs[0].id, { cmd, payload }); }); }

document.addEventListener('DOMContentLoaded', async () => {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const saveBtn = document.getElementById('saveBtn');
  const toggleCiteBtn = document.getElementById('toggleCiteBtn');
  const status = document.getElementById('status');
  const result = document.getElementById('result');
  const summary = document.getElementById('summary');
  const riskScore = document.getElementById('riskScore');
  const highlights = document.getElementById('highlights');
  const actions = document.getElementById('actions');
  const backendUrlInput = document.getElementById('backendUrl');
  const openDashboard = document.getElementById('openDashboard');

  let lastAnalysis = null;
  let citeOn = false;

  const defaultBackend = await loadBackendUrl();
  backendUrlInput.value = defaultBackend;
  backendUrlInput.addEventListener('change', (e) => saveBackendUrl(e.target.value));

  analyzeBtn.addEventListener('click', async () => {
    status.textContent = "Extracting page text…";
    result.classList.add('hidden');
    saveBtn.disabled = true;
    toggleCiteBtn.disabled = true;
    sendToContent('clearHighlights');

    const tab = await getActiveTab();
    try {
      const [{ result: pageText }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const readCandidate = document.querySelector('main') || document.querySelector('article') || document.body;
          const walker = document.createTreeWalker(readCandidate, NodeFilter.SHOW_TEXT, null, false);
          let text = '', node;
          while (node = walker.nextNode()) {
            const t = node.nodeValue.replace(/\s+/g, ' ').trim();
            if (t.length > 1) text += t + ' ';
          }
          return text.slice(0, 200000);
        }
      });

      status.textContent = "Contacting analyzer…";
      const backendUrl = backendUrlInput.value || 'http://localhost:8788';
      saveBackendUrl(backendUrl);

      const res = await fetch(`${backendUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url, text: pageText })
      });
      if (!res.ok) throw new Error(`Analyzer returned ${res.status}`);
      const data = await res.json();
      lastAnalysis = { ...data, url: tab.url, raw: pageText };

      summary.textContent = data.summary || '(no summary)';
      riskScore.textContent = data.risk_score ?? '-';
      highlights.innerHTML = '';
      (data.citations || data.highlights || []).forEach(h => {
        const li = document.createElement('li');
        li.textContent = (h.text || h);
        highlights.appendChild(li);
      });
      actions.innerHTML = '';
      (data.actions || []).forEach(a => {
        const li = document.createElement('li');
        li.textContent = a;
        actions.appendChild(li);
      });

      result.classList.remove('hidden');
      status.textContent = "Done.";
      saveBtn.disabled = false;
      toggleCiteBtn.disabled = false;
      citeOn = true;
      sendToContent('highlightPhrases', (data.citations || data.highlights || []).map(h => (h.text || h)).slice(0, 12));
      openDashboard.href = `${backendUrl}/dashboard`;

    } catch (e) {
      console.error(e);
      status.textContent = "Error: " + e.message;
    }
  });

  saveBtn.addEventListener('click', async () => {
    if (!lastAnalysis) return;
    const backendUrl = backendUrlInput.value || 'http://localhost:8788';
    try {
      const res = await fetch(`${backendUrl}/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: lastAnalysis.url,
          summary: lastAnalysis.summary,
          risk_score: lastAnalysis.risk_score,
          highlights: (lastAnalysis.highlights || []),
          citations: (lastAnalysis.citations || []),
          actions: (lastAnalysis.actions || [])
        })
      });
      if (!res.ok) throw new Error('Save failed');
      status.textContent = "Saved to dashboard.";
    } catch (e) {
      status.textContent = "Save error: " + e.message;
    }
  });

  toggleCiteBtn.addEventListener('click', () => {
    citeOn = !citeOn;
    sendToContent(citeOn ? 'highlightPhrases' : 'clearHighlights');
  });
});


// --- Auth Token + Encrypt save payload using Web Crypto (same as dashboard) ---
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}
function bufToHex(buffer) { return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join(''); }
function hexToBuf(hex) { const m = hex.match(/.{1,2}/g).map(byte => parseInt(byte,16)); return new Uint8Array(m).buffer; }

async function ensureEncKey(password) {
  let saltHex = localStorage.getItem('pt_salt');
  if (!saltHex) { const rand = crypto.getRandomValues(new Uint8Array(16)); saltHex = bufToHex(rand); localStorage.setItem('pt_salt', saltHex); }
  const key = await deriveKey(password, hexToBuf(saltHex));
  return { key, saltHex };
}

async function encryptBlob(password, obj) {
  const { key, saltHex } = await ensureEncKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { enc: { cipherText: btoa(String.fromCharCode(...new Uint8Array(cipher))), iv: bufToHex(iv), salt: saltHex } };
}

async function getAuthToken() {
  return new Promise(resolve => chrome.storage.sync.get(['pt_token','pt_email'], d => resolve(d.pt_token || null)));
}

async function promptLogin(backendUrl) {
  const email = prompt('Email for dashboard login/registration:');
  const password = prompt('Password (min 8 chars):');
  if (!email || !password || password.length < 8) { alert('Invalid credentials'); return null; }
  let r = await fetch(`${backendUrl}/auth/login`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password }) });
  if (r.status === 401) {
    r = await fetch(`${backendUrl}/auth/register`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password }) });
  }
  if (!r.ok) { alert('Login/Register failed'); return null; }
  const data = await r.json();
  chrome.storage.sync.set({ pt_token: data.token, pt_email: email, pt_pw_hint: 'set' });
  return { token: data.token, email, password };
}

// Override saveBtn behavior to encrypt + send with token
document.addEventListener('DOMContentLoaded', async () => {
  const saveBtn = document.getElementById('saveBtn');
  const status = document.getElementById('status');
  const backendUrlInput = document.getElementById('backendUrl');

  saveBtn.addEventListener('click', async () => {
    const backendUrl = backendUrlInput.value || 'http://localhost:8788';
    let token = await getAuthToken();
    let email = null; let password = null;
    if (!token) {
      const creds = await promptLogin(backendUrl);
      if (!creds) return;
      token = creds.token; email = creds.email; password = creds.password;
    } else {
      email = (await new Promise(resolve => chrome.storage.sync.get(['pt_email'], d => resolve(d.pt_email))));
      // We can't retrieve password; for prototype, ask it now for encryption
      password = prompt('Enter your password to encrypt this save:');
      if (!password) { alert('Save canceled'); return; }
    }
    try {
      // Gather page info again minimally
      const tab = await getActiveTab();
      const [{ result: pageText }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const readCandidate = document.querySelector('main') || document.querySelector('article') || document.body;
          const walker = document.createTreeWalker(readCandidate, NodeFilter.SHOW_TEXT, null, false);
          let text = '', node;
          while (node = walker.nextNode()) {
            const t = node.nodeValue.replace(/\s+/g, ' ').trim();
            if (t.length > 1) text += t + ' ';
          }
          return text.slice(0, 200000);
        }
      });

      // Build plaintext payload from lastAnalysis-ish by re-calling analyzer for accurate record
      const res = await fetch(`${backendUrl}/analyze`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: tab.url, text: pageText })
      });
      const data = await res.json();
      const plain = { url: tab.url, summary: data.summary, risk_score: data.risk_score, highlights: (data.highlights||data.citations||[]), actions: (data.actions||[]) };
      const encPkg = await encryptBlob(password, plain);

      const saveRes = await fetch(`${backendUrl}/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ url: tab.url, ...encPkg })
      });
      if (!saveRes.ok) throw new Error('Save failed');
      status.textContent = "Saved (encrypted) to dashboard.";
    } catch (e) {
      status.textContent = "Save error: " + e.message;
    }
  });
});
