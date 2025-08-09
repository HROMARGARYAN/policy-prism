
const $ = s => document.querySelector(s);
const listEl = $('#list');
const navAnalyses = $('#navAnalyses');
const navBreach = $('#navBreach');
const secAnalyses = $('#analyses');
const secBreach = $('#breach');

navAnalyses.addEventListener('click', (e) => { e.preventDefault(); navAnalyses.classList.add('active'); navBreach.classList.remove('active'); secAnalyses.classList.remove('hidden'); secBreach.classList.add('hidden'); });
navBreach.addEventListener('click', (e) => { e.preventDefault(); navBreach.classList.add('active'); navAnalyses.classList.remove('active'); secBreach.classList.remove('hidden'); secAnalyses.classList.add('hidden'); });

async function fetchList() {
  const r = await fetch('/list');
  const data = await r.json();
  renderList(data.items || []);
}
function renderList(items) {
  listEl.innerHTML = '';
  if (!items.length) {
    listEl.innerHTML = '<div class="card"><em>No saved analyses yet.</em></div>';
    return;
  }
  items.forEach(it => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <h3>${it.url || '(no url)'}</h3>
      <div class="meta">
        <span>Risk: <strong>${it.risk_score ?? '-'}</strong></span>
        <span>Saved: ${new Date(it.created_at).toLocaleString()}</span>
      </div>
      <p>${it.summary || ''}</p>
      <div><strong>Highlights:</strong><ul>${(it.highlights || []).slice(0,6).map(h => `<li>${(h.text||h)}</li>`).join('')}</ul></div>
      <div class="actions">
        <button data-id="${it.id}" class="recheck">Re-check</button>
        <button data-id="${it.id}" class="delete secondary">Delete</button>
        <a href="${it.url}" target="_blank" class="secondary">Open</a>
      </div>
    `;
    listEl.appendChild(card);
  });
  listEl.querySelectorAll('.delete').forEach(btn => btn.addEventListener('click', async (e) => {
    const id = e.target.getAttribute('data-id');
    await fetch(`/delete/${id}`, { method: 'DELETE' });
    fetchList();
  }));
  listEl.querySelectorAll('.recheck').forEach(btn => btn.addEventListener('click', async (e) => {
    const id = e.target.getAttribute('data-id');
    const r = await fetch(`/recheck/${id}`, { method: 'POST' });
    if (r.ok) fetchList();
  }));
}
fetchList();

// Breach Watch
$('#addEmailForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#emailInput').value.trim();
  if (!email) return;
  const r = await fetch('/breach/add', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ email }) });
  if (r.ok) { $('#emailInput').value=''; checkBreach(); }
});
async function checkBreach() {
  const r = await fetch('/breach/check');
  const data = await r.json();
  const wrap = $('#breachResults');
  wrap.innerHTML = '';
  (data.results || []).forEach(row => {
    const div = document.createElement('div');
    div.className = 'item';
    div.textContent = `${row.email}: ${row.status}`;
    wrap.appendChild(div);
  });
}
$('#checkBtn').addEventListener('click', checkBreach);


// --- Provider Audits ---
const navAudits = document.querySelector('#navAudits');
const secAudits = document.querySelector('#audits');
navAudits.addEventListener('click', async (e) => {
  e.preventDefault();
  navAnalyses.classList.remove('active');
  navBreach.classList.remove('active');
  navAudits.classList.add('active');
  secAnalyses.classList.add('hidden');
  secBreach.classList.add('hidden');
  secAudits.classList.remove('hidden');
  await loadProviders();
});

async function loadProviders() {
  const r = await fetch('/audit/providers');
  const data = await r.json();
  const wrap = document.querySelector('#providers');
  wrap.innerHTML = '';
  (data.providers || []).forEach(p => {
    const btn = document.createElement('button');
    btn.textContent = p;
    btn.addEventListener('click', () => loadChecklist(p));
    wrap.appendChild(btn);
  });
}
async function loadChecklist(provider) {
  const r = await fetch('/audit/' + provider);
  const data = await r.json();
  const wrap = document.querySelector('#checklist');
  wrap.innerHTML = `<h3>${data.provider}</h3>`;
  const ul = document.createElement('ul');
  (data.checklist || []).forEach(item => {
    const li = document.createElement('li');
    if (item.link) {
      const a = document.createElement('a');
      a.href = item.link; a.target = '_blank'; a.textContent = item.label;
      li.appendChild(a);
    } else {
      li.textContent = item.label;
    }
    ul.appendChild(li);
  });
  wrap.appendChild(ul);
}

// Enhance list cards with PDF export links
function enhanceCardsWithPDF() {
  document.querySelectorAll('#list .card').forEach(card => {
    const h3 = card.querySelector('h3');
    const idMatch = /data-id="([^"]+)"/.exec(card.innerHTML);
    if (!idMatch) return;
    const id = idMatch[1];
    const link = document.createElement('a');
    link.href = `/report/${id}.pdf`;
    link.textContent = 'Export PDF';
    link.className = 'secondary';
    link.style.marginLeft = '8px';
    card.querySelector('.actions').appendChild(link);
  });
}
const origRenderList = renderList;
renderList = function(items) { origRenderList(items); enhanceCardsWithPDF(); }


// --- Auth & Encryption (client-side AES-GCM with PBKDF2 key) ---
let token = null;
let encKey = null; // CryptoKey
let saltHex = null; // hex string

const authSec = document.querySelector('#auth');
const loginForm = document.querySelector('#loginForm');
const registerBtn = document.querySelector('#registerBtn');

function bufToHex(buffer) { return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join(''); }
function hexToBuf(hex) { const m = hex.match(/.{1,2}/g).map(byte => parseInt(byte,16)); return new Uint8Array(m).buffer; }

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

async function ensureEncKey(password) {
  if (encKey) return encKey;
  // Create deterministic salt from email (not ideal) or random and store locally
  if (!saltHex) { saltHex = localStorage.getItem('pt_salt'); }
  if (!saltHex) {
    const rand = crypto.getRandomValues(new Uint8Array(16));
    saltHex = bufToHex(rand);
    localStorage.setItem('pt_salt', saltHex);
  }
  encKey = await deriveKey(password, hexToBuf(saltHex));
  return encKey;
}

async function encryptPayload(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const key = await ensureEncKey(currentPassword);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { cipherText: btoa(String.fromCharCode(...new Uint8Array(cipher))), iv: bufToHex(iv), salt: saltHex };
}

async function decryptPayload(encObj) {
  try {
    const key = await ensureEncKey(currentPassword);
    const iv = hexToBuf(encObj.iv);
    const bytes = Uint8Array.from(atob(encObj.cipherText), c => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytes);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(plain)));
  } catch (e) {
    console.error('Decrypt failed', e.message);
    return null;
  }
}

let currentEmail = null;
let currentPassword = null;

async function api(path, opts={}) {
  opts.headers = opts.headers || {};
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  return fetch(path, opts);
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.querySelector('#authEmail').value.trim();
  const password = document.querySelector('#authPassword').value;
  currentEmail = email; currentPassword = password;
  let r = await fetch('/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password }) });
  if (r.status === 401) {
    // Try register
    r = await fetch('/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password }) });
  }
  if (r.ok) {
    const data = await r.json();
    token = data.token;
    await ensureEncKey(password);
    authSec.classList.add('hidden');
    secAnalyses.classList.remove('hidden');
    navAnalyses.classList.add('active');
    fetchListSecure();
  } else {
    alert('Login/Register failed');
  }
});
registerBtn.addEventListener('click', async () => {
  loginForm.dispatchEvent(new Event('submit'));
});

async function fetchListSecure() {
  const r = await api('/list');
  const data = await r.json();
  // Decrypt each item payload to display summary/risk/highlights
  const items = [];
  for (const it of (data.items || [])) {
    const plain = await decryptPayload(it.enc);
    items.push({ ...it, plain });
  }
  renderListSecure(items);
}

function renderListSecure(items) {
  listEl.innerHTML = '';
  if (!items.length) {
    listEl.innerHTML = '<div class="card"><em>No saved analyses yet.</em></div>';
    return;
  }
  items.forEach(it => {
    const p = it.plain || {};
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <h3 data-id="${it.id}">${it.url || p.url || '(no url)'}</h3>
      <div class="meta">
        <span>Risk: <strong>${p.risk_score ?? '-'}</strong></span>
        <span>Saved: ${new Date(it.created_at).toLocaleString()}</span>
      </div>
      <p>${p.summary || ''}</p>
      <div><strong>Highlights:</strong><ul>${(p.highlights || []).slice(0,6).map(h => `<li>${(h.text||h)}</li>`).join('')}</ul></div>
      <div class="actions">
        <button data-id="${it.id}" class="recheck">Re-check</button>
        <button data-id="${it.id}" class="delete secondary">Delete</button>
        <a href="${it.url ? '/report/'+it.id : '#'}" target="_blank" class="secondary">Open Report</a>
        <a href="${it.url ? '/report/'+it.id+'.pdf' : '#'}" target="_blank" class="secondary">Export PDF</a>
      </div>
    `;
    listEl.appendChild(card);
  });
  listEl.querySelectorAll('.delete').forEach(btn => btn.addEventListener('click', async (e) => {
    const id = e.target.getAttribute('data-id');
    await api(`/delete/${id}`, { method: 'DELETE' });
    fetchListSecure();
  }));
  listEl.querySelectorAll('.recheck').forEach(btn => btn.addEventListener('click', async (e) => {
    const id = e.target.getAttribute('data-id');
    const r = await api(`/recheck/${id}`, { method: 'POST' });
    if (r.ok) fetchListSecure();
  }));
}

// --- Navigation updates: Letters & email alerts toggle ---
const navLetters = document.querySelector('#navLetters');
const secLetters = document.querySelector('#letters');
navLetters.addEventListener('click', (e) => {
  e.preventDefault();
  navAnalyses.classList.remove('active'); navBreach.classList.remove('active'); navAudits.classList.remove('active'); navLetters.classList.add('active');
  secAnalyses.classList.add('hidden'); secBreach.classList.add('hidden'); secAudits.classList.add('hidden'); secLetters.classList.remove('hidden');
});

// Letters form
document.querySelector('#letterForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    law: document.querySelector('#law').value,
    request: document.querySelector('#request').value,
    fullName: document.querySelector('#fullName').value,
    email: document.querySelector('#yourEmail').value,
    address: document.querySelector('#address').value,
    company: document.querySelector('#company').value
  };
  const r = await fetch('/letters/generate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await r.json();
  document.querySelector('#letterOut').textContent = (data.body || '');
});

