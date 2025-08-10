import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { z } from 'zod';
import { nanoid } from 'nanoid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';
import puppeteer from 'puppeteer';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App
const PORT = process.env.PORT || 8788;
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Static: landing + dashboard assets
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/dashboard', express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public_site', 'index.html'));
});

// Simple file “DB”
const DB_PATH = path.join(__dirname, 'data', 'db.json');
function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8')); }
  catch { return { users: [], analyses: [], watchlist_emails: [] }; }
}
function saveDb(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

// ---------- Analysis helpers ----------
const AnalyzeReq = z.object({ url: z.string().url().optional(), text: z.string().min(50) });

function heuristicRiskScore(text) {
  const t = text.toLowerCase();
  const weights = [
    { kw: 'sell', w: 18 }, { kw: 'share with', w: 12 }, { kw: 'third party', w: 10 },
    { kw: 'retain', w: 6 }, { kw: 'indefinite', w: 10 }, { kw: 'location', w: 8 },
    { kw: 'tracking', w: 10 }, { kw: 'cookie', w: 5 }, { kw: 'children', w: 15 },
    { kw: 'ai model', w: 12 }, { kw: 'train', w: 8 }, { kw: 'combine', w: 6 },
    { kw: 'affiliate', w: 4 }, { kw: 'advertis', w: 8 }
  ];
  let score = 0;
  for (const { kw, w } of weights) {
    const count = (t.match(new RegExp(kw, 'g')) || []).length;
    score += Math.min(count, 3) * w;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

function sentenceSplit(text) {
  return (text.replace(/\s+/g, ' ').match(/[^.!?]+[.!?]/g) || []).map(s => s.trim());
}

function extractCitations(text) {
  const sentences = sentenceSplit(text);
  const keys = ['sell', 'share', 'third party', 'retain', 'indefinite', 'children', 'location', 'advertis', 'ai model', 'train', 'tracking'];
  const cites = [];
  for (let i = 0; i < sentences.length; i++) {
    const s = sentences[i];
    const ls = s.toLowerCase();
    if (keys.some(k => ls.includes(k))) {
      cites.push({ text: s, idx: i });
      if (cites.length >= 12) break;
    }
  }
  return cites;
}

function recommendedActions(text) {
  const actions = [];
  const t = text.toLowerCase();
  if (t.includes('sell')) actions.push('Opt out of sale/sharing of personal data (see policy instructions).');
  if (t.includes('advertis')) actions.push('Disable ad personalization in your account settings.');
  if (t.includes('location')) actions.push('Turn off precise location access unless strictly needed.');
  if (t.includes('retain') || t.includes('indefinite')) actions.push('Request data deletion or set auto-delete where available.');
  if (t.includes('children')) actions.push('Review child/teen privacy controls and consent settings.');
  if (t.includes('third party')) actions.push('Limit third-party integrations; review connected apps.');
  if (!actions.length) actions.push('Review your privacy settings and enable 2FA on your account.');
  return actions;
}

async function llmAnalysis(text) {
  const key = process.env.OPENAI_API_KEY;
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
  if (!key) return null;

  const prompt = `You are a privacy-policy analyst. Analyze the policy and return JSON with fields:
  summary (120-180 words, plain-English), bullets (6-10 short items).
  JSON only. Policy: "${text.slice(0, 8000)}"`;

  try {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], temperature: 0.2 })
    });
    if (!r.ok) throw new Error(`OpenAI ${r.status}`);
    const data = await r.json();
    const content = data.choices?.[0]?.message?.content || '';
    const start = content.indexOf('{');
    const end = content.lastIndexOf('}');
    if (start >= 0 && end > start) return JSON.parse(content.slice(start, end + 1));
  } catch (e) { console.error('LLM analysis failed:', e.message); }
  return null;
}

// ---------- Public analyze endpoint ----------
app.post('/analyze', async (req, res) => {
  try {
    const parsed = AnalyzeReq.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
    const { text, url } = parsed.data;

    const risk = heuristicRiskScore(text);
    const citations = extractCitations(text);
    const actions = recommendedActions(text);
    const llm = await llmAnalysis(text);
    const summary = llm?.summary || 'This policy describes data collected, uses (service, analytics, ads), possible sharing with partners/third parties, and user rights (access, deletion, opt-out). Review the highlighted lines and consider the recommended actions.';

    res.json({ url, risk_score: risk, summary, citations, highlights: llm?.bullets || citations.map(c => c.text), actions });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Breach watch (HIBP) ----------
app.post('/breach/add', (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  const db = loadDb();
  if (!db.watchlist_emails.includes(email)) db.watchlist_emails.push(email);
  saveDb(db);
  res.json({ ok: true });
});

app.get('/breach/check', async (req, res) => {
  const db = loadDb();
  const out = [];
  const apiKey = process.env.HIBP_API_KEY;
  for (const email of db.watchlist_emails) {
    if (!apiKey) {
      out.push({ email, status: 'unknown', hint: 'Set HIBP_API_KEY to enable real breach checks.' });
    } else {
      try {
        const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`, {
          headers: { 'hibp-api-key': apiKey, 'User-Agent': 'PolicyTranslatorPro/0.2' }
        });
        if (r.status === 404) out.push({ email, status: 'clear' });
        else if (r.ok) out.push({ email, status: 'breached', details: await r.json() });
        else out.push({ email, status: 'error', code: r.status });
      } catch (e) {
        out.push({ email, status: 'error', message: e.message });
      }
    }
  }
  res.json({ results: out });
});

// ---------- Reports (HTML + PDF) ----------
function getMailer() {
  const { SMTP_HOST, SMTP_USER, SMTP_PASS, EMAIL_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !EMAIL_FROM) return null;
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: 587, secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  return { transporter, from: EMAIL_FROM };
}

app.get('/report/:id', (req, res) => {
  const db = loadDb();
  const item = db.analyses.find(a => a.id === req.params.id);
  if (!item) return res.status(404).send('Not found');
  const html = `<!doctype html>
  <html><head><meta charset="utf-8"><title>Privacy Report</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
    h1 { margin: 0 0 8px; }
    .meta { color:#666; font-size: 12px; margin-bottom: 12px; }
    .score { font-size: 28px; margin: 8px 0 12px; }
    ul { margin-top: 4px; }
    .box { border:1px solid #eaeaea; border-radius:8px; padding:12px; margin:12px 0; }
    .muted { color:#666; }
  </style>
  </head>
  <body>
    <h1>Privacy Policy Report</h1>
    <div class="meta">${item.url || ''}</div>
    <div class="score"><strong>Risk Score: ${item.risk_score ?? '-'}</strong> / 100</div>
    <div class="box"><h2>Summary</h2><p>${(item.summary || '').replace(/</g,'&lt;')}</p></div>
    <div class="box"><h3>Highlights</h3><ul>${(item.highlights||[]).map(h=>`<li>${(h.text||h||'').toString().replace(/</g,'&lt;')}</li>`).join('')}</ul></div>
    <div class="box"><h3>Recommended Actions</h3><ul>${(item.actions||[]).map(a=>`<li>${(a||'').toString().replace(/</g,'&lt;')}</li>`).join('')}</ul></div>
    <p class="muted">Generated at ${new Date().toLocaleString()}</p>
  </body></html>`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

app.get('/report/:id.pdf', async (req, res) => {
  try {
    const url = `${req.protocol}://${req.get('host')}/report/${req.params.id}`;
    const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="policy-report-${req.params.id}.pdf"`);
    res.send(pdfBuffer);
  } catch (e) {
    console.error('PDF export failed', e.message);
    res.status(500).json({ error: 'PDF export failed. Ensure puppeteer is installed.' });
  }
});

// ---------- Provider audits ----------
const PROVIDER_AUDITS = {
  google: [
    { label: 'Review Google Dashboard', link: 'https://myaccount.google.com/' },
    { label: 'Ad Personalization Off', link: 'https://myadcenter.google.com/personalization' },
    { label: 'Web & App Activity Off / Auto-Delete 3 months', link: 'https://myactivity.google.com/activitycontrols' },
    { label: 'Location History Off', link: 'https://myaccount.google.com/activitycontrols/location' },
    { label: 'YouTube History Off', link: 'https://myaccount.google.com/activitycontrols/youtube' },
    { label: 'Third-party app access review', link: 'https://myaccount.google.com/permissions' },
    { label: '2FA/Passkeys Enable', link: 'https://myaccount.google.com/signinoptions/two-step-verification' }
  ],
  instagram: [
    { label: 'Private Account', link: 'https://www.instagram.com/accounts/privacy_and_security/' },
    { label: 'Limit Ad Topics', link: 'https://www.facebook.com/adpreferences/ad_settings' },
    { label: 'Activity Status Off', link: 'https://www.instagram.com/accounts/activity_status/' },
    { label: 'Location Permissions (OS-level)', link: '' },
    { label: 'Connected Apps Review', link: 'https://www.instagram.com/accounts/manage_access/' },
    { label: 'Two-Factor Authentication', link: 'https://www.instagram.com/accounts/password/change/' }
  ]
};
const PROVIDER_AUDITS_EXT = {
  facebook: [
    { label: 'Privacy Checkup', link: 'https://www.facebook.com/privacy/checkup' },
    { label: 'Ad Preferences', link: 'https://www.facebook.com/adpreferences' },
    { label: 'Off-Facebook Activity', link: 'https://www.facebook.com/off_facebook_activity/' },
    { label: 'Face Recognition Off', link: 'https://www.facebook.com/settings?tab=face_recognition' },
    { label: 'Two-Factor Authentication', link: 'https://www.facebook.com/security/2fac/settings/' }
  ],
  tiktok: [
    { label: 'Personalization & Data', link: 'https://www.tiktok.com/setting' },
    { label: 'Ad Settings', link: 'https://www.tiktok.com/settings/ads' },
    { label: 'Download Your Data', link: 'https://www.tiktok.com/privacy/setting/download-your-data' },
    { label: 'Two-Step Verification', link: 'https://www.tiktok.com/setting' }
  ],
  x: [
    { label: 'Privacy & Safety', link: 'https://x.com/settings/privacy_and_safety' },
    { label: 'Personalization & Data', link: 'https://x.com/settings/your_twitter_data' },
    { label: 'Two-Factor Authentication', link: 'https://x.com/settings/security' }
  ],
  linkedin: [
    { label: 'Data Privacy', link: 'https://www.linkedin.com/psettings/data-privacy' },
    { label: 'Advertising data', link: 'https://www.linkedin.com/psettings/advertising' },
    { label: 'Sign in & security', link: 'https://www.linkedin.com/psettings/' }
  ]
};

app.get('/audit/providers', (req, res) => {
  res.json({ providers: [...Object.keys(PROVIDER_AUDITS), ...Object.keys(PROVIDER_AUDITS_EXT)] });
});
app.get('/audit/:provider', (req, res) => {
  const list = PROVIDER_AUDITS[req.params.provider] || PROVIDER_AUDITS_EXT[req.params.provider];
  if (!list) return res.status(404).json({ error: 'Unknown provider' });
  res.json({ provider: req.params.provider, checklist: list });
});

// ---------- Auth + encrypted saves ----------
function initUsers(db) { if (!db.users) db.users = []; if (!db.analyses) db.analyses = []; return db; }
function findUserByEmail(db, email) { return (db.users || []).find(u => u.email.toLowerCase() === email.toLowerCase()); }
function createToken(user) {
  const secret = process.env.JWT_SECRET || 'dev_secret_change_me';
  return jwt.sign({ uid: user.id, email: user.email }, secret, { expiresIn: '30d' });
}
function verifyToken(token) {
  try {
    const secret = process.env.JWT_SECRET || 'dev_secret_change_me';
    return jwt.verify(token, secret);
  } catch { return null; }
}

const AuthRegisterReq = z.object({ email: z.string().email(), password: z.string().min(8) });
const AuthLoginReq = z.object({ email: z.string().email(), password: z.string().min(8) });

app.post('/auth/register', (req, res) => {
  const parsed = AuthRegisterReq.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const { email, password } = parsed.data;
  const db = loadDb(); initUsers(db);
  if (findUserByEmail(db, email)) return res.status(409).json({ error: 'Email already registered' });
  const id = nanoid(10);
  const hash = bcrypt.hashSync(password, 10);
  db.users.push({ id, email, password_hash: hash, created_at: new Date().toISOString(), alerts: { email_enabled: false } });
  saveDb(db);
  const token = createToken({ id, email });
  res.json({ token, uid: id, email });
});

app.post('/auth/login', (req, res) => {
  const parsed = AuthLoginReq.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const { email, password } = parsed.data;
  const db = loadDb(); initUsers(db);
  const user = findUserByEmail(db, email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = createToken({ id: user.id, email: user.email });
  res.json({ token, uid: user.id, email: user.email });
});

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const m = /^Bearer (.+)$/.exec(h);
  if (!m) return res.status(401).json({ error: 'Missing token' });
  const payload = verifyToken(m[1]);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  req.user = payload;
  next();
}

const SaveReq = z.object({
  url: z.string().optional(),
  enc: z.object({ cipherText: z.string(), iv: z.string(), salt: z.string() })
});

app.post('/save', authMiddleware, (req, res) => {
  const parsed = SaveReq.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const db = loadDb(); initUsers(db);
  const item = {
    id: nanoid(10),
    uid: req.user.uid,
    url: parsed.data.url || null,
    enc: parsed.data.enc,
    created_at: new Date().toISOString(),
    updated_at: null
  };
  db.analyses.unshift(item);
  saveDb(db);
  res.json({ ok: true, id: item.id });
});

app.get('/list', authMiddleware, (req, res) => {
  const db = loadDb(); initUsers(db);
  const items = db.analyses.filter(a => a.uid === req.user.uid);
  res.json({ items });
});

app.delete('/delete/:id', authMiddleware, (req, res) => {
  const db = loadDb(); initUsers(db);
  const id = req.params.id;
  db.analyses = db.analyses.filter(a => !(a.id === id && a.uid === req.user.uid));
  saveDb(db);
  res.json({ ok: true });
});

// Recheck: server computes fresh meta; client re-saves encrypted if desired
app.post('/recheck/:id', authMiddleware, async (req, res) => {
  const db = loadDb(); initUsers(db);
  const item = db.analyses.find(a => a.id === req.params.id && a.uid === req.user.uid);
  if (!item || !item.url) return res.status(404).json({ error: 'Not found' });
  try {
    const r = await fetch(item.url, { method: 'GET' });
    const html = await r.text();
    const text = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
                     .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
                     .replace(/<[^>]+>/g, ' ')
                     .replace(/\s+/g, ' ');
    const newRisk = heuristicRiskScore(text);
    const llm = await llmAnalysis(text);
    const cites = extractCitations(text);
    item.updated_at = new Date().toISOString();
    item.meta = { url: item.url, risk_score: newRisk, summary: llm?.summary || null, citations: cites.map(c=>c.text).slice(0,6) };
    saveDb(db);
    res.json({ ok: true, meta: item.meta });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Fetch failed' });
  }
});

// Alerts: toggle & background monitor with email
app.post('/alerts/email', authMiddleware, (req, res) => {
  const db = loadDb(); initUsers(db);
  const u = db.users.find(x => x.id === req.user.uid);
  if (!u) return res.status(404).json({ error: 'User not found' });
  u.alerts = { email_enabled: !!req.body?.enabled };
  saveDb(db);
  res.json({ ok: true, alerts: u.alerts });
});

const RISK_DELTA_NOTIFY = 10;
async function sendEmail(to, subject, html) {
  const m = getMailer();
  if (!m) return false;
  try {
    await m.transporter.sendMail({ from: m.from, to, subject, html });
    return true;
  } catch (e) { console.error('Email send failed', e.message); return false; }
}

async function backgroundRecheckAllWithAlerts() {
  const db = loadDb(); initUsers(db);
  const changes = [];
  for (const it of db.analyses) {
    if (!it.url) continue;
    try {
      const r = await fetch(it.url, { method: 'GET' });
      const html = await r.text();
      const text = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
                       .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
                       .replace(/<[^>]+>/g, ' ')
                       .replace(/\s+/g, ' ');
      const newRisk = heuristicRiskScore(text);
      const oldRisk = it.meta?.risk_score ?? newRisk;
      const delta = newRisk - oldRisk;
      if (Math.abs(delta) >= RISK_DELTA_NOTIFY) {
        const cites = extractCitations(text);
        const llm = await llmAnalysis(text);
        it.meta = { url: it.url, risk_score: newRisk, summary: llm?.summary || null, citations: cites.map(c=>c.text).slice(0,6) };
        it.updated_at = new Date().toISOString();
        changes.push({ uid: it.uid, url: it.url, newRisk, oldRisk, summary: it.meta.summary });
      }
    } catch { /* ignore per-item errors */ }
  }
  saveDb(db);
  for (const ch of changes) {
    const user = db.users.find(u => u.id === ch.uid);
    if (!user || !user.alerts?.email_enabled) continue;
    await sendEmail(
      user.email,
      'Policy risk changed',
      `<p>The policy at <a href="${ch.url}">${ch.url}</a> changed risk from <b>${ch.oldRisk}</b> to <b>${ch.newRisk}</b>.</p><p>${(ch.summary||'')}</p>`
    );
  }
}
setInterval(backgroundRecheckAllWithAlerts, 1000 * 60 * 60 * 6);
app.get('/monitor/run-alerts', async (req, res) => { await backgroundRecheckAllWithAlerts(); res.json({ ok: true }); });

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Policy Translator Pro server on http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard`);
});

