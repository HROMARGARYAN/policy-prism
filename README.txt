# Policy Translator Pro (v1)

**What’s new vs MVP:**
- Inline **citations** and on-page **highlights** in the extension
- Save, list, delete analyses — plus **re-check** a policy for changes
- Simple **Dashboard** at `/dashboard`
- **Breach Watch** stubs (real checks via HaveIBeenPwned if you add `HIBP_API_KEY`)

## Quick Start

### 1) Run the server
```
cd server
cp .env.example .env
# (optional) add OPENAI_API_KEY for LLM summaries
# (optional) add HIBP_API_KEY for real breach checks
npm install
npm start
```
Server: http://localhost:8788
Dashboard: http://localhost:8788/dashboard

### 2) Load the extension
- Open Chrome → `chrome://extensions` → Developer mode
- **Load unpacked** → select the `extension/` folder
- Click the extension → set **Backend URL** to `http://localhost:8788`
- Open a Privacy Policy page → **Analyze this page** → **Toggle citations** to highlight lines
- **Save analysis** → view it on the Dashboard

## Notes
- Storage uses a simple `data/db.json`. In production, replace with a database.
- Without API keys: heuristics still work (risk score, highlights, actions).

## Roadmap (suggested next)
- OAuth sign-in and encrypted vault (E2E) for user-specific data
- Provider “Audit Flows” with deep links (Google, Instagram, etc.)
- Background policy-change monitor (cron) + email notifications
- Export/share report (PDF) with citations
- Accessibility and internationalization


---
## Pro v2 Additions
- **PDF Export:** `/report/:id` (HTML) and `/report/:id.pdf` (requires `puppeteer`)
- **Background Change Monitor:** auto re-checks saved policies every 6 hours; manual trigger at `/monitor/run`
- **Provider Audits:** `/audit/providers` and `/audit/:provider` + Dashboard UI with deep links for Google and Instagram
- **Email plumbing ready:** nodemailer added for future alerts (configure SMTP in `.env` if you want to extend)

### Extra setup
- In `server/`: `npm install` will now fetch `puppeteer` (first install can take a few minutes).

### Notes
- PDF endpoint uses a headless Chromium via Puppeteer; if your environment restricts it, the HTML report at `/report/:id` still works.
- Background monitor is naive but effective for prototypes (risk delta + summary snippet change). For production, consider diffing the DOM and stricter thresholds.


---
## Pro v3 Additions
- **Accounts**: /auth/register, /auth/login (JWT). User‑scoped saved items.
- **Client‑side encryption**: extension & dashboard encrypt saved analyses with AES‑GCM (PBKDF2 key). Server stores ciphertext only.
- **Email alerts**: opt‑in; risk‑change notifications (configure SMTP in .env).
- **Expanded audits**: Facebook, TikTok, X, LinkedIn added.
- **Data request letters**: /letters/generate (CCPA/GDPR; access/delete/opt‑out).

### Setup notes
- After `npm install`, run `npm start`. Visit `/dashboard`, log in (or register), then use the extension to save encrypted analyses.
- For alerts, set SMTP_* and EMAIL_FROM in `.env`. For breach checks, set `HIBP_API_KEY`.
- E2E caveat: This prototype prompts for your password in the extension at save time to derive the key. In production, store only a local key handle (never transmit passwords).
