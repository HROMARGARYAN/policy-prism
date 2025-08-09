
# Deploying Policy Translator Pro (v4)

## Option A: Docker (local or any VM)
1) Ensure Docker is installed.
2) From the project root:
   ```bash
   docker compose up --build -d
   ```
3) App runs on http://localhost:8788 (Dashboard at /dashboard). The `server/data` folder is persisted.

## Option B: Render.com (one-click)
1) Create a Render account.
2) New -> Blueprint -> connect this repo or upload.
3) Use `render.yaml`. Set env vars in the UI (OPENAI_API_KEY, JWT_SECRET, etc.).
4) Deploy. Health check path: `/dashboard`.

## Option C: Fly.io
1) `flyctl launch` (it will use `fly.toml`) -> deploy.
2) Set secrets:
   ```bash
   flyctl secrets set OPENAI_API_KEY=... JWT_SECRET=...
   ```

## Option D: Heroku
1) `heroku create`
2) `git push heroku main`
3) `heroku config:set OPENAI_API_KEY=... JWT_SECRET=...`
4) Open the app; the server runs in `server/` per `Procfile`.

## Environment Variables (must set in production)
- `JWT_SECRET` (required): random long string
- `OPENAI_API_KEY` (optional): for richer summaries
- `HIBP_API_KEY` (optional): for breach checks
- `SMTP_HOST, SMTP_USER, SMTP_PASS, EMAIL_FROM` (optional): for email alerts
- `PORT` (defaults to 8788)

## Security Notes
- Client-side encryption keeps saved analyses encrypted end-to-end. Do not send passwords to the server.
- For high security, consider rotating salts per-user and storing only a local key-handle.
- Use HTTPS in production.

## Post-Deploy
- Visit `/dashboard` to register/login.
- Load the Chrome extension and point Backend URL to your deployed domain.
- Start analyzing & saving encrypted reports. Export PDFs as needed.
