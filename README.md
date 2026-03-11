# NamBank Biometric Authentication System
### HCI711S Lab 1 — Production Deployment Guide

**Live URL (after deploy):** `https://nambank.up.railway.app` — or your own custom domain

---

## Architecture

```
Browser (any device)
    │  HTTPS
    ▼
Railway.app  ──────────────────────────────────────────
│  Node.js + Express server (always-on, no sleep)     │
│  SimpleWebAuthn — proper FIDO2 verification         │
│  Auto HTTPS certificate (Let's Encrypt)             │
└──────────────────── MongoDB Atlas ──────────────────
                       Free M0 cluster
                       Persistent — data never resets
                       Encrypted at rest
```

---

## Step 1 — MongoDB Atlas (free persistent database)

1. Go to **https://mongodb.com/atlas** → Sign Up Free
2. Create a **free M0 cluster** (Shared tier — always free)
   - Provider: AWS, Region: pick closest to Namibia (e.g. eu-west-1 Ireland)
3. **Create a Database User**
   - Username: `nambank`  Password: make a strong one, **save it**
   - Role: Atlas admin (or readWriteAnyDatabase)
4. **Network Access** → Add IP Address → Allow Access from Anywhere → `0.0.0.0/0`
   - (Railway's IP changes so we allow all — the password protects access)
5. **Connect** → Drivers → Node.js → copy the connection string
6. Replace `<password>` in the string with your password
   - Final string looks like:
     `mongodb+srv://nambank:YOUR_PASSWORD@cluster0.abc12.mongodb.net/?retryWrites=true&w=majority`
7. **Save this string** — you paste it into Railway in Step 3

---

## Step 2 — Push to GitHub

You already have a GitHub account. Do this once:

```bash
# In the nambank-cloud folder:
git init
git add .
git commit -m "NamBank biometric system v3.0"

# Create a new repo on github.com named: nambank-biometric
# Then:
git remote add origin https://github.com/YOUR_USERNAME/nambank-biometric.git
git branch -M main
git push -u origin main
```

Every future `git push` automatically re-deploys via GitHub Actions.

---

## Step 3 — Deploy to Railway

Railway is the best free option for a professional, always-on URL.
Unlike Render, **Railway never sleeps your app** on the free tier (500 hours/month free).

1. Go to **https://railway.app** → Login with GitHub
2. Click **New Project** → **Deploy from GitHub repo**
3. Select your `nambank-biometric` repository
4. Railway detects Node.js automatically and starts deploying
5. Click the project → **Variables** tab → Add these:

| Variable | Value |
|---|---|
| `MONGODB_URI` | your Atlas connection string from Step 1 |
| `RP_NAME` | `NamBank Financial Services` |
| `NODE_ENV` | `production` |

6. Go to **Settings** tab → **Domains** → **Generate Domain**
   - You get: `https://nambank-biometric.up.railway.app`
   - This is your permanent, always-on HTTPS URL ✅

7. Wait ~2 minutes for the build → your app is live

---

## Step 4 — Custom Domain (optional but professional)

You can point any domain you own to Railway for free.

### Option A — Free domain from Freenom
1. Go to **https://freenom.com**
2. Search for `nambank` → check `.tk`, `.ml`, `.ga`, `.cf` (all free)
3. Register `nambank.tk` or `nambank-auth.tk` for free (12 months)
4. In Railway → Settings → Domains → **Add Custom Domain**
   - Enter: `nambank.tk`
   - Railway shows you a CNAME record to add
5. In Freenom DNS Management:
   - Add CNAME record: `@` → `[your-railway-url].up.railway.app`
   - TTL: 300
6. Wait 5-15 minutes for DNS to propagate
7. Railway auto-provisions HTTPS certificate → `https://nambank.tk` is live ✅

### Option B — Cloudflare (most professional, free)
If you want `https://nambank.yourdomain.com` with Cloudflare's CDN:
1. Register a domain at Cloudflare Registrar (at-cost, ~$8/year for .com)
   - Or: transfer any existing domain to Cloudflare
2. Add a CNAME record in Cloudflare DNS:
   - Name: `nambank` (or `@` for root)
   - Target: `[your-railway-url].up.railway.app`
   - Proxy: ON (orange cloud) — enables Cloudflare CDN + DDoS protection
3. In Railway → Custom Domain → add your domain → copy the CNAME Railway gives
4. SSL/TLS in Cloudflare → Full (strict)
5. Done: `https://nambank.yourdomain.com` ✅

---

## Step 5 — Set Up GitHub Actions Auto-Deploy

Railway auto-deploys from GitHub pushes already. The included Actions workflow
(`.github/workflows/deploy.yml`) adds a test step first — it boots the server
and checks the health endpoint before deploying.

To enable it:
1. In Railway → Settings → **Generate API Token** → copy it
2. In GitHub repo → Settings → Secrets → **New repository secret**
   - Name: `RAILWAY_TOKEN`
   - Value: paste your Railway token
3. Done — every `git push main` now: tests → deploys automatically

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `MONGODB_URI` | ✅ For persistence | MongoDB Atlas connection string |
| `RP_NAME` | Optional | Display name in WebAuthn prompts (default: NamBank Financial Services) |
| `RP_ID` | Optional | Override rpID if using custom domain (default: auto-detected from Host header) |
| `NODE_ENV` | Optional | Set to `production` to enable HSTS headers |
| `PORT` | Auto-set | Railway sets this automatically — do not override |

---

## WebAuthn Domain Binding — Important

WebAuthn credentials are **cryptographically bound to the exact domain** they were enrolled on.

- Credentials enrolled on `localhost` → **only work on `localhost`**
- Credentials enrolled on `nambank-biometric.up.railway.app` → **only work on that domain**
- If you add a custom domain like `nambank.tk` → **re-enrol on that domain**

This is a security feature, not a bug. It means phishing sites on different domains cannot use your credentials.

**For the demo:**
1. Deploy to Railway → get your URL
2. Open that URL → enrol your fingerprint there
3. That credential works permanently on that URL from any device

---

## API Endpoints

| Endpoint | Method | Rate Limit | Description |
|---|---|---|---|
| `/api/enroll/start` | POST | 10/min | Begin fingerprint enrolment |
| `/api/enroll/finish` | POST | 10/min | Complete enrolment |
| `/api/auth/start` | POST | 20/min | Begin authentication |
| `/api/auth/finish` | POST | 20/min | Verify fingerprint |
| `/api/database-view` | GET | — | Live database view (lecturer demo) |
| `/api/audit-log` | GET | — | Authentication event log |
| `/api/status` | GET | — | Server health + config |

---

## Local Development

```bash
npm install
node server/server.js
# Open http://localhost:3000
# Works without MONGODB_URI (uses in-memory storage)
```
