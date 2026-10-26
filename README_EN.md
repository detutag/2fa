# 2FA Authenticator

[正體中文文件](./README.md)

A cloud-based 2FA authenticator supporting both Cloudflare Workers and Docker deployment.

## Features

- **TOTP / HOTP Generation**: Compatible with Google Authenticator, Authy, and other standard protocols; custom digits (6/7/8), period (seconds), algorithm (SHA-1/256/512) and HOTP counters
- **Universal Import**: Aegis, 2FAS, Ente Auth, Bitwarden, FreeOTP, Raivo, OTP Auth (iOS), Google Authenticator migration data (`otpauth-migration://`), `otpauth://` URI lists and native JSON backups — with a preview checklist that flags duplicates and invalid entries
- **Export**: JSON backup (all parameters preserved) or generic `otpauth://` URI list (.txt) for migration to other apps
- **Cloud Sync**: Data stored in Cloudflare KV, accessible across devices
- **End-to-End Encryption**: AES-256-GCM encryption, server only stores ciphertext
- **Zero Registration**: No email/phone required, create account with just a master password
- **Remember Login**: Login state persists across browser restarts (opt-out), with configurable idle auto-lock (15 min – 7 days / never, default 24 h)
- **PWA Support**: Install to desktop/home screen for native app experience
- **Offline Access**: Full offline support after first login, data cached for 7 days
- **QR Code Scanning**: Support camera scanning, image upload, and clipboard paste to recognize QR codes (including batch migration QR codes)
- **Themes**: Light / dark / follow system, remembered per device
- **Privacy Mode**: Blur on-screen codes; clipboard auto-clear option (60 s)
- **Drag & Drop Reorder**: Reorder keys on desktop
- **Hardened Security**: Strict CSP (no inline scripts), login throttling, API key-format validation and payload size limits, optional rate limiting, full security headers

## Architecture

Two deployment methods supported:

**Cloudflare Workers Deployment**:
```
Browser <--HTTPS--> Cloudflare Worker <--KV API--> KV Storage
```

**Docker Deployment**:
```
Browser <--HTTP/HTTPS--> Express Server <--SQLite--> Local Database
```

**Security Design**:
| Aspect | Measure |
|--------|---------|
| Data Encryption | AES-256-GCM, encrypted on client before transmission |
| Key Derivation | PBKDF2-SHA256, 600,000 iterations |
| User Identification | Password hash (PBKDF2) |
| Frontend Security | Strict CSP (`script-src 'self'` + hash), no inline event handlers |
| API Protection | Key format validation (64-hex), payload size limits, optional rate-limit binding |
| CORS | Same-origin only (opt-in `ALLOWED_ORIGIN` for specific origins) |
| Login Protection | Exponential backoff lockout after 5 failed attempts (30 s up to 5 min) |
| Headers | CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy |

## Command Quick Reference

| Target | Build command | Deploy / start command | Notes |
|--------|--------------|------------------------|-------|
| Cloudflare Workers (Wrangler) | None (pure static + Worker) | `wrangler deploy` | Local testing: `wrangler dev` |
| Cloudflare dashboard (Git-connected) | Leave empty (optional field) | Deploy command defaults to `npx wrangler deploy` | See Method 3; redeploys on push |
| Docker | `docker build -t 2fa .` | `docker compose up -d` or `docker run …` | Or pull the prebuilt image `l981244680/2fa` |
| Local Node (Docker-version backend) | `npm install` | `npm start` | Dev hot-reload: `npm run dev` |
| Regression tests | — | `npm test` | Node ≥ 18 |

## Deployment Guide

### Method 1: Docker Deployment (Recommended)

Prerequisites: Install [Docker](https://docs.docker.com/get-docker/)

#### Using Docker Run

```bash
docker run -d \
  --name 2fa-auth \
  -p 3000:3000 \
  -v 2fa-data:/app/data \
  l981244680/2fa:latest

# Visit http://localhost:3000
```

#### Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
services:
  2fa:
    image: l981244680/2fa:latest
    container_name: 2fa-authenticator
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

Then run:

```bash
docker compose up -d
```

#### Build from Source

```bash
# build command
docker build -t 2fa .

# deploy / start command
docker run -d \
  --name 2fa-auth \
  -p 3000:3000 \
  -v 2fa-data:/app/data \
  2fa
```

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | HTTP service port |
| `DB_PATH` | `/app/data/2fa.db` | SQLite database path |

### Method 2: Cloudflare Workers Deployment

#### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Cloudflare Account](https://dash.cloudflare.com/sign-up)

#### Step 1: Install Wrangler CLI

```bash
npm install -g wrangler
```

#### Step 2: Login to Cloudflare

```bash
wrangler login
```

#### Step 3: KV Namespace (Optional)

If `wrangler.toml` only sets `binding` (no `id`), wrangler will auto-provision (or reuse) the KV namespace on the first `wrangler deploy`, and subsequent deploys will still bind to the same KV. So you can skip this step by default.

If you want to create it manually (for example, to pin/reuse an existing KV), run:

```bash
# Navigate to project directory
cd 2fa

# Create production KV
wrangler kv namespace create DATA_KV
# Output like: { binding = "DATA_KV", id = "xxxxxxxxxxxx" }

# Create preview KV (Optional)
wrangler kv namespace create DATA_KV --preview
# Output like: { binding = "DATA_KV", preview_id = "yyyyyyyyyyyy" }
```

#### Step 4: Configure wrangler.toml

- Auto provisioning: keep `[[kv_namespaces]]` with only `binding` and run `wrangler deploy`; Wrangler will auto-provision/reuse KV (and won't modify `wrangler.toml`).
- Manual: fill the `id` / `preview_id` from the previous step into `wrangler.toml`:

```toml
name = "2fa-sync"
main = "worker.js"
compatibility_date = "2024-01-01"
assets = { directory = "./public" }

[[kv_namespaces]]
binding = "DATA_KV"
id = "xxxxxxxxxxxx"        # Replace with your id
preview_id = "yyyyyyyyyyyy" # Replace with your preview_id
```

#### Step 5: Local Testing (Optional)

```bash
wrangler dev
# Visit http://localhost:8787
```

#### Step 6: Deploy

```bash
wrangler deploy
# Output like: Published 2fa-sync (https://2fa-sync.xxx.workers.dev)
```

After deployment, visit the output URL to start using.

### Method 3: Cloudflare Dashboard Deployment (Git-connected, no local Wrangler)

For deployments entirely from the Cloudflare dashboard, without installing Wrangler or running your own CI:

1. In the [Cloudflare dashboard](https://dash.cloudflare.com/), go to **Workers & Pages** → **Create application**
2. Choose **Import an existing Git repository** (connect GitHub/GitLab) and select this repository
3. Fill in the build settings (under the Worker's **Settings → Build**):
   - **Branch**: `main`
   - **Root directory**: leave empty (repository root, where `wrangler.toml` lives)
   - **Build command**: **leave empty**. This field is optional and only needed for frameworks with a compile step (Next.js, Astro, …); this project is pure static files + a plain JS Worker with no build step. If the dashboard prefills a default (e.g. `npm run build`), clear it — or keep it: the `build` script in package.json is a no-op echo, so it cannot fail
   - **Deploy command**: keep the default `npx wrangler deploy`. This is the step that actually deploys: wrangler reads `wrangler.toml` and uploads the `public/` static assets plus the Worker script; the Wrangler version follows `devDependencies` in package.json (pinned to `^4.59.1`)
   - The dashboard reads `wrangler.toml` from the repository automatically: assets directory (`public/`), KV bindings, etc.; KV namespaces declared without an `id` are created and bound on first deploy (the API token auto-generated by Workers Builds already includes KV edit permissions)
4. Click **Deploy**, wait for the build to finish, then visit the assigned `*.workers.dev` subdomain
5. Every subsequent push to `main` triggers a new dashboard build and deployment (Cloudflare's own CI, independent of GitHub Actions)
6. Optional:
   - **Custom domain**: Worker page → Settings → Domains & Routes
   - **Manual KV**: Workers & Pages → KV → create a namespace → paste its ID into `[[kv_namespaces]] id` in `wrangler.toml` (auto-created if left empty)
   - **Rate limiting**: the `[[ratelimits]]` binding in `wrangler.toml` (`API_RATE_LIMITER`, `namespace_id = "1001"`, 100 requests per IP per 60 s) is enabled by default; comment that block out if your environment does not support the Rate Limiting API (all other protections remain)
   - **Worker name**: dashboard Builds deploys to the Worker created under the project name (repo name `2fa`); `wrangler.toml` sets `name = "2fa"` so local CLI, GitHub Actions and the dashboard all deploy the same Worker
   - **Reusing old KV data**: if a previously deployed Worker holds your encrypted vault and you want to keep it, copy its KV namespace ID (dashboard: Workers & Pages → old Worker → Settings → Bindings, or the KV page) into `[[kv_namespaces]] id` in `wrangler.toml`; leaving it empty auto-creates a brand-new KV (old data will not carry over)

> Note: if the repository's GitHub Actions workflow (`deploy-worker.yml`) is also active, both pipelines deploy the same Worker name (`2fa-sync`) and overwrite each other — keep only one.

## GitHub Actions Auto Deploy (Optional)

This repository includes an automatic deployment workflow for the Cloudflare Worker:

- Deploy Cloudflare Worker: `.github/workflows/deploy-worker.yml` — deploys the Worker on push to `main` or via manual dispatch. Requires the repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

## Usage Guide

### First Time Setup (Create Account)

1. Visit the deployed URL
2. Click "First time? Create account"
3. Set a master password (at least 8 characters, with letters and digits; a strength meter is shown)
4. Confirm password and click "Set Password"

### Login

1. Enter master password
2. Optionally check "Remember login" (default on)
3. Click "Unlock"

### Add 2FA Key

Click the "+" button in the top right, three methods available:

**Manual Input**:
1. Enter a name (e.g., GitHub)
2. Enter the Base32 format secret key
3. Click "Add"

**Scan QR Code**:
1. Switch to "Scan" tab
2. Click "Start Camera"
3. Point the QR code at the camera, auto-fills when recognized

**Upload Image**:
1. Switch to "Upload" tab
2. Click to select, drag and drop, or paste a screenshot
3. Auto-fills when recognized

### Use Verification Code

- Click the code to copy to clipboard
- The ring on the right shows remaining valid time (30-second cycle)

### Logout

Click the logout button in the top left to clear current session and return to login page.

### Import / Export

**Import** (click "Import", pick a .json or .txt backup):

| Source app | Format |
|------------|--------|
| This app | Native JSON v1/v2 |
| Aegis Authenticator | Plain (unencrypted) JSON backup |
| 2FAS Authenticator | Plain (unencrypted) JSON backup |
| Ente Auth | JSON backup |
| Bitwarden | JSON export (with TOTP fields) |
| FreeOTP / FreeOTP+ | JSON backup |
| Raivo OTP | JSON backup |
| OTP Auth (iOS) | JSON backup |
| Google Authenticator | Migration data (`otpauth-migration://`, incl. QR scan) |
| Generic | `otpauth://` URI list (one per line) |

A preview checklist appears before importing: select entries, duplicates and invalid items are flagged automatically. Encrypted backups (Aegis/2FAS encrypted exports) are detected with a clear hint to export plaintext instead.

**Export** (click "Export", choose a format):

| Format | Compatible with |
|--------|-----------------|
| Native JSON backup (v2) | Round-trip into this app with all parameters (digits, period, algorithm, HOTP counter) |
| otpauth URI list (.txt) | De-facto universal standard: Aegis / Ente "Plain text" import, any URI-capable tool, or per-line QR conversion |
| Aegis-compatible JSON | Aegis "Import → Aegis" accepts the file directly (plaintext format) |
| 2FAS-compatible JSON | 2FAS "Import from other apps → 2FAS" accepts the file directly |

> ⚠ All exports are plaintext — store them safely and delete after use.

## Important Notes

1. **Password Cannot Be Recovered**: Forgetting password means losing all data - remember your master password
2. **Password = Account**: Same password = same account, use the same password on different devices to sync data
3. **Session**: With "Remember login" checked (default), closing and reopening the browser does not require re-login; the idle auto-lock (default 24 h, configurable) requires the password again after inactivity
4. **Offline Mode**: First login requires internet, then works offline (cache valid for 7 days)
5. **Data Sync**: Offline changes sync automatically when online; conflicts prompt user to choose

## Project Structure

```
2fa/
├── .github/
│   └── workflows/
│       ├── deploy-worker.yml   # Deploy Cloudflare Worker
│       └── docker-publish.yml  # Build/push Docker image
├── public/
│   ├── icons/           # PWA icons
│   ├── index.html       # Frontend
│   ├── manifest.json    # PWA manifest
│   └── service-worker.js # Service Worker (offline cache)
├── src/
│   └── server.js        # Express server for Docker deployment
├── worker.js            # Cloudflare Worker
├── wrangler.toml        # Wrangler configuration
├── Dockerfile           # Docker image definition
├── docker-compose.yml   # Docker Compose configuration
├── package.json         # npm dependencies
└── README.md            # Documentation
```

## License

MIT
