
# Sveltia CMS custom auth with Cloudflare Worker

This repo includes `workers/cms-auth/worker.js` to authenticate Sveltia CMS using:

- Google Sign-In (allowlisted Gmail/email accounts)
- Email/password (allowlisted users with SHA-256 password hashes)

No database is required. The Worker returns a GitHub PAT to Sveltia only after successful auth.

## 1) Configure CMS backend endpoint

In `public/admin/config.yml`:

```yml
backend:
  name: github
  repo: Novatra-Studios/N-S-Mehta-Associates-Site
  branch: master

  base_url: https://cms-auth.YOUR_SUBDOMAIN.workers.dev
  auth_endpoint: /auth
```

Replace `YOUR_SUBDOMAIN` after deploying the Worker.

## 2) Set Worker secrets/vars

Deploy-time required secret:

```bash
npx wrangler secret put GITHUB_PAT --config workers/cms-auth/wrangler.toml
```

Optional vars (add in Cloudflare dashboard Worker settings or via Wrangler):

- `GOOGLE_CLIENT_ID`: Google OAuth client ID used by GIS button.
- `GOOGLE_CLIENT_IDS`: Comma-separated accepted audience IDs (falls back to `GOOGLE_CLIENT_ID`).
- `ALLOWED_GOOGLE_EMAILS`: Comma-separated exact email allowlist for Google login.
- `EMAIL_PASSWORD_USERS`: Allowlist for email/password.
- `ALLOWED_DOMAINS`: Optional comma-separated site_id/domain allowlist for `/auth`.

`EMAIL_PASSWORD_USERS` accepted formats:

- JSON object: `{"editor@gmail.com":"<sha256_hex>"}`
- JSON array: `[{"email":"editor@gmail.com","passwordSha256":"<sha256_hex>"}]`
- CSV: `editor@gmail.com:<sha256_hex>,other@gmail.com:<sha256_hex>`

Generate SHA-256 hash:

```bash
node -e 'const c=require("crypto");console.log(c.createHash("sha256").update(process.argv[1]).digest("hex"))' "YourStrongPassword"
```

## 3) Deploy Worker

```bash
npm run deploy:google-sveltia-auth
```

## 4) Local test

```bash
npm run dev:google-sveltia-auth
```

Then test:

- `http://127.0.0.1:8787/auth?provider=github`
- `http://localhost:4321/admin`

## Notes

- Insight URLs are derived from markdown filenames.
- Field definitions for editors are in `public/admin/config.yml`.
