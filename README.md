# Keyhold — personal agent vault demo

A Go backend and React/TypeScript frontend demonstrating encrypted credential storage, passkey approval, and expiring agent access. Deploys as one Vercel Services application. **Use fake credentials only.**

## Try the demo

1. Create an account and passkey. Vault setup performs a second passkey ceremony to evaluate WebAuthn PRF.
2. Download the recovery key. It unlocks the vault after account sign-in; it does **not** recover a lost account/passkey.
3. Open **Credential vault** and add a fake username and password.
4. In **Personal agent**, choose the credential and an access duration. Ask to read your demo profile.
5. Open **Review access request**, review the scope, and approve with your passkey.
6. The backend completes the pending operation. Repeat it to reuse the grant; revoke it to require fresh approval.

The agent is a deterministic demonstration, not an LLM. Its single internal tool accepts a non-empty fake login and returns a mock profile. The approval link is displayed in chat; email/SMS delivery is not configured.

## Local development

Requirements: Go 1.26+, Node.js 24+, a Postgres database, and an HTTPS/localhost browser with a PRF-capable passkey provider. `go.mod` pins dependency versions; Go can download the required toolchain automatically.

```sh
make install
npx vercel link --project webauthn-demo --scope gramlius-projects
npx vercel env pull .env.local --yes
make migrate
make dev
```

Visit **http://localhost:5173** (use `localhost`, not `127.0.0.1`, to match the configured origin). The Go API runs on port 8080; Vite proxies `/api` to it.

For a standalone Postgres setup, put `DATABASE_URL` in `.env.local`. Migrations prefer `DATABASE_URL_UNPOOLED` when present. The backend explicitly loads the root `.env.development.local` and `.env.local` without overwriting existing process environment variables. These files are ignored by Git.

Optional overrides in `.env.development.local`:

```dotenv
APP_ORIGIN=http://localhost:5173
PORT=8080
EXECUTOR_PRIVATE_KEY=<base64-encoded PKCS8 RSA private key>
```

Local development can generate an ephemeral executor key if none is provided. **Persist a key if grants must survive local restarts.** Changing the executor key invalidates old grants and pending approval requests.

## Architecture

```text
Browser (React + TypeScript)
  WebAuthn user verification → PRF → HKDF-SHA256 wrapping key
  wrapping key → encrypted vault master key
  vault master key → wrapped per-credential keys
  per-credential key → AES-256-GCM credential ciphertext

Go API
  verifies WebAuthn signatures, UV, origin, RP ID, and stored single-use challenge
  stores opaque authentication sessions and pending approvals in Postgres
  receives only the approved credential key, wrapped to the executor public key
  checks the grant on each use → decrypts credential → runs the allowlisted tool
  returns a sanitized result and records an event
```

The browser never sends PRF output, the vault master key, or a raw password to the API. `webauthn.ts` explicitly serializes authentication proofs instead of using `credential.toJSON()`, which can include PRF secret output. Vault keys are held in memory as non-extractable `CryptoKey` objects; reloading locks the vault. JavaScript strings and runtime copies cannot be reliably erased; clearing byte buffers is best-effort hygiene, not a memory-isolation guarantee.

Delegation uses RSA-OAEP-SHA256. The OAEP label is the approval request ID, so a delegation envelope cannot be reused for another request. AES-GCM additional authenticated data binds credential ciphertext to its owner, item ID, and version. Grant records also constrain the agent, operation, destination, credential version, and executor key identity.

Approval requests expire after 10 minutes; passkey challenges after 5 minutes. Grants last 1 minute, 1 hour, or 24 hours starting at approval. Each use checks server time and revocation; a cleanup job is not required to enforce expiry. Revocation removes the current stored delegation envelope and blocks subsequent invocations. An operation already started cannot be undone.

**Expiry is a policy enforced by the trusted Go executor, not cryptographic erasure.** After delegation the executor can decrypt that credential. Its private key plus copied/backup delegation data could decrypt it later. This is not an adversarial-agent containment system or an end-to-end encrypted vault against a malicious hosting provider. The server delivers the browser JavaScript, so server compromise can also compromise browser unlocking.

## Database

Postgres stores accounts, hashed session tokens, hashed ceremony tokens with purpose/request bindings, and rate-limit buckets. Each account's encrypted vault items, approvals, grants, chat, and audit events form a JSONB aggregate locked with `SELECT ... FOR UPDATE`. This keeps approval and grant changes atomic for a small prototype without an ORM. Credentials are immutable after creation. The demo limits accounts to 20 items and 100 approval requests, and retains the most recent 100 chat messages and events.

Accounts are namespaced by their exact application origin, separating localhost and deployment hosts even when a demonstration database is shared. Each deployment environment has its own executor key. A production system should additionally use separate databases/branches, normalize the account aggregate, add comprehensive abuse protection, implement account/passkey recovery and credential rotation, and isolate tools from the agent runtime.

## Vercel deployment

`vercel.json` composes the Vite frontend and native Go API using **Vercel Services (beta)**. The original `/api` prefix reaches Go unchanged. Frontend deep links resolve to the SPA. Both deploy together under one URL.

The Go service's explicit build command disables VCS stamping because deployment filtering can remove Git metadata. Deployment and GitHub commit metadata still identify the release.

Required server-only environment variables:

- `DATABASE_URL`: pooled Postgres connection, provided by the Neon integration.
- `EXECUTOR_PRIVATE_KEY`: base64-encoded PKCS8 RSA private key (2048 bits or more). Use different keys for development, preview, and production. Store deployed keys as Vercel Secrets.
- `APP_ORIGIN`: optional exact HTTPS origin; defaults to the production project hostname on production. Preview deployments use `VERCEL_URL` and consequently have their own passkeys and account namespace.

Run migrations once before deploying; they are not executed during requests or frontend builds. Do not expose these variables under a `VITE_*` prefix.

```sh
npx vercel deploy          # reviewable preview
npx vercel deploy --prod   # stable production origin
```

Use a stable production/custom domain for a lasting passkey demo. A passkey registered on a generated preview hostname does not transfer to another deployment hostname. API responses use `Cache-Control: no-store`; mutations require both the exact configured Origin and a custom request header. Session cookies are HttpOnly, SameSite=Lax, and Secure on HTTPS. Frontend output has a restrictive CSP and self-hosted fonts.

## Validation

```sh
make test
(cd backend && RUN_DB_TESTS=1 go test ./...)  # real Postgres: replay, expiry, transactions, origin isolation
(cd web && npx playwright install chromium)
(cd web && npx playwright test)             # while make dev is running
```

Go tests cover grant boundaries, wrong scopes, tampering, cross-account ciphertext, OAEP request binding, and public-response redaction. Browser crypto tests cover vault wrapping and delegation. Playwright uses Chromium's virtual WebAuthn authenticator with PRF support to exercise real registration/signatures, vault encryption, approval, execution, grant reuse, revocation, reload/unlock, and mobile layout. Actual biometric hardware/provider support still needs a manual check on the target device.

## Layout

```text
backend/main.go             HTTP server and migration entrypoint
backend/internal/demo/      Auth, persistence, grants, executor, security tests
web/src/                    UI, browser crypto, WebAuthn adapter
web/e2e/                    End-to-end browser test
scripts/dev.mjs             Starts Go and Vite locally
vercel.json                 Services and public ingress
```
