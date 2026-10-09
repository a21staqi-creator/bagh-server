# Bagh Worker auth update

## What this changes
- Adds `/auth/register` and `/auth/login` using phone + password (no SMS).
- Passwords are PBKDF2-SHA-256 hashes, never stored as plain text.
- Adds 30-day bearer sessions: `/auth/profile` (GET) and `/auth/logout` (POST).
- Adds `/auth/recovery` to record a recovery request; user still needs to contact support `@mrmmdt`.
- Keeps `/health` and KV-backed database routes. Database routes now require a `DB_KEY` Worker secret; configure it before using any frontend database calls.
- `/auth/send` and `/auth/verify` remain disabled; SMS is not configured.

## Deploy from GitHub
Replace the repository's `worker.js` with this file, commit the change, then let Cloudflare redeploy from GitHub.

## Required compatibility
Keep your existing KV namespace binding variable name exactly `BAGH_KV`.

## Important integration note
The existing website must call:
- `POST /auth/register` with JSON `{ "phone": "+49123456789", "password": "...", "displayName": "..." }`
- `POST /auth/login` with JSON `{ "phone": "+49123456789", "password": "..." }`
- `GET /auth/profile` with header `Authorization: Bearer <token>`
- `POST /auth/logout` with header `Authorization: Bearer <token>`
- `POST /auth/recovery` with JSON `{ "phone": "...", "message": "..." }`

The token should be kept in sessionStorage or a secure app session mechanism, not placed in a URL. Do not store plain passwords. Phone numbers are not verified by SMS, so this does not prove the user owns the number. Apply rate limiting / Turnstile before public launch to limit automated registration and login attempts.

## Support
Recovery contact: @mrmmdt
