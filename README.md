# Bagh Cloudflare Worker starter

This starter is not a full drop-in replacement for the original Node.js server.

Before deploying:
1. Create a Cloudflare Workers KV namespace.
2. Add a KV binding named `BAGH_KV` for this Worker.
3. Set `DB_KEY` as a Worker secret if you want the optional `/db/<key>/...` path guard.
4. Do not deploy publicly until the login/authentication flow and frontend API URL have been updated and tested.

Important limitations:
- SMS login endpoints intentionally return 503 until a real SMS provider is configured.
- SSE realtime updates from the original server are not implemented here.
- Cloudflare KV is eventually consistent and is not a relational database.
- Do not store passwords, SMS codes, or sensitive personal data in a public repository.
