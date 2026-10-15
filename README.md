# Bank System

A local Flask demonstration app with card-number login, private account pages, transaction history, protected card-to-card payments, audit logs, and a separate API key for every card.

> This is an educational demo, not a real bank or payment processor. Do not use real card details, credentials, or financial data.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and replace the sample `BANK_ADMIN_KEY` with a long random secret. Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Run `python app.py`. On this Mac, open <http://127.0.0.1:2501/>. Payments are at <http://127.0.0.1:2501/payments>, management is at <http://127.0.0.1:2501/management>, and API docs are at <http://127.0.0.1:2501/api>. Other devices on the same private network can use `http://YOUR_MAC_PRIVATE_IP:2501/`.

The development server listens on all local interfaces. Keep port 2501 blocked from the public internet and do not configure router port forwarding for this demo.

## Key security

- Management operations require `BANK_ADMIN_KEY` in the `X-Admin-Key` header.
- Every card has a different generated `bank_card_...` API key.
- Users log in with their generated 8-digit demo card number and a hashed password configured by an administrator.
- Browser and API payments require an authenticated session plus a CSRF token.
- Passwords use Werkzeug's `scrypt` hashing and are never stored in plain text.
- Raw card keys appear only when created or replaced.
- Only a salted `scrypt` hash is stored in `cards.json`.
- Key checks use constant-time comparisons.
- Replacing a key immediately invalidates the previous key.
- Deleting a card requires the admin key and a zero balance; its deletion remains in the audit log.

Local `.env`, card data, logs, databases, and backups are excluded from Git.

## Google account linking

Create a Google OAuth 2.0 Web application and register this exact authorized redirect URI:

```text
http://127.0.0.1:2501/auth/google/callback
```

Add its client ID and secret to `.env` as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. The app requests only `openid email`; it stores the verified email and stable Google account identifier, but does not store access tokens or request permission to read or send Gmail.
