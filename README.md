# Bank System

A local Flask demonstration app with card management, deposits and withdrawals, audit logs, and a separate API key for every card.

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

Run `python app.py`, then open the homepage at <http://127.0.0.1:2501/>, management at <http://127.0.0.1:2501/management>, or API docs at <http://127.0.0.1:2501/api>.

## Key security

- Management operations require `BANK_ADMIN_KEY` in the `X-Admin-Key` header.
- Every card has a different generated `bank_card_...` API key.
- Raw card keys appear only when created or replaced.
- Only a salted `scrypt` hash is stored in `cards.json`.
- Key checks use constant-time comparisons.
- Replacing a key immediately invalidates the previous key.

Local `.env`, card data, logs, databases, and backups are excluded from Git.
