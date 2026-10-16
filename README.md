# Bank System

Bank System is an educational Flask project that demonstrates account login, fictional multi-currency balances, linked cards, simulated transfers, reference-rate exchange calculations, transaction history, administration tools, and authenticated API access.

> [!IMPORTANT]
> **Bank System is a software demonstration—not a real bank, financial institution, payment processor, wallet, or money-changing service.** All cards, balances, transfers, and conversions are fictional, have no monetary value, and cannot be deposited, withdrawn, redeemed, or exchanged for real money. Never enter real financial information, card details, government identifiers, or passwords used elsewhere.

## Features

- User registration and login with generated 8-digit demo card numbers
- Zero-balance self-service and linked-card creation
- Separate balances for SGD, USD, EUR, GBP, and CNY
- Simulated card-to-card transfers without automatic currency conversion
- Optional internal exchange using delayed external reference rates
- Transaction history grouped by day
- Per-card API keys stored as salted hashes
- Restricted Management page with admin-card and admin-key checks
- JSON API with session, CSRF, card-key, and admin-key authentication
- Atomic JSON storage and audit logging

## Run locally

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and replace both sample secrets. Generate secure values with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then start the development server:

```bash
python3 app.py
```

Open <http://127.0.0.1:2501/>. API documentation is available at <http://127.0.0.1:2501/api>.

## Configuration

| Variable | Purpose |
|---|---|
| `BANK_SESSION_SECRET` | Signs browser sessions; use a unique random value |
| `BANK_ADMIN_KEY` | Authorizes management operations |
| `BANK_ADMIN_CARD_NUMBER` | Selects the only demo card allowed to open browser Management |

The default example admin card number is `44808087`, formerly internal card ID 5. Do not use the example configuration for a public deployment.

## Authentication model

- Users authenticate with a demo card number and password.
- Browser changes require a CSRF token.
- Card integrations use a separate `X-API-Key` for each card.
- API management calls may use `X-Admin-Key`.
- Browser Management requires the configured admin card plus the admin key; successful authorization lasts seven days or until logout.
- Passwords and API keys are stored as salted `scrypt` hashes rather than plain text.

## Data storage

This project stores local demonstration data in `cards.json` and `logs.json`. Writes use a temporary file followed by replacement to reduce corruption risk. These files, `.env`, databases, logs, backups, credentials, and virtual environments are excluded from Git.

Do not commit or deploy existing local data. Start any public demo with empty fictional records and reset them regularly.

## Public deployment warning

Flask's built-in server is for development only. Do not expose `python3 app.py` directly to the public internet. A public demonstration requires, at minimum:

- A production WSGI server and reverse proxy
- Valid HTTPS
- Secure production secret management
- Rate limiting and login-abuse protection
- A production database with backups and restricted access
- Security review, dependency maintenance, monitoring, and an incident-response plan
- Removal or strong isolation of Management
- A privacy notice if any personal data is collected
- Prominent disclosure that the application is fictional and provides no financial service

This repository is not designed or approved to process real money, deposits, withdrawals, payment instruments, or sensitive financial data.

## Project layout

```text
app.py              Flask pages, APIs, sessions, and access control
bank.py             Card, balance, transfer, transaction, and JSON-storage logic
exchange.py         Reference-rate retrieval, caching, totals, and quotes
templates/          Server-rendered HTML pages
static/             CSS and browser JavaScript
.env.example        Non-secret configuration template
```

## API documentation

Run the application and visit `/api` for examples or `/api.json` for machine-readable endpoint information.

## Licence

See [LICENSE](LICENSE).
