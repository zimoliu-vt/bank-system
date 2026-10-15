import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path

ROOT = Path(__file__).parent
CARDS_FILE = ROOT / "cards.json"
LOGS_FILE = ROOT / "logs.json"
DATA_LOCK = threading.RLock()
ALLOWED_CURRENCIES = {"SGD", "USD", "EUR", "GBP"}


class BankError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


def now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BankError(f"Could not read {path.name}: {error}", 500) from error


def atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def cents_from_amount(value, allow_zero=False):
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError) as error:
        raise BankError("Amount must be a valid number") from error
    if amount < 0 or (amount == 0 and not allow_zero):
        raise BankError("Amount must be greater than zero")
    return int(amount * 100)


def public_card(card, include_transactions=False):
    result = {"id": card["id"], "holder": card["holder"], "label": card["label"], "last4": card["last4"], "currency": card["currency"], "balance": f'{Decimal(card["balance_cents"]) / 100:.2f}', "status": card["status"], "created_at": card["created_at"]}
    if include_transactions:
        result["transactions"] = card.get("transactions", [])
    return result


def write_log(action, card_id, detail):
    logs = read_json(LOGS_FILE, [])
    logs.insert(0, {"timestamp": now(), "action": action, "card_id": card_id, "detail": detail})
    atomic_write(LOGS_FILE, logs[:1000])


def hash_key(api_key, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.scrypt(api_key.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex(), digest.hex()


def list_cards():
    with DATA_LOCK:
        return [public_card(card) for card in read_json(CARDS_FILE, [])]


def find_card(cards, card_id):
    card = next((item for item in cards if item.get("id") == card_id), None)
    if card is None:
        raise BankError("Card not found", 404)
    return card


def get_card(card_id, include_transactions=False):
    with DATA_LOCK:
        return public_card(find_card(read_json(CARDS_FILE, []), card_id), include_transactions)


def create_card(holder, label, initial_balance=0, currency="SGD"):
    holder, label = str(holder or "").strip(), str(label or "Everyday card").strip()
    currency = str(currency or "SGD").strip().upper()
    if not holder:
        raise BankError("Card holder is required")
    if len(holder) > 100 or len(label) > 80:
        raise BankError("Holder or label is too long")
    if currency not in ALLOWED_CURRENCIES:
        raise BankError("Unsupported currency")
    balance_cents = cents_from_amount(initial_balance, allow_zero=True)
    api_key = f"bank_card_{secrets.token_urlsafe(32)}"
    salt, key_hash = hash_key(api_key)
    with DATA_LOCK:
        cards = read_json(CARDS_FILE, [])
        card = {"id": max((item.get("id", 0) for item in cards), default=0) + 1, "holder": holder, "label": label, "last4": f"{secrets.randbelow(10000):04d}", "currency": currency, "balance_cents": balance_cents, "status": "active", "key_salt": salt, "key_hash": key_hash, "created_at": now(), "transactions": []}
        cards.append(card)
        atomic_write(CARDS_FILE, cards)
        write_log("CARD_CREATED", card["id"], f"Created {label} for {holder}")
        return public_card(card), api_key


def verify_card_key(card_id, api_key):
    if not isinstance(api_key, str) or len(api_key) > 200:
        return False
    try:
        with DATA_LOCK:
            card = find_card(read_json(CARDS_FILE, []), card_id)
            _, candidate = hash_key(api_key, card["key_salt"])
            return hmac.compare_digest(candidate, card["key_hash"])
    except BankError:
        return False


def replace_card_key(card_id):
    api_key = f"bank_card_{secrets.token_urlsafe(32)}"
    salt, key_hash = hash_key(api_key)
    with DATA_LOCK:
        cards = read_json(CARDS_FILE, [])
        card = find_card(cards, card_id)
        card["key_salt"], card["key_hash"] = salt, key_hash
        atomic_write(CARDS_FILE, cards)
        write_log("KEY_REPLACED", card_id, "Card API key replaced")
    return api_key


def set_card_status(card_id, status):
    if status not in {"active", "frozen"}:
        raise BankError("Status must be active or frozen")
    with DATA_LOCK:
        cards = read_json(CARDS_FILE, [])
        card = find_card(cards, card_id)
        card["status"] = status
        atomic_write(CARDS_FILE, cards)
        write_log("STATUS_CHANGED", card_id, f"Card changed to {status}")
        return public_card(card)


def make_transaction(card_id, transaction_type, amount, description=""):
    if transaction_type not in {"deposit", "withdrawal"}:
        raise BankError("Type must be deposit or withdrawal")
    amount_cents = cents_from_amount(amount)
    description = str(description or "").strip()[:160]
    with DATA_LOCK:
        cards = read_json(CARDS_FILE, [])
        card = find_card(cards, card_id)
        if card["status"] != "active":
            raise BankError("Card is frozen", 403)
        if transaction_type == "withdrawal" and amount_cents > card["balance_cents"]:
            raise BankError("Insufficient funds", 409)
        card["balance_cents"] += amount_cents if transaction_type == "deposit" else -amount_cents
        transaction = {"id": secrets.token_hex(8), "type": transaction_type, "amount": f"{Decimal(amount_cents) / 100:.2f}", "description": description, "created_at": now()}
        card.setdefault("transactions", []).insert(0, transaction)
        card["transactions"] = card["transactions"][:200]
        atomic_write(CARDS_FILE, cards)
        write_log(transaction_type.upper(), card_id, f'{transaction["amount"]} {card["currency"]}')
        return {"card": public_card(card), "transaction": transaction}


def get_logs():
    with DATA_LOCK:
        return read_json(LOGS_FILE, [])
