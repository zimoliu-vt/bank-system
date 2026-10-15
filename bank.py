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
from werkzeug.security import check_password_hash, generate_password_hash

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
    balances = card.get("balances", {card["currency"]: card.get("balance_cents", 0)})
    result = {"id": card["id"], "holder": card["holder"], "label": card["label"], "card_number": format_card_number(card["card_number"]), "last4": card["last4"], "currency": card["currency"], "balance": f'{Decimal(balances.get(card["currency"], 0)) / 100:.2f}', "balances": {currency: f"{Decimal(cents) / 100:.2f}" for currency, cents in sorted(balances.items())}, "status": card["status"], "created_at": card["created_at"], "login_configured": bool(card.get("password_hash"))}
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


def generate_card_number(existing_numbers):
    while True:
        first_seven = "4" + "".join(str(secrets.randbelow(10)) for _ in range(6))
        digits = [int(value) for value in first_seven]
        total = 0
        for index, digit in enumerate(digits):
            value = digit * 2 if index % 2 == 0 else digit
            total += value - 9 if value > 9 else value
        number = first_seven + str((10 - total % 10) % 10)
        if number not in existing_numbers:
            return number


def read_cards():
    cards = read_json(CARDS_FILE, [])
    existing = {card.get("card_number") for card in cards if card.get("card_number")}
    changed = False
    for card in cards:
        if len(card.get("card_number", "")) != 8:
            card["card_number"] = generate_card_number(existing)
            card["last4"] = card["card_number"][-4:]
            existing.add(card["card_number"])
            changed = True
        if "balances" not in card:
            card["balances"] = {card["currency"]: card.get("balance_cents", 0)}
            changed = True
    if changed:
        atomic_write(CARDS_FILE, cards)
    return cards


def format_card_number(number):
    return " ".join(number[index:index + 4] for index in range(0, 8, 4))


def list_cards():
    with DATA_LOCK:
        return [public_card(card) for card in read_cards()]


def find_card(cards, card_id):
    card = next((item for item in cards if item.get("id") == card_id), None)
    if card is None:
        raise BankError("Card not found", 404)
    return card


def get_card(card_id, include_transactions=False):
    with DATA_LOCK:
        return public_card(find_card(read_cards(), card_id), include_transactions)


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
        cards = read_cards()
        card_number = generate_card_number({item["card_number"] for item in cards})
        card = {"id": max((item.get("id", 0) for item in cards), default=0) + 1, "holder": holder, "label": label, "card_number": card_number, "last4": card_number[-4:], "currency": currency, "balance_cents": balance_cents, "balances": {currency: balance_cents}, "status": "active", "key_salt": salt, "key_hash": key_hash, "created_at": now(), "transactions": []}
        cards.append(card)
        atomic_write(CARDS_FILE, cards)
        write_log("CARD_CREATED", card["id"], f"Created {label} for {holder}")
        return public_card(card), api_key


def set_card_login(card_id, password):
    password = str(password or "")
    if len(password) < 10:
        raise BankError("Password must be at least 10 characters")
    if len(password) > 200:
        raise BankError("Password is too long")
    with DATA_LOCK:
        cards = read_cards()
        card = find_card(cards, card_id)
        card["password_hash"] = generate_password_hash(password, method="scrypt")
        atomic_write(CARDS_FILE, cards)
        write_log("LOGIN_CONFIGURED", card_id, "Card-number login configured")
        return public_card(card)


def authenticate_card(card_number, password):
    card_number = "".join(character for character in str(card_number or "") if character.isdigit())
    password = str(password or "")
    with DATA_LOCK:
        cards = read_cards()
        card = next((item for item in cards if item.get("card_number") == card_number), None)
        if card is None or not card.get("password_hash") or not check_password_hash(card["password_hash"], password):
            return None
        if card["status"] != "active":
            raise BankError("This account is frozen", 403)
        write_log("LOGIN", card["id"], "User logged in")
        return public_card(card)


def verify_card_key(card_id, api_key):
    if not isinstance(api_key, str) or len(api_key) > 200:
        return False
    try:
        with DATA_LOCK:
            card = find_card(read_cards(), card_id)
            _, candidate = hash_key(api_key, card["key_salt"])
            return hmac.compare_digest(candidate, card["key_hash"])
    except BankError:
        return False


def replace_card_key(card_id):
    api_key = f"bank_card_{secrets.token_urlsafe(32)}"
    salt, key_hash = hash_key(api_key)
    with DATA_LOCK:
        cards = read_cards()
        card = find_card(cards, card_id)
        card["key_salt"], card["key_hash"] = salt, key_hash
        atomic_write(CARDS_FILE, cards)
        write_log("KEY_REPLACED", card_id, "Card API key replaced")
    return api_key


def set_card_status(card_id, status):
    if status not in {"active", "frozen"}:
        raise BankError("Status must be active or frozen")
    with DATA_LOCK:
        cards = read_cards()
        card = find_card(cards, card_id)
        card["status"] = status
        atomic_write(CARDS_FILE, cards)
        write_log("STATUS_CHANGED", card_id, f"Card changed to {status}")
        return public_card(card)


def delete_card(card_id):
    with DATA_LOCK:
        cards = read_cards()
        card = find_card(cards, card_id)
        if any(card.get("balances", {card["currency"]: card.get("balance_cents", 0)}).values()):
            raise BankError("All currency balances must be zero before deleting a card", 409)
        deleted = public_card(card)
        cards.remove(card)
        atomic_write(CARDS_FILE, cards)
        write_log("CARD_DELETED", card_id, f'Deleted {card["label"]} for {card["holder"]}')
        return deleted


def make_transaction(card_id, transaction_type, amount, description=""):
    if transaction_type not in {"deposit", "withdrawal"}:
        raise BankError("Type must be deposit or withdrawal")
    amount_cents = cents_from_amount(amount)
    description = str(description or "").strip()[:160]
    with DATA_LOCK:
        cards = read_cards()
        card = find_card(cards, card_id)
        if card["status"] != "active":
            raise BankError("Card is frozen", 403)
        balances = card.setdefault("balances", {card["currency"]: card.get("balance_cents", 0)})
        if transaction_type == "withdrawal" and amount_cents > balances.get(card["currency"], 0):
            raise BankError("Insufficient funds", 409)
        balances[card["currency"]] = balances.get(card["currency"], 0) + (amount_cents if transaction_type == "deposit" else -amount_cents)
        card["balance_cents"] = balances[card["currency"]]
        transaction = {"id": secrets.token_hex(8), "type": transaction_type, "amount": f"{Decimal(amount_cents) / 100:.2f}", "currency": card["currency"], "description": description, "created_at": now()}
        card.setdefault("transactions", []).insert(0, transaction)
        card["transactions"] = card["transactions"][:200]
        atomic_write(CARDS_FILE, cards)
        write_log(transaction_type.upper(), card_id, f'{transaction["amount"]} {card["currency"]}')
        return {"card": public_card(card), "transaction": transaction}


def make_payment(from_card_id, to_card_id, amount, description="", currency=None):
    if type(to_card_id) is not int:
        raise BankError("to_card_id must be an integer")
    if from_card_id == to_card_id:
        raise BankError("A card cannot pay itself")
    amount_cents = cents_from_amount(amount)
    description = str(description or "").strip()[:160]
    transfer_id = secrets.token_hex(10)
    created_at = now()
    with DATA_LOCK:
        cards = read_cards()
        sender = find_card(cards, from_card_id)
        recipient = find_card(cards, to_card_id)
        if sender["status"] != "active":
            raise BankError("Sender card is frozen", 403)
        if recipient["status"] != "active":
            raise BankError("Recipient card is frozen", 403)
        sender_balances = sender.setdefault("balances", {sender["currency"]: sender.get("balance_cents", 0)})
        transfer_currency = str(currency or sender["currency"]).strip().upper()
        if transfer_currency not in sender_balances:
            raise BankError(f"No {transfer_currency} balance is available", 409)
        recipient_balances = recipient.setdefault("balances", {recipient["currency"]: recipient.get("balance_cents", 0)})
        if amount_cents > sender_balances.get(transfer_currency, 0):
            raise BankError("Insufficient funds", 409)
        sender_balances[transfer_currency] -= amount_cents
        recipient_balances[transfer_currency] = recipient_balances.get(transfer_currency, 0) + amount_cents
        sender["balance_cents"] = sender_balances.get(sender["currency"], 0)
        recipient["balance_cents"] = recipient_balances.get(recipient["currency"], 0)
        amount_text = f"{Decimal(amount_cents) / 100:.2f}"
        sender_transaction = {"id": secrets.token_hex(8), "transfer_id": transfer_id, "type": "payment_sent", "amount": amount_text, "currency": transfer_currency, "description": description, "other_card_id": to_card_id, "created_at": created_at}
        recipient_transaction = {"id": secrets.token_hex(8), "transfer_id": transfer_id, "type": "payment_received", "amount": amount_text, "currency": transfer_currency, "description": description, "other_card_id": from_card_id, "created_at": created_at}
        sender.setdefault("transactions", []).insert(0, sender_transaction)
        recipient.setdefault("transactions", []).insert(0, recipient_transaction)
        sender["transactions"] = sender["transactions"][:200]
        recipient["transactions"] = recipient["transactions"][:200]
        atomic_write(CARDS_FILE, cards)
        write_log("PAYMENT", from_card_id, f"{amount_text} {transfer_currency} to card {to_card_id}; transfer {transfer_id}; no conversion")
        return {"payment": {"transfer_id": transfer_id, "from_card_id": from_card_id, "to_card_id": to_card_id, "amount": amount_text, "currency": transfer_currency, "conversion": "none; recipient keeps the original currency", "description": description, "created_at": created_at}, "card": public_card(sender)}


def exchange_balance(card_id, quote):
    source, target = quote["from_currency"], quote["to_currency"]
    if source not in ALLOWED_CURRENCIES or target not in ALLOWED_CURRENCIES:
        raise BankError("Unsupported currency")
    source_cents = cents_from_amount(quote["amount"])
    target_cents = cents_from_amount(quote["converted_amount"])
    with DATA_LOCK:
        cards = read_cards()
        card = find_card(cards, card_id)
        if card["status"] != "active":
            raise BankError("Card is frozen", 403)
        balances = card.setdefault("balances", {card["currency"]: card.get("balance_cents", 0)})
        if source_cents > balances.get(source, 0):
            raise BankError(f"Insufficient {source} balance", 409)
        balances[source] -= source_cents
        balances[target] = balances.get(target, 0) + target_cents
        card["balance_cents"] = balances.get(card["currency"], 0)
        transaction = {"id": secrets.token_hex(8), "type": "currency_exchange", "amount": quote["amount"], "currency": source, "converted_amount": quote["converted_amount"], "to_currency": target, "rate": quote["rate"], "rate_date": quote.get("date"), "description": f"Exchanged {source} to {target}", "created_at": now()}
        card.setdefault("transactions", []).insert(0, transaction)
        card["transactions"] = card["transactions"][:200]
        atomic_write(CARDS_FILE, cards)
        write_log("CURRENCY_EXCHANGE", card_id, f'{quote["amount"]} {source} to {quote["converted_amount"]} {target} at {quote["rate"]}')
        return {"card": public_card(card), "transaction": transaction, "quote": quote}


def get_logs():
    with DATA_LOCK:
        return read_json(LOGS_FILE, [])
