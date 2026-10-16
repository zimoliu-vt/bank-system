import os
import hmac
import secrets
from decimal import InvalidOperation
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from bank import (BankError, authenticate_card, create_card, delete_card, exchange_balance, get_card, get_linked_cards, get_logs, list_cards,
                  make_payment, make_transaction, replace_card_key, set_card_status,
                  select_linked_card, set_card_login, verify_card_key)
from exchange import ExchangeError, get_quote, get_total_value


def load_env():
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


load_env()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.config.update(SECRET_KEY=os.environ.get("BANK_SESSION_SECRET", ""), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
ADMIN_KEY = os.environ.get("BANK_ADMIN_KEY", "").strip()


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BankError("Expected a JSON object", 400)
    return data


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not ADMIN_KEY:
            return jsonify({"error": "BANK_ADMIN_KEY is not configured", "setup": "Copy .env.example to .env and choose a strong admin key."}), 503
        supplied_key = request.headers.get("X-Admin-Key", "")
        if len(supplied_key) > 200 or not hmac.compare_digest(supplied_key, ADMIN_KEY):
            return jsonify({"error": "Valid X-Admin-Key header required"}), 401
        return view(*args, **kwargs)
    return wrapped


def card_key_required(view):
    @wraps(view)
    def wrapped(card_id, *args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not key or not verify_card_key(card_id, key):
            return jsonify({"error": "Valid X-API-Key header required"}), 401
        return view(card_id, *args, **kwargs)
    return wrapped


def user_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("card_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Login required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def verify_csrf():
    expected = session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise BankError("Invalid session token. Refresh the page and try again.", 403)


def card_valuation(card, target_currency=None):
    target = str(target_currency or card["currency"]).strip().upper()
    if target not in {"SGD", "USD", "EUR", "GBP", "CNY"}:
        target = card["currency"]
    try:
        return get_total_value(card["balances"], target)
    except (ExchangeError, InvalidOperation, ValueError):
        return {"currency": card["currency"], "amount": card["balance"], "rate_date": None, "complete": False}


@app.errorhandler(BankError)
def bank_error(error):
    return jsonify({"error": str(error)}), error.status_code


@app.get("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("card_id"):
            return redirect(url_for("account"))
        return render_template("login.html", error=None)
    try:
        card = authenticate_card(request.form.get("card_number"), request.form.get("password"))
    except BankError as error:
        return render_template("login.html", error=str(error)), error.status_code
    if card is None:
        return render_template("login.html", error="Incorrect card number or password"), 401
    session.clear()
    session["card_id"] = card["id"]
    session["csrf_token"] = secrets.token_urlsafe(24)
    session.permanent = False
    return redirect(url_for("account"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        if session.get("card_id"):
            return redirect(url_for("account"))
        return render_template("register.html", error=None, values={})
    values = request.form
    password = values.get("password", "")
    if not hmac.compare_digest(password, values.get("confirm_password", "")):
        return render_template("register.html", error="Passwords do not match", values=values), 400
    try:
        card, _unused_api_key = create_card(values.get("holder"), values.get("label"), 0, values.get("currency", "SGD"),
                                             password=password, created_by="user")
    except BankError as error:
        return render_template("register.html", error=str(error), values=values), error.status_code
    session.clear()
    session["card_id"] = card["id"]
    session["csrf_token"] = secrets.token_urlsafe(24)
    session.permanent = False
    return redirect(url_for("account"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/account")
@user_login_required
def account():
    session.setdefault("csrf_token", secrets.token_urlsafe(24))
    card = get_card(session["card_id"], include_transactions=True)
    valuation = card_valuation(card)
    transaction_days = sorted({item.get("created_at", "")[:10] for item in card["transactions"] if item.get("created_at")}, reverse=True)
    requested_day = request.args.get("day", "")
    selected_day = requested_day if requested_day in transaction_days else (transaction_days[0] if transaction_days else "")
    selected_transactions = [item for item in card["transactions"] if item.get("created_at", "")[:10] == selected_day]
    day_index = transaction_days.index(selected_day) if selected_day else -1
    newer_day = transaction_days[day_index - 1] if day_index > 0 else None
    older_day = transaction_days[day_index + 1] if 0 <= day_index < len(transaction_days) - 1 else None
    return render_template("account.html", card=card, linked_cards=get_linked_cards(session["card_id"]),
                           csrf_token=session["csrf_token"], transaction_days=transaction_days,
                           selected_day=selected_day, selected_transactions=selected_transactions,
                           newer_day=newer_day, older_day=older_day, valuation=valuation)


@app.post("/account/select-card")
@user_login_required
def select_account_card():
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise BankError("Invalid session token. Refresh the page and try again.", 403)
    try:
        selected_id = int(request.form.get("card_id", ""))
    except (TypeError, ValueError) as error:
        raise BankError("A valid card ID is required") from error
    selected = select_linked_card(session["card_id"], selected_id)
    session["card_id"] = selected["id"]
    return redirect(url_for("account"))


@app.route("/account/cards/new", methods=["GET", "POST"])
@user_login_required
def create_linked_card():
    session.setdefault("csrf_token", secrets.token_urlsafe(24))
    current = get_card(session["card_id"])
    if request.method == "GET":
        return render_template("new-linked-card.html", card=current, csrf_token=session["csrf_token"], error=None, values={})
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise BankError("Invalid session token. Refresh the page and try again.", 403)
    try:
        card, _unused_api_key = create_card(current["holder"], request.form.get("label"), 0,
                                             request.form.get("currency", current["currency"]),
                                             linked_card_id=current["id"], created_by="user")
    except BankError as error:
        return render_template("new-linked-card.html", card=current, csrf_token=session["csrf_token"],
                               error=str(error), values=request.form), error.status_code
    session["card_id"] = card["id"]
    return redirect(url_for("account"))


@app.get("/management")
@app.get("/managment")
def management():
    return render_template("management.html")


@app.get("/payments")
@user_login_required
def payments():
    return render_template("payments.html", card=get_card(session["card_id"]), csrf_token=session["csrf_token"])


@app.get("/exchange")
@user_login_required
def exchange_page():
    return render_template("exchange.html", card=get_card(session["card_id"]), csrf_token=session["csrf_token"])


@app.get("/api")
def api_documentation():
    return render_template("api.html")


@app.get("/api.json")
def api_documentation_json():
    return jsonify({
        "name": "Bank System API", "version": "1.0",
        "authentication": {"user_operations": "Login with card number and password; retain the session cookie", "card_api_operations": "X-API-Key: bank_card_...", "management_operations": "X-Admin-Key: BANK_ADMIN_KEY"},
        "security_note": "Raw card API keys are returned once and stored only as salted hashes.",
        "endpoints": [
            {"method": "GET", "path": "/api/health", "auth": "none"},
            {"method": "GET", "path": "/api/cards/<id>", "auth": "card API key"},
            {"method": "POST", "path": "/api/cards/<id>/transactions", "auth": "card API key"},
            {"method": "POST", "path": "/api/auth/login", "auth": "card number and password"},
            {"method": "POST", "path": "/api/auth/register", "auth": "none", "description": "Creates a new unlinked card with a server-enforced zero balance and starts a user session"},
            {"method": "GET", "path": "/api/account", "auth": "user session", "description": "Returns the selected card, linked cards, and an estimated total value in the main currency"},
            {"method": "GET", "path": "/api/account/valuation?currency=SGD", "auth": "user session", "description": "Returns the account total converted into a supported display currency"},
            {"method": "POST", "path": "/api/account/select-card", "auth": "user session and CSRF token"},
            {"method": "POST", "path": "/api/account/cards", "auth": "user session and CSRF token", "description": "Creates a linked card under the authenticated holder name with a server-enforced zero balance"},
            {"method": "POST", "path": "/api/payments", "auth": "user session and CSRF token", "description": "Accepts recipient as either a Card ID or 8-digit card number; legacy to_card_id is also supported"},
            {"method": "GET", "path": "/api/exchange/quote", "auth": "user session"},
            {"method": "POST", "path": "/api/exchange", "auth": "user session and CSRF token"},
            {"method": "GET", "path": "/admin/cards", "auth": "admin key"},
            {"method": "POST", "path": "/admin/cards", "auth": "admin key"},
            {"method": "POST", "path": "/admin/cards/<id>/replace-key", "auth": "admin key"},
            {"method": "PUT", "path": "/admin/cards/<id>/login", "auth": "admin key"},
            {"method": "PATCH", "path": "/admin/cards/<id>/status", "auth": "admin key"},
            {"method": "DELETE", "path": "/admin/cards/<id>", "auth": "admin key; zero balance required"},
            {"method": "GET", "path": "/admin/logs", "auth": "admin key"}
        ]
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "bank-system", "admin_configured": bool(ADMIN_KEY)})


@app.get("/api/cards/<int:card_id>")
@card_key_required
def card_details(card_id):
    return jsonify({"card": get_card(card_id, include_transactions=True)})


@app.post("/api/cards/<int:card_id>/transactions")
@card_key_required
def transact(card_id):
    data = json_body()
    transaction = make_transaction(card_id, data.get("type"), data.get("amount"), data.get("description", ""))
    return jsonify({"status": "success", **transaction}), 201


@app.post("/api/auth/login")
def api_login():
    data = json_body()
    card = authenticate_card(data.get("card_number"), data.get("password"))
    if card is None:
        return jsonify({"error": "Incorrect card number or password"}), 401
    session.clear()
    session["card_id"] = card["id"]
    session["csrf_token"] = secrets.token_urlsafe(24)
    return jsonify({"status": "success", "card": card, "linked_cards": get_linked_cards(card["id"]), "csrf_token": session["csrf_token"]})


@app.post("/api/auth/register")
def api_register():
    data = json_body()
    card, _unused_api_key = create_card(data.get("holder"), data.get("label"), 0, data.get("currency", "SGD"),
                                        password=data.get("password"), created_by="user")
    session.clear()
    session["card_id"] = card["id"]
    session["csrf_token"] = secrets.token_urlsafe(24)
    return jsonify({"status": "success", "card": card, "csrf_token": session["csrf_token"],
                    "message": "Card created with a zero balance"}), 201


@app.get("/api/account")
@user_login_required
def api_account():
    card = get_card(session["card_id"], include_transactions=True)
    return jsonify({"card": card, "valuation": card_valuation(card), "linked_cards": get_linked_cards(session["card_id"])})


@app.get("/api/account/valuation")
@user_login_required
def api_account_valuation():
    card = get_card(session["card_id"])
    return jsonify({"valuation": card_valuation(card, request.args.get("currency"))})


@app.post("/api/account/select-card")
@user_login_required
def api_select_account_card():
    verify_csrf()
    data = json_body()
    if type(data.get("card_id")) is not int:
        raise BankError("card_id must be an integer")
    selected = select_linked_card(session["card_id"], data["card_id"])
    session["card_id"] = selected["id"]
    return jsonify({"status": "success", "card": selected})


@app.post("/api/account/cards")
@user_login_required
def api_create_linked_card():
    verify_csrf()
    data = json_body()
    current = get_card(session["card_id"])
    card, _unused_api_key = create_card(current["holder"], data.get("label"), 0,
                                        data.get("currency", current["currency"]),
                                        linked_card_id=current["id"], created_by="user")
    session["card_id"] = card["id"]
    return jsonify({"status": "success", "card": card, "message": "Linked card created with a zero balance"}), 201


@app.post("/api/payments")
@user_login_required
def user_pay():
    verify_csrf()
    data = json_body()
    recipient = data.get("recipient", data.get("to_card_number", data.get("to_card_id")))
    payment = make_payment(session["card_id"], recipient, data.get("amount"), data.get("description", ""), data.get("currency"))
    return jsonify({"status": "success", **payment}), 201


@app.get("/api/exchange/quote")
@user_login_required
def exchange_quote():
    try:
        quote = get_quote(request.args.get("from"), request.args.get("to"), request.args.get("amount"))
    except ExchangeError as error:
        return jsonify({"error": str(error)}), 503
    return jsonify({"quote": quote})


@app.post("/api/exchange")
@user_login_required
def exchange_money():
    verify_csrf()
    data = json_body()
    try:
        quote = get_quote(data.get("from_currency"), data.get("to_currency"), data.get("amount"))
    except ExchangeError as error:
        return jsonify({"error": str(error)}), 503
    return jsonify({"status": "success", **exchange_balance(session["card_id"], quote)}), 201


@app.get("/admin/cards")
@admin_required
def admin_cards():
    return jsonify({"cards": list_cards()})


@app.post("/admin/cards")
@admin_required
def admin_create_card():
    data = json_body()
    card, api_key = create_card(data.get("holder"), data.get("label"), data.get("initial_balance", 0), data.get("currency", "SGD"), data.get("linked_card_id"))
    return jsonify({"status": "success", "card": card, "api_key": api_key, "warning": "Save this key now. It cannot be viewed again."}), 201


@app.post("/admin/cards/<int:card_id>/replace-key")
@admin_required
def admin_replace_key(card_id):
    api_key = replace_card_key(card_id)
    return jsonify({"status": "success", "api_key": api_key, "warning": "The previous key no longer works. Save this key now."})


@app.put("/admin/cards/<int:card_id>/login")
@admin_required
def admin_set_login(card_id):
    data = json_body()
    return jsonify({"status": "success", "card": set_card_login(card_id, data.get("password"))})


@app.patch("/admin/cards/<int:card_id>/status")
@admin_required
def admin_set_status(card_id):
    return jsonify({"status": "success", "card": set_card_status(card_id, json_body().get("status"))})


@app.delete("/admin/cards/<int:card_id>")
@admin_required
def admin_delete_card(card_id):
    deleted = delete_card(card_id)
    return jsonify({"status": "success", "message": "Card deleted", "card": deleted})


@app.get("/admin/logs")
@admin_required
def admin_logs():
    return jsonify({"logs": get_logs()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2501, debug=False)
