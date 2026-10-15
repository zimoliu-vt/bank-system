import os
import hmac
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from bank import (BankError, create_card, get_card, get_logs, list_cards,
                  make_transaction, replace_card_key, set_card_status,
                  verify_card_key)


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


@app.errorhandler(BankError)
def bank_error(error):
    return jsonify({"error": str(error)}), error.status_code


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/management")
@app.get("/managment")
def management():
    return render_template("management.html")


@app.get("/api")
def api_documentation():
    return render_template("api.html")


@app.get("/api.json")
def api_documentation_json():
    return jsonify({
        "name": "Bank System API", "version": "1.0",
        "authentication": {"card_operations": "X-API-Key: bank_card_...", "management_operations": "X-Admin-Key: BANK_ADMIN_KEY"},
        "security_note": "Raw card API keys are returned once and stored only as salted hashes.",
        "endpoints": [
            {"method": "GET", "path": "/api/health", "auth": "none"},
            {"method": "GET", "path": "/api/cards/<id>", "auth": "card API key"},
            {"method": "POST", "path": "/api/cards/<id>/transactions", "auth": "card API key"},
            {"method": "GET", "path": "/admin/cards", "auth": "admin key"},
            {"method": "POST", "path": "/admin/cards", "auth": "admin key"},
            {"method": "POST", "path": "/admin/cards/<id>/replace-key", "auth": "admin key"},
            {"method": "PATCH", "path": "/admin/cards/<id>/status", "auth": "admin key"},
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


@app.get("/admin/cards")
@admin_required
def admin_cards():
    return jsonify({"cards": list_cards()})


@app.post("/admin/cards")
@admin_required
def admin_create_card():
    data = json_body()
    card, api_key = create_card(data.get("holder"), data.get("label"), data.get("initial_balance", 0), data.get("currency", "SGD"))
    return jsonify({"status": "success", "card": card, "api_key": api_key, "warning": "Save this key now. It cannot be viewed again."}), 201


@app.post("/admin/cards/<int:card_id>/replace-key")
@admin_required
def admin_replace_key(card_id):
    api_key = replace_card_key(card_id)
    return jsonify({"status": "success", "api_key": api_key, "warning": "The previous key no longer works. Save this key now."})


@app.patch("/admin/cards/<int:card_id>/status")
@admin_required
def admin_set_status(card_id):
    return jsonify({"status": "success", "card": set_card_status(card_id, json_body().get("status"))})


@app.get("/admin/logs")
@admin_required
def admin_logs():
    return jsonify({"logs": get_logs()})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=2501, debug=False)
