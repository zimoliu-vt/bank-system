import os
import hmac
import secrets
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from bank import (BankError, authenticate_card, create_card, delete_card, get_card, get_logs, list_cards,
                  link_google_account, make_payment, make_transaction, replace_card_key,
                  set_card_status, set_card_login, unlink_google_account, verify_card_key)


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
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://127.0.0.1:2501/auth/google/callback").strip()


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


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/account")
@user_login_required
def account():
    return render_template("account.html", card=get_card(session["card_id"], include_transactions=True), csrf_token=session["csrf_token"], google_configured=bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET), notice=session.pop("account_notice", None))


@app.get("/auth/google/start")
@user_login_required
def google_start():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        session["account_notice"] = "Google linking is not configured yet. Add the Google OAuth client ID and secret to .env."
        return redirect(url_for("account"))
    state = secrets.token_urlsafe(32)
    session["google_oauth_state"] = state
    parameters = {"client_id": GOOGLE_CLIENT_ID, "redirect_uri": GOOGLE_REDIRECT_URI, "response_type": "code", "scope": "openid email", "state": state, "access_type": "online", "prompt": "select_account"}
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(parameters))


@app.get("/google-setup")
@user_login_required
def google_setup():
    return render_template("google_setup.html", redirect_uri=GOOGLE_REDIRECT_URI, configured=bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET))


@app.get("/auth/google/callback")
@user_login_required
def google_callback():
    expected_state = session.pop("google_oauth_state", "")
    supplied_state = request.args.get("state", "")
    if not expected_state or not supplied_state or not hmac.compare_digest(expected_state, supplied_state):
        raise BankError("Invalid Google linking state", 403)
    if request.args.get("error"):
        session["account_notice"] = "Google linking was cancelled."
        return redirect(url_for("account"))
    code = request.args.get("code", "")
    try:
        token_response = requests.post("https://oauth2.googleapis.com/token", data={"code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET, "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code"}, timeout=15)
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]
        user_response = requests.get("https://openidconnect.googleapis.com/v1/userinfo", headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
        user_response.raise_for_status()
        identity = user_response.json()
    except (requests.RequestException, KeyError, ValueError):
        raise BankError("Could not verify the Google account", 502)
    if identity.get("email_verified") is not True:
        raise BankError("Google email address is not verified", 403)
    link_google_account(session["card_id"], identity.get("sub"), identity.get("email"))
    session["account_notice"] = "Google account linked successfully."
    return redirect(url_for("account"))


@app.post("/auth/google/unlink")
@user_login_required
def google_unlink():
    supplied = request.form.get("csrf_token", "")
    if not supplied or not hmac.compare_digest(session.get("csrf_token", ""), supplied):
        raise BankError("Invalid session token", 403)
    unlink_google_account(session["card_id"])
    session["account_notice"] = "Google account unlinked."
    return redirect(url_for("account"))


@app.get("/management")
@app.get("/managment")
def management():
    return render_template("management.html")


@app.get("/payments")
@user_login_required
def payments():
    return render_template("payments.html", card=get_card(session["card_id"]), csrf_token=session["csrf_token"])


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
            {"method": "GET", "path": "/api/account", "auth": "user session"},
            {"method": "POST", "path": "/api/payments", "auth": "user session and CSRF token"},
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
    return jsonify({"status": "ok", "service": "bank-system", "admin_configured": bool(ADMIN_KEY), "google_linking_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)})


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
    return jsonify({"status": "success", "card": card, "csrf_token": session["csrf_token"]})


@app.get("/api/account")
@user_login_required
def api_account():
    return jsonify({"card": get_card(session["card_id"], include_transactions=True)})


@app.post("/api/payments")
@user_login_required
def user_pay():
    verify_csrf()
    data = json_body()
    payment = make_payment(session["card_id"], data.get("to_card_id"), data.get("amount"), data.get("description", ""))
    return jsonify({"status": "success", **payment}), 201


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
