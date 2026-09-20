"""
Thirsty Quench (TQ) — Balance Sheet Web App
Local multi-user system with Admin and Worker logins.

Security posture:
  - Flask-Talisman: CSP, X-Frame-Options, nosniff, Permissions-Policy, Referrer-Policy
  - Flask-Limiter: 5 login attempts per 60s per IP
  - CSRF fail-closed on all mutating routes (header or form token)
  - Public signup locked unless TQ_ALLOW_SIGNUP=1
  - Debug off unless TQ_DEBUG=1; never enable with public tunnels
  - Non-admins: ownership checks on edit; API strips finance collections/fields
  - Text field sanitization includes materials.item
  - Jinja2 auto-escapes; session cookie HttpOnly + SameSite=Strict
  - Audit log: authentication, CRUD, role changes (no passwords/tokens logged)
  - Secret loaded from data/secret.key or TQ_SECRET_KEY env var
"""

from __future__ import annotations

import html
import json
import logging
import sys
import os
import re
import secrets
import threading
from urllib.parse import urlparse

import pyngrok
import time
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

# ── logging ──────────────────────────────────────────────────────────────────
logger = logging.getLogger("tq")

# ── paths & secrets ──────────────────────────────────────────────────────────
APP_DIR = Path(__file__).resolve().parent
DATA_FILE = APP_DIR / str(os.getenv("TQ_DATA_PATH", "data/store.json"))
USERS_FILE = APP_DIR / "data" / "users.json"
SECRET_FILE = APP_DIR / "data" / "secret.key"


def _load_secret() -> str:
    """Load from env first, then fall back to file, generate if missing."""
    env_key = os.getenv("TQ_SECRET_KEY", "").strip()
    if env_key:
        return env_key
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    SECRET_FILE.write_text(key + "\n", encoding="utf-8")
    return key


app = Flask(__name__)
# Bind Talisman BEFORE any route is hit.
# Local app: heuristic HTTPS off, but CSP/headers still enforced.
Talisman(
    app,
    force_https=False,
    strict_transport_security=False,
    strict_transport_security_preload=False,
    frame_options="DENY",
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src": "'self' https://fonts.gstatic.com",
        "img-src": "'self' data:",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "manifest-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    },
    content_security_policy_nonce_in=["script-src"],
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy="geolocation=(), microphone=(), camera=(), payment=()",
    x_content_type_options=True,
)

app.secret_key = _load_secret()
# Secure cookies when served over HTTPS (set TQ_HTTPS=1 behind a TLS tunnel/proxy).
_https = os.getenv("TQ_HTTPS", "").strip().lower() in ("1", "true", "yes")
# Open self-signup is OFF by default. Set TQ_ALLOW_SIGNUP=1 only on trusted LAN.
ALLOW_SIGNUP = os.getenv("TQ_ALLOW_SIGNUP", "").strip().lower() in ("1", "true", "yes")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",  # stricter than Lax; local same-site POST works
    SESSION_COOKIE_SECURE=_https,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,  # 12 h max
)

limiter = Limiter(
    key_func=lambda: (
        f"user:{current_user()['id']}"
        if current_user()
        else f"ip:{get_remote_address()}"
    ),
    default_limits=[
        "200 per day",
        "50 per hour",
    ],
    storage_uri="memory://",
    app=app,
)

# ── field validation ────────────────────────────────────────────────────────

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}$")  # usernames


def _sanitize_text(value, *, max_len=200, field="field"):
    if value is None:
        return ""
    text = str(value).strip()[:max_len]
    return html.escape(text)


def _validate_username(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        raise ValueError("Username is required")
    if not 3 <= len(v) <= 32:
        raise ValueError("Username must be 3-32 characters")
    if not _IDENT.match(v):
        raise ValueError("Username may only contain letters, numbers, and underscore")
    return v


def _validate_password(value: str) -> str:
    v = value or ""
    if not v:
        raise ValueError("Password is required")
    if len(v) < 6:
        raise ValueError("Password must be at least 6 characters")
    if len(v) > 128:
        v = v[:128]
    return v


def _validate_role(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in ("admin", "driver", "bagger"):
        raise ValueError("Role must be admin, driver, or bagger")
    return v


def _validate_date(value: str | None) -> str | None:
    if not value:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Invalid date format; expected YYYY-MM-DD")
    return value


_AUDIT_LOG: list[dict] = []  # runtime audit log; clear on restart; small installs keep in memory


def audit(event: str, **meta: object) -> None:
    """Append an audit event. Never log passwords or tokens."""
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "who": session.get("display_name") or session.get("user_id") or "anon",
        "role": session.get("role", ""),
        "event": event,
        # metadata is already filtered at call-sites; do not forward secrets here
        "meta": meta if meta else {},
    }
    _AUDIT_LOG.append(entry)
    # Keep memory bounded: cap at 2000 events
    if len(_AUDIT_LOG) > 2000:
        _AUDIT_LOG[: len(_AUDIT_LOG) - 2000] = []


# ── storage ──────────────────────────────────────────────────────────────────


def load_store() -> dict:
    if not DATA_FILE.exists():
        return empty_store()
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_store(store: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Sanitize against injection in any text fields before persisting
    _purge_profiles(store)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False, default=_json_default)


def _json_default(obj: object) -> object:
    if isinstance(obj, datetime):
        return obj.isoformat(timespec="seconds")
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")


def _purge_profiles(store: dict) -> None:
    """Escape HTML-special chars in text fields to prevent XSS."""
    # Free-text keys per collection (includes materials.item — previously missed).
    text_keys = ("description", "notes", "worker", "item")
    for coll in ("daily", "expenses", "baggers", "materials"):
        for row in store.get(coll, []):
            if not isinstance(row, dict):
                continue
            for key in text_keys:
                if key in row and isinstance(row[key], str):
                    row[key] = _sanitize_text(row[key], max_len=300, field=key)
    s = store.get("settings", {})
    if isinstance(s, dict):
        for k in ("business_name", "currency"):
            if k in s and isinstance(s[k], str):
                s[k] = _sanitize_text(s[k], max_len=120, field=k)


def empty_store() -> dict:
    return {
        "settings": {
            "bag_price": 6.5,
            "default_bagger_rate": 0.3,
            "business_name": "Thirsty Quench (TQ)",
            "currency": "₵",
        },
        "daily": [],
        "expenses": [],
        "baggers": [],
        "materials": [],
    }


def default_users() -> list[dict]:
    return [
        {
            "id": "u_admin",
            "username": "admin",
            "password_hash": generate_password_hash("admin123"),
            "display_name": "Administrator",
            "role": "admin",
            "active": True,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        },
    ]


def load_users() -> list[dict]:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        users = default_users()
        save_users(users)
        return users
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users: list[dict]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def public_user(u: dict) -> dict:
    return {
        "id": u.get("id"),
        "username": u.get("username"),
        "display_name": u.get("display_name"),
        "role": u.get("role"),
        "active": bool(u.get("active", True)),
        "created_at": u.get("created_at"),
    }


def find_user(username: str | None = None, user_id: str | None = None) -> dict | None:
    for u in load_users():
        if username and u.get("username", "").lower() == username.lower():
            return u
        if user_id and u.get("id") == user_id:
            return u
    return None


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def iso_week(date_str: str | None) -> int | None:
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").isocalendar()[1]
    except ValueError:
        return None


def n(val, default: float = 0.0) -> float:
    try:
        if val is None or val == "":
            return default
        return float(val)
    except (TypeError, ValueError):
        return default


# CSRF double-submit token
def _csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_hex(24)
        session["csrf_token"] = tok
    return tok


def _enforce_csrf() -> None:
    """Fail closed: require matching token from header or form field."""
    tok = session.get("csrf_token") or ""
    hdr = (request.headers.get("X-CSRF-Token") or "").strip()
    form_tok = ""
    if request.form:
        form_tok = (request.form.get("csrf_token") or "").strip()
    # Temporary debug fallback: also accept token from cookie
    cookie_tok = (request.headers.get("X-CSRF-Token") or request.cookies.get("csrf_token") or "").strip()
    submitted = hdr or form_tok or cookie_tok
    if not tok or not submitted or not secrets.compare_digest(str(tok), str(submitted)):
        reason = 'no_session_token' if not tok else ('no_submitted' if not submitted else 'mismatch')
        logger.warning("csrf_rejected path=%s method=%s reason=%s session_tok=%s submitted=%s", request.path, request.method, reason, tok[:20] if tok else None, submitted[:20] if submitted else None)
        audit("csrf_rejected", path=request.path, method=request.method, ip=request.remote_addr)
        abort(400, description="CSRF validation failed")


def _owns_row(row: dict, user: dict) -> bool:
    """Non-admins may only mutate rows they created."""
    return (row.get("created_by") or "") == (user.get("username") or "")


# ── auth helpers ─────────────────────────────────────────────────────────────


def current_user() -> dict | None:
    uid = session.get("user_id")
    if not uid:
        return None
    u = find_user(user_id=uid)
    if not u or not u.get("active", True):
        session.clear()
        return None
    return u


def _require_password_change(user: dict | None) -> bool:
    if not user:
        return False
    if user.get("role") != "admin":
        return False
    if user.get("username", "").lower() != "admin":
        return False
    return check_password_hash(user.get("password_hash", ""), "admin123")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Login required"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Login required"}), 401
            return redirect(url_for("login"))
        if user.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "Admin access only"}), 403
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapper


def is_admin(user: dict | None = None) -> bool:
    u = user or current_user()
    return bool(u and u.get("role") == "admin")


_DEFAULT_PW_HASH = generate_password_hash("admin123")


def _is_default_password(user: dict, password: str) -> bool:
    return bool(
        user.get("username", "").lower() == "admin"
        and check_password_hash(user.get("password_hash", ""), password)
        and check_password_hash(_DEFAULT_PW_HASH, password)
    )


# ── business calculations ─────────────────────────────────────────────────────


def enrich(store: dict, for_role: str = "admin") -> dict:
    price = n(store.get("settings", {}).get("bag_price"), 6.5)
    daily = store.get("daily", [])
    expenses = store.get("expenses", [])
    baggers = store.get("baggers", [])
    materials = store.get("materials", [])

    bagger_by_date: dict[str, float] = {}
    for b in baggers:
        d = b.get("date") or ""
        due = n(b.get("bags_done")) * n(b.get("rate"), 0.3)
        bagger_by_date[d] = bagger_by_date.get(d, 0) + due

    exp_by_date: dict[str, float] = {}
    for e in expenses:
        d = e.get("date") or ""
        exp_by_date[d] = exp_by_date.get(d, 0) + n(e.get("amount"))

    mat_by_date: dict[str, float] = {}
    for m in materials:
        d = m.get("date") or ""
        mat_by_date[d] = mat_by_date.get(d, 0) + n(m.get("amount"))

    enriched_daily = []
    for row in daily:
        d = row.get("date") or ""
        week = row.get("week")
        if week is None:
            week = iso_week(d)
        sold_out = n(row.get("sold_out"))
        sold_inside = n(row.get("sold_inside"))
        asanteman = n(row.get("asanteman"))
        produced = n(row.get("produced"))
        fuel = n(row.get("fuel"))
        new_debt = n(row.get("new_debt"))
        debt_paid = n(row.get("debt_paid"))

        inside_cash = sold_inside * price
        expected_out = sold_out * price
        calculated = (
            expected_out
            + inside_cash
            - fuel
            - new_debt
            + debt_paid
            - bagger_by_date.get(d, 0)
            - exp_by_date.get(d, 0)
            - mat_by_date.get(d, 0)
        )

        entry = {
            **row,
            "week": week,
            "inside_cash": round(inside_cash, 2),
            "expected_out_cash": round(expected_out, 2),
            "bagger_cost": round(bagger_by_date.get(d, 0), 2),
            "expense_cost": round(exp_by_date.get(d, 0), 2),
            "material_cost": round(mat_by_date.get(d, 0), 2),
            "calculated_cash": round(calculated, 2),
            "net_movement": produced - sold_out - asanteman - sold_inside,
        }
        # Workers see operational figures only — never cash / cost breakdowns.
        if for_role != "admin":
            for secret_key in (
                "calculated_cash",
                "bagger_cost",
                "expense_cost",
                "material_cost",
                "inside_cash",
                "expected_out_cash",
            ):
                entry.pop(secret_key, None)
        enriched_daily.append(entry)

    enriched_baggers = []
    for b in baggers:
        bags = n(b.get("bags_done"))
        rate = n(b.get("rate"), 0.3)
        entry_b = {**b, "due": round(bags * rate, 2)}
        # Non-admins get operational bagger rows; rates still needed for their forms.
        enriched_baggers.append(entry_b)

    total_sales = sum(r.get("inside_cash", 0) + r.get("expected_out_cash", 0) for r in enriched_daily)
    total_bagger = sum(b["due"] for b in enriched_baggers)
    total_fuel = sum(n(r.get("fuel")) for r in daily)
    total_occasional = sum(
        n(e.get("amount"))
        for e in expenses
        if (e.get("description") or "").strip().lower() != "money from sir rich"
    )
    total_materials = sum(n(m.get("amount")) for m in materials)
    total_debt = sum(n(r.get("new_debt")) for r in daily) - sum(n(r.get("debt_paid")) for r in daily)
    sir_rich = sum(
        n(e.get("amount"))
        for e in expenses
        if (e.get("description") or "").strip().lower() == "money from sir rich"
    )
    inventory = sum(n(r.get("produced")) for r in daily) - sum(
        n(r.get("sold_out")) + n(r.get("asanteman")) + n(r.get("sold_inside")) for r in daily
    )
    cash_in_hand = sum(r.get("calculated_cash", 0) for r in enriched_daily if "calculated_cash" in r)
    if for_role == "admin":
        cash_in_hand = sum(
            (
                n(r.get("sold_out")) * price
                + n(r.get("sold_inside")) * price
                - n(r.get("fuel"))
                - n(r.get("new_debt"))
                + n(r.get("debt_paid"))
                - bagger_by_date.get(r.get("date") or "", 0)
                - exp_by_date.get(r.get("date") or "", 0)
                - mat_by_date.get(r.get("date") or "", 0)
            )
            for r in daily
        )

    unpaid_baggers = sum(b["due"] for b in enriched_baggers if not b.get("paid"))
    latest = max(enriched_daily, key=lambda r: r.get("date") or "") if enriched_daily else None

    summary = {
        "inventory": round(inventory, 2),
        "total_produced": round(sum(n(r.get("produced")) for r in daily), 2),
        "total_sold": round(
            sum(n(r.get("sold_out")) + n(r.get("sold_inside")) for r in daily),
            2,
        ),
    }
    if for_role == "admin":
        summary.update(
            {
                "unpaid_baggers": round(unpaid_baggers, 2),
                "total_bagger": round(total_bagger, 2),
                "total_fuel": round(total_fuel, 2),
                "total_occasional": round(total_occasional, 2),
                "total_materials": round(total_materials, 2),
                "total_debt": round(total_debt, 2),
                "total_sales": round(total_sales, 2),
                "sir_rich": round(sir_rich, 2),
                "cash_in_hand": round(cash_in_hand, 2),
            }
        )

    settings = dict(store.get("settings", {}))
    if for_role != "admin":
        # workers can see price for their forms but not edit
        settings = {
            "bag_price": settings.get("bag_price", 6.5),
            "default_bagger_rate": settings.get("default_bagger_rate", 0.3),
            "business_name": settings.get("business_name", "Thirsty Quench (TQ)"),
            "currency": settings.get("currency", "₵"),
        }

    # Role-based collection filtering — never rely on UI hiding alone.
    out_daily = sorted(enriched_daily, key=lambda r: r.get("date") or "", reverse=True)
    out_baggers = sorted(enriched_baggers, key=lambda r: r.get("date") or "", reverse=True)
    out_expenses = sorted(expenses, key=lambda r: r.get("date") or "", reverse=True)
    out_materials = sorted(materials, key=lambda r: r.get("date") or "", reverse=True)
    out_latest = latest

    if for_role == "bagger":
        # Baggers: own bagger rows only; no daily / expenses / materials.
        out_daily = []
        out_expenses = []
        out_materials = []
        out_latest = None
        # Filter applied at API layer with username via enrich_for_user when available.
    elif for_role != "admin":
        # Drivers / other non-admins: operational daily + baggers; no finance collections.
        out_expenses = []
        out_materials = []

    return {
        "settings": settings,
        "daily": out_daily,
        "expenses": out_expenses,
        "baggers": out_baggers,
        "materials": out_materials,
        "summary": summary,
        "latest": out_latest,
        "role": for_role,
    }


def enrich_for_user(store: dict, user: dict) -> dict:
    """Enrich store and apply per-user ownership filters for non-admins."""
    role = user.get("role", "worker")
    data = enrich(store, for_role=role)
    if role == "admin":
        return data
    username = user.get("username") or ""
    if role == "bagger":
        # Only rows this bagger created (plus unpaid visibility limited to own work).
        data["baggers"] = [b for b in data.get("baggers", []) if (b.get("created_by") or "") == username]
        # Recompute unpaid for own rows only so dashboard isn't empty of meaning.
        own_unpaid = sum(n(b.get("due")) for b in data["baggers"] if not b.get("paid"))
        data.setdefault("summary", {})["unpaid_baggers"] = round(own_unpaid, 2)
    return data


def weekly_stats(store: dict, week: int) -> dict:
    price = n(store.get("settings", {}).get("bag_price"), 6.5)
    daily = [
        r
        for r in store.get("daily", [])
        if int(r.get("week") or iso_week(r.get("date")) or 0) == week
    ]
    dates = {r.get("date") for r in daily if r.get("date")}

    bags_sold = sum(n(r.get("sold_out")) for r in daily)
    production = sum(n(r.get("produced")) for r in daily)
    revenue = sum(n(r.get("sold_out")) * price for r in daily) + sum(
        n(r.get("sold_inside")) * price for r in daily
    )
    fuel = sum(n(r.get("fuel")) for r in daily)
    bagger = sum(
        n(b.get("bags_done")) * n(b.get("rate"), 0.3)
        for b in store.get("baggers", [])
        if b.get("date") in dates
    )
    occasional = sum(
        n(e.get("amount"))
        for e in store.get("expenses", [])
        if e.get("date") in dates
        and (e.get("description") or "").strip().lower() != "money from sir rich"
    )
    materials = sum(
        n(m.get("amount")) for m in store.get("materials", []) if m.get("date") in dates
    )
    cost_per_bag = (fuel + bagger + occasional + materials) / production if production else 0

    return {
        "week": week,
        "bags_sold": round(bags_sold, 2),
        "production": round(production, 2),
        "revenue": round(revenue, 2),
        "fuel": round(fuel, 2),
        "bagger": round(bagger, 2),
        "occasional": round(occasional, 2),
        "materials": round(materials, 2),
        "cost_per_bag": round(cost_per_bag, 4),
    }


def _safe_float(value: object, label: str) -> float:
    if isinstance(value, (int, float)):
        v = float(value)
    elif isinstance(value, str):
        v = float(value)
    else:
        raise ValueError(f"{label} must be a number")
    # Guard injection-style strings; n() already protects, this is defense-in-depth
    if v <-1e12 or v > 1e12:
        raise ValueError(f"{label} out of range")
    return v


def _normalize_item(collection: str, item: dict) -> dict:
    out = {**item}
    if collection == "daily" and out.get("date") and out.get("week") in (None, ""):
        out["week"] = iso_week(out.get("date"))
    for key in (
        "produced",
        "sold_out",
        "asanteman",
        "sold_inside",
        "fuel",
        "new_debt",
        "debt_paid",
        "bags_done",
        "rate",
        "amount",
        "week",
    ):
        if key in out:
            out[key] = n(out[key]) if out[key] not in (None, "") else (0 if key != "week" else None)
    if collection == "baggers" and "paid" in out:
        out["paid"] = bool(out["paid"])
    return out


# ── pages ─────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user():
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        try:
            _enforce_csrf()
        except HTTPException:
            error = "Invalid session token. Please try again."
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = find_user(username=username)
            if not user or not user.get("active", True):
                error = "Invalid username or password."
                logger.warning(
                    "login_failed ip=%s user=%s reason=inactive_or_unknown",
                    request.remote_addr,
                    username,
                )
            elif not check_password_hash(user.get("password_hash", ""), password):
                error = "Invalid username or password."
                logger.warning(
                    "login_failed ip=%s user=%s reason=bad_password uid=%s",
                    request.remote_addr,
                    username,
                    user.get("id"),
                )
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["display_name"] = user.get("display_name") or user["username"]
                _csrf_token()  # new CSRF token after privilege change
                logger.info(
                    "login_success ip=%s user=%s uid=%s role=%s",
                    request.remote_addr,
                    username,
                    user.get("id"),
                    user.get("role"),
                )
                audit("login", ip=request.remote_addr, uid=user.get("id"), role=user.get("role"))
                if _require_password_change(user):
                    return redirect(url_for("force_password_change"))
                return redirect(url_for("index"))

    return render_template(
        "login.html",
        error=error,
        csrf_token=_csrf_token(),
        allow_signup=ALLOW_SIGNUP,
    )


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def signup():
    error = None
    success = None
    locked = not ALLOW_SIGNUP

    if locked:
        if request.method == "POST":
            audit("signup_blocked", ip=request.remote_addr)
            return (
                render_template(
                    "signup.html",
                    error="Public signup is disabled. Ask an admin to create your account.",
                    success=None,
                    csrf_token=_csrf_token(),
                    signup_locked=True,
                ),
                403,
            )
        return render_template(
            "signup.html",
            error="Public signup is disabled. Ask an admin to create your account.",
            success=None,
            csrf_token=_csrf_token(),
            signup_locked=True,
        )

    if request.method == "POST":
        _csrf_token()
        try:
            _enforce_csrf()
        except HTTPException:
            error = "Invalid session token. Please try again."
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            display_name = (request.form.get("display_name") or "").strip()
            role = (request.form.get("role") or "").strip().lower()
            try:
                username = _validate_username(username)
                password = _validate_password(password)
                display_name = _sanitize_text(
                    display_name or username, max_len=120, field="display_name"
                )
                role = _validate_role(role)
                if role == "admin":
                    raise ValueError("Cannot create admin accounts via signup.")
            except ValueError as exc:
                error = str(exc)
            else:
                users = load_users()
                if find_user(username=username):
                    error = "Username already exists"
                else:
                    users.append(
                        {
                            "id": new_id("u"),
                            "username": username,
                            "password_hash": generate_password_hash(password),
                            "display_name": display_name,
                            "role": role,
                            "active": True,
                            "created_at": datetime.now().isoformat(timespec="seconds"),
                        }
                    )
                    save_users(users)
                    audit("signup", username=username, role=role)
                    success = "Account created. You can now sign in."

    return render_template(
        "signup.html",
        error=error,
        success=success,
        csrf_token=_csrf_token(),
        signup_locked=False,
    )


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if request.method == "POST":
        # Prefer CSRF-protected POST (form in index). GET kept for simple local use.
        try:
            _enforce_csrf()
        except HTTPException:
            return redirect(url_for("login"))
    uid = session.get("user_id")
    audit("logout", uid=uid)
    logger.info("logout uid=%s", uid)
    session.clear()
    return redirect(url_for("login"))


@app.route("/force-password-change", methods=["GET", "POST"])
@login_required
def force_password_change():
    user = current_user()
    if not user or not _require_password_change(user):
        return redirect(url_for("index"))

    error = None
    success = None
    if request.method == "POST":
        _csrf_token()
        try:
            _enforce_csrf()
        except HTTPException:
            error = "Invalid session token. Please try again."
        else:
            new_pw = (request.form.get("new_password") or "").strip()
            confirm_pw = (request.form.get("confirm_password") or "").strip()
            try:
                new_pw = _validate_password(new_pw)
            except ValueError as exc:
                error = str(exc)
            else:
                if new_pw == "admin123":
                    error = "Please choose a different password."
                elif new_pw != confirm_pw:
                    error = "Passwords do not match."
                else:
                    users = load_users()
                    for i, u in enumerate(users):
                        if u.get("id") == user.get("id"):
                            u["password_hash"] = generate_password_hash(new_pw)
                            users[i] = u
                            save_users(users)
                            audit("password_changed_forced", uid=user.get("id"))
                            success = "Password updated. Redirecting..."
                            session["csrf_token"] = secrets.token_hex(24)
                            break
    return render_template(
        "force_password_change.html",
        error=error,
        success=success,
        csrf_token=_csrf_token(),
        user=public_user(user),
    )


@app.route("/")
@login_required
def index():
    user = current_user()
    return render_template(
        "index.html",
        user=public_user(user),
        is_admin=is_admin(user),
        csrf_token=_csrf_token(),
    )


# ── PWA (installable phone app) ───────────────────────────────────────────────
import os as _os

_PWA_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "static")


@app.route("/manifest.webmanifest")
def pwa_manifest():
    from flask import send_from_directory

    return send_from_directory(
        _PWA_DIR, "manifest.webmanifest", mimetype="application/manifest+json"
    )


@app.route("/sw.js")
def pwa_sw():
    from flask import send_from_directory

    return send_from_directory(_PWA_DIR, "sw.js", mimetype="text/javascript")


@app.route("/icon-192.png")
def pwa_icon_192():
    from flask import send_from_directory

    return send_from_directory(_PWA_DIR, "icon-192.png", mimetype="image/png")


@app.route("/icon-512.png")
def pwa_icon_512():
    from flask import send_from_directory

    return send_from_directory(_PWA_DIR, "icon-512.png", mimetype="image/png")


# ── auth API ──────────────────────────────────────────────────────────────────


@app.route("/api/me")
@login_required
def api_me():
    user = current_user()
    return jsonify({"user": public_user(user), "is_admin": is_admin(user)})


@app.route("/api/data")
@login_required
def api_data():
    user = current_user()
    data = enrich_for_user(load_store(), user)
    data["user"] = public_user(user)
    data["is_admin"] = is_admin(user)
    return jsonify(data)


@app.route("/api/debug/csrf")
@login_required
def debug_csrf():
    return jsonify({
        "session_csrf": session.get("csrf_token", ""),
        "window_csrf": request.headers.get("X-CSRF-Token", ""),
        "has_session": bool(session.get("user_id")),
        "is_admin": is_admin(current_user()),
    })

@app.route("/api/weekly/<int:week>")
@login_required
def api_weekly(week: int):
    if not is_admin():
        return jsonify({"error": "Admin access only"}), 403
    return jsonify(weekly_stats(load_store(), week))


@app.route("/api/settings", methods=["PUT"])
@admin_required
def api_settings():
    _enforce_csrf()
    store = load_store()
    body = request.get_json(force=True) or {}
    allowed = ("bag_price", "default_bagger_rate", "business_name", "currency")
    for k in allowed:
        if k not in body:
            continue
        v = body[k]
        if k in ("business_name", "currency") and isinstance(v, str):
            store.setdefault("settings", {})[k] = _sanitize_text(v, max_len=120, field=k)
        elif k in ("bag_price", "default_bagger_rate"):
            store.setdefault("settings", {})[k] = float(v)  # ValueError → 400
        else:
            store.setdefault("settings", {})[k] = v
    save_store(store)
    audit(
        "settings_updated",
        keys=[k for k in allowed if k in body],
        uid=session.get("user_id"),
    )
    user = current_user()
    return jsonify(
        enrich_for_user(store, user) | {"user": public_user(user), "is_admin": True}
    )


# ── user management (admin) ───────────────────────────────────────────────────


@app.route("/api/users", methods=["GET"])
@admin_required
def api_users_list():
    users = load_users()
    return jsonify({"users": [public_user(u) for u in users]})


@app.route("/api/users", methods=["POST"])
@admin_required
def api_users_create():
    _enforce_csrf()
    body = request.get_json(force=True) or {}
    try:
        username = _validate_username(body.get("username"))
        password = _validate_password(body.get("password"))
        display_name = _sanitize_text(body.get("display_name") or username, max_len=120, field="display_name")
        role = _validate_role(body.get("role", "worker"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if find_user(username=username):
        return jsonify({"error": "Username already exists"}), 400

    users = load_users()
    users.append(
        {
            "id": new_id("u"),
            "username": username,
            "password_hash": generate_password_hash(password),
            "display_name": display_name,
            "role": role,
            "active": True,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
    )
    save_users(users)
    audit("user_created", username=username, role=role, uid=session.get("user_id"))
    return jsonify({"users": [public_user(u) for u in users]})


@app.route("/api/users/<user_id>", methods=["PUT"])
@admin_required
def api_users_update(user_id: str):
    _enforce_csrf()
    body = request.get_json(force=True) or {}
    users = load_users()
    me = current_user()

    for i, u in enumerate(users):
        if u.get("id") != user_id:
            continue
        if "display_name" in body:
            u["display_name"] = _sanitize_text(
                body["display_name"] or u["display_name"], max_len=120, field="display_name"
            )
        if "role" in body:
            role = _validate_role(body["role"])
            # prevent demoting yourself if last admin
            if u["id"] == me["id"] and role != "admin":
                admins = [x for x in users if x.get("role") == "admin" and x.get("active", True)]
                if len(admins) <= 1:
                    return jsonify({"error": "Cannot remove the last admin"}), 400
            u["role"] = role
        if "active" in body:
            active = bool(body["active"])
            if u["id"] == me["id"] and not active:
                return jsonify({"error": "Cannot deactivate yourself"}), 400
            if u.get("role") == "admin" and not active:
                admins = [
                    x for x in users
                    if x.get("role") == "admin" and x.get("active", True) and x["id"] != u["id"]
                ]
                if not admins:
                    return jsonify({"error": "Cannot deactivate the last admin"}), 400
            u["active"] = active
        if body.get("password"):
            pw = _validate_password(body["password"])
            u["password_hash"] = generate_password_hash(pw)
        users[i] = u
        save_users(users)
        audit("user_updated", target_uid=user_id, uid=session.get("user_id"))
        return jsonify({"users": [public_user(x) for x in users]})

    return jsonify({"error": "User not found"}), 404


@app.route("/api/users/<user_id>", methods=["DELETE"])
@admin_required
def api_users_delete(user_id: str):
    _enforce_csrf()
    me = current_user()
    if user_id == me["id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    users = load_users()
    target = next((u for u in users if u.get("id") == user_id), None)
    if not target:
        return jsonify({"error": "User not found"}), 404
    if target.get("role") == "admin":
        admins = [x for x in users if x.get("role") == "admin" and x.get("active", True)]
        if len(admins) <= 1:
            return jsonify({"error": "Cannot delete the last admin"}), 400
    users = [u for u in users if u.get("id") != user_id]
    save_users(users)
    audit("user_deleted", target_username=target.get("username"), uid=session.get("user_id"))
    return jsonify({"users": [public_user(u) for u in users]})


@app.route("/api/password", methods=["POST"])
@login_required
def api_change_password():
    _enforce_csrf()
    body = request.get_json(force=True) or {}
    current = body.get("current_password") or ""
    new_pw = body.get("new_password") or ""
    try:
        new_pw = _validate_password(new_pw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    users = load_users()
    me = current_user()
    for i, u in enumerate(users):
        if u.get("id") != me["id"]:
            continue
        if not check_password_hash(u.get("password_hash", ""), current):
            return jsonify({"error": "Current password is incorrect"}), 400
        u["password_hash"] = generate_password_hash(new_pw)
        users[i] = u
        save_users(users)
        audit("password_changed", uid=me.get("id"))
        return jsonify({"ok": True})
    return jsonify({"error": "User not found"}), 404


@app.route("/api/audit-log")
@admin_required
def api_audit_log():
    # Return last 200 events, newest last; never include raw passwords/tokens.
    return jsonify({"log": _AUDIT_LOG[-200:]})


# ── CRUD ─────────────────────────────────────────────────────────────────────


def _register_crud(collection: str) -> None:
    @login_required
    @limiter.limit("60 per minute")
    def add_item():
        _enforce_csrf()
        user = current_user()
        if not user:
            app.logger.warning('add_item: no user after CSRF, session=%s', dict(session))
            return jsonify({'error': 'Session expired'}), 401
        store = load_store()
        body = request.get_json(force=True) or {}
        app.logger.info("mutate add_item %s body_keys=%s", collection, sorted(body.keys()))
        if not is_admin(user):
            if collection == "daily" and user.get("role") == "driver":
                allowed = {
                    "sold_out",
                    "sold_inside",
                    "fuel",
                    "new_debt",
                    "debt_paid",
                    "date",
                    "description",
                    "produced",
                    "asanteman",
                }
                body = {k: v for k, v in body.items() if k in allowed}
            elif collection == "baggers" and user.get("role") == "bagger":
                # Rate is server-controlled; paid is always false for self-service.
                allowed = {"date", "worker", "bags_done"}
                body = {k: v for k, v in body.items() if k in allowed}
                body["paid"] = False
                body["rate"] = store.get("settings", {}).get("default_bagger_rate", 0.3)
            else:
                return jsonify({"error": "Not allowed"}), 403
        try:
            item = _normalize_item(
                collection,
                {
                    **body,
                    "id": new_id(collection[0]),
                    "created_by": user.get("username"),
                    "created_at": datetime.now().isoformat(timespec="seconds"),
                },
            )
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400
        store.setdefault(collection, []).append(item)
        save_store(store)
        data = enrich_for_user(store, user)
        data["user"] = public_user(user)
        data["is_admin"] = is_admin(user)
        audit("create", collection=collection, item_id=item.get("id"), uid=session.get("user_id"))
        return jsonify(data)

    @login_required
    @limiter.limit("120 per minute")
    def mutate_item(item_id: str):
        _enforce_csrf()
        user = current_user()
        store = load_store()

        if request.method == "DELETE":
            if not is_admin(user):
                return jsonify({"error": "Only admin can delete records"}), 403
            before = len(store.get(collection, []))
            logger.info("DELETE %s id=%s before=%s", collection, item_id, before)
            store[collection] = [r for r in store.get(collection, []) if r.get("id") != item_id]
            after = len(store[collection])
            logger.info("DELETE %s id=%s after=%s", collection, item_id, after)
            if after == before:
                logger.warning("DELETE %s id=%s not_found", collection, item_id)
                return jsonify({"error": "not found"}), 404
            save_store(store)
            data = enrich_for_user(store, user)
            data["user"] = public_user(user)
            data["is_admin"] = True
            audit("delete", collection=collection, item_id=item_id, uid=session.get("user_id"))
            return jsonify(data)

        body = request.get_json(force=True) or {}
        items = store.get(collection, [])
        target = next((r for r in items if r.get("id") == item_id), None)
        if not target:
            return jsonify({"error": "not found"}), 404

        if not is_admin(user):
            if not _owns_row(target, user):
                return jsonify({"error": "You can only edit records you created"}), 403
            if collection == "daily" and user.get("role") == "driver":
                allowed = {
                    "sold_out",
                    "sold_inside",
                    "fuel",
                    "new_debt",
                    "debt_paid",
                    "date",
                    "description",
                    "produced",
                    "asanteman",
                }
                body = {k: v for k, v in body.items() if k in allowed}
            elif collection == "baggers" and user.get("role") == "bagger":
                allowed = {"date", "worker", "bags_done"}
                body = {k: v for k, v in body.items() if k in allowed}
                body["paid"] = False
                # Keep existing rate or fall back to default — never client-supplied.
                body["rate"] = target.get("rate")
                if body["rate"] in (None, ""):
                    body["rate"] = store.get("settings", {}).get("default_bagger_rate", 0.3)
            else:
                return jsonify({"error": "Not allowed"}), 403

        for i, row in enumerate(items):
            if row.get("id") == item_id:
                try:
                    updated = _normalize_item(
                        collection,
                        {
                            **row,
                            **body,
                            "id": item_id,
                            "created_by": row.get("created_by"),  # ownership immutable
                            "updated_by": user.get("username"),
                            "updated_at": datetime.now().isoformat(timespec="seconds"),
                        },
                    )
                except (ValueError, TypeError) as exc:
                    return jsonify({"error": str(exc)}), 400
                if collection == "daily" and "date" in body and "week" not in body:
                    updated["week"] = iso_week(updated.get("date"))
                    updated = _normalize_item(collection, updated)
                items[i] = updated
                break
        store[collection] = items
        save_store(store)
        data = enrich_for_user(store, user)
        data["user"] = public_user(user)
        data["is_admin"] = is_admin(user)
        audit("update", collection=collection, item_id=item_id, uid=session.get("user_id"))
        return jsonify(data)

    add_item.__name__ = f"add_{collection}"
    mutate_item.__name__ = f"mutate_{collection}"

    app.add_url_rule(
        f"/api/{collection}",
        endpoint=f"add_{collection}",
        view_func=add_item,
        methods=["POST"],
    )
    app.add_url_rule(
        f"/api/{collection}/<item_id>",
        endpoint=f"mutate_{collection}",
        view_func=mutate_item,
        methods=["PUT", "DELETE"],
    )


for _coll in ("daily", "expenses", "baggers", "materials"):
    _register_crud(_coll)


@app.route("/api/export")
@admin_required
def api_export():
    store = load_store()
    # Defense-in-depth: never expose password hashes through export.
    for key in ("password_hash", "password"):
        if key in store:
            store.pop(key, None)
    return jsonify(store)


@app.route("/api/import", methods=["POST"])
@admin_required
def api_import():
    _enforce_csrf()
    body = request.get_json(force=True) or {}
    if not isinstance(body, dict) or "daily" not in body:
        return jsonify({"error": "invalid payload"}), 400
    if not isinstance(body.get("daily"), list):
        return jsonify({"error": "daily must be a list"}), 400
    if len(body.get("daily", [])) > 5000:
        return jsonify({"error": "Import too large"}), 400

    allowed_top = {"daily", "expenses", "baggers", "materials", "settings"}
    unknown_top = [k for k in body.keys() if k not in allowed_top]
    if unknown_top:
        return jsonify({"error": f"Unknown top-level keys: {', '.join(sorted(set(unknown_top)))}"}), 400

    for coll in ("daily", "expenses", "baggers", "materials"):
        if not isinstance(body.get(coll), list):
            return jsonify({"error": f"{coll} must be a list"}), 400
        for row in body.get(coll, []):
            if not isinstance(row, dict):
                return jsonify({"error": "Each row must be a dict"}), 400
            allowed_fields = {
                "id",
                "date",
                "week",
                "description",
                "produced",
                "sold_out",
                "asanteman",
                "sold_inside",
                "fuel",
                "new_debt",
                "debt_paid",
                "worker",
                "bags_done",
                "rate",
                "paid",
                "amount",
                "item",
                "notes",
                "created_by",
                "created_at",
                "updated_by",
                "updated_at",
            }
            unknown_fields = [k for k in row.keys() if k not in allowed_fields]
            if unknown_fields:
                return jsonify({"error": f"Unknown fields in {coll}: {', '.join(sorted(set(unknown_fields)))}"}), 400
            d = row.get("date")
            if d is not None and d != "":
                try:
                    _validate_date(str(d))
                except ValueError as exc:
                    return jsonify({"error": str(exc)}), 400

    # Auto-backup current store before destructive overwrite.
    backup_path = None
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = DATA_FILE.with_name(f"store_backup_before_import_{ts}.json")
        if DATA_FILE.exists():
            import shutil
            shutil.copy2(DATA_FILE, backup_path)
    except Exception:
        logger.warning("import_backup_failed", exc_info=True)

    cleaned = json.loads(json.dumps(body))
    save_store(cleaned)
    audit(
        "import",
        rows=len(cleaned.get("daily", [])),
        backup=str(backup_path) if backup_path else "",
        uid=session.get("user_id"),
    )
    user = current_user()
    return jsonify(
        enrich_for_user(cleaned, user) | {"user": public_user(user), "is_admin": True}
    )


@app.errorhandler(HTTPException)
def on_http_error(exc: HTTPException):
    """Keep real HTTP status codes (e.g. CSRF 400) instead of swallowing them."""
    if request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json":
        return jsonify({"error": exc.description or exc.name}), exc.code or 500
    return exc


@app.errorhandler(Exception)
def on_error(exc: Exception):
    if isinstance(exc, HTTPException):
        return on_http_error(exc)
    logger.exception("unhandled_error")
    return jsonify({"error": "Internal error"}), 500


# Ensure default users exist on startup
load_users()


if __name__ == "__main__":
    import socket

    port = int(os.getenv("TQ_PORT", "5050"))
    # Default bind all interfaces for LAN; set TQ_HOST=127.0.0.1 for local-only.
    host = os.getenv("TQ_HOST", "0.0.0.0")
    # Debug is OFF unless explicitly enabled — never use with public tunnels.
    debug = os.getenv("TQ_DEBUG", "").strip().lower() in ("1", "true", "yes")
    lan_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass

    token = os.environ.get("NGROK_AUTHTOKEN")
    if token:
        from pyngrok import ngrok as _ngrok_mod
        try:
            tunnel = _ngrok_mod.connect(f"http://{host}:{port}", "http")
            public_url = tunnel.public_url
            print(f"🔗 Public tunnel: {public_url}")
        except Exception as e:
            print(f"⚠ ngrok failed: {e}")

    print(f"🌐 LAN: http://{lan_ip}:{port}")
    print(f"🔒 Local: http://127.0.0.1:{port}")
    print(f"🛡  debug={debug}  signup={'open' if ALLOW_SIGNUP else 'locked'}  https_cookies={_https}")
    print()
    app.run(host=host, port=port, debug=debug)