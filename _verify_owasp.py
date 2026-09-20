"""OWASP / hardening verification for TQ webapp_dev."""
import json
import os

# Ensure signup stays locked during tests unless we flip it intentionally.
os.environ.pop("TQ_ALLOW_SIGNUP", None)
os.environ.pop("TQ_DEBUG", None)

from app import ALLOW_SIGNUP, app, _purge_profiles, _csrf_token

print("=" * 60)
print("HARDENING SECURITY VERIFICATION")
print("=" * 60)

fails = 0


def chk(name, got, exp):
    global fails
    ok = got == exp
    mark = "OK" if ok else "FAIL"
    print(f"  [{mark}] {name}: got {got!r}, expected {exp!r}")
    if not ok:
        fails += 1


with app.test_client() as c:
    # ── 1. Login requires CSRF ──────────────────────────────────────────
    r = c.post("/login", data={"username": "admin", "password": "admin123"})
    chk("Login without CSRF rejected-or-failed", r.status_code in (200, 400), True)

    r = c.get("/login")
    chk("Login page", r.status_code, 200)
    html = r.data.decode("utf-8", errors="replace")
    chk("Login form has csrf_token", 'name="csrf_token"' in html, True)

    # Extract csrf from session via cookie + re-render path
    with c.session_transaction() as sess:
        tok = sess.get("csrf_token")
        if not tok:
            # Force token into session the same way the app does
            import secrets as _sec

            tok = _sec.token_hex(24)
            sess["csrf_token"] = tok
    r = c.post(
        "/login",
        data={"username": "admin", "password": "admin123", "csrf_token": tok},
    )
    chk("Admin login with CSRF", r.status_code, 302)
    chk("Session cookie HttpOnly", "HttpOnly" in r.headers.get("Set-Cookie", ""), True)
    chk("SameSite=Strict", "SameSite=Strict" in r.headers.get("Set-Cookie", ""), True)

    # ── 2. Dashboard + CSRF meta ────────────────────────────────────────
    r = c.get("/")
    chk("Dashboard", r.status_code, 200)
    html = r.data.decode("utf-8", errors="replace")
    chk("csrf meta", 'name="csrf-token"' in html, True)
    chk("window.TQ_CSRF", "window.TQ_CSRF" in html, True)

    with c.session_transaction() as sess:
        admin_csrf = sess.get("csrf_token") or ""

    # ── 3. Protected API ────────────────────────────────────────────────
    r = c.get("/api/data")
    chk("/api/data", r.status_code, 200)
    j = r.get_json()
    chk("role=admin", j.get("role"), "admin")
    chk("admin sees expenses key", isinstance(j.get("expenses"), list), True)
    chk("admin sees materials key", isinstance(j.get("materials"), list), True)

    # ── 4. CSRF fail-closed on mutating API ─────────────────────────────
    r = c.put(
        "/api/settings",
        json={"bag_price": 6.5},
        headers={},  # no X-CSRF-Token
    )
    chk("Settings without CSRF -> 400", r.status_code, 400)
    body = r.get_json() or {}
    chk("CSRF error message", "CSRF" in (body.get("error") or "").upper(), True)

    r = c.put(
        "/api/settings",
        json={"bag_price": 6.5},
        headers={"X-CSRF-Token": admin_csrf},
    )
    chk("Settings with CSRF -> 200", r.status_code, 200)

    # ── 5. Worker / driver blocked from admin routes ────────────────────
    c2 = app.test_client()
    r = c2.get("/login")
    with c2.session_transaction() as sess:
        wtok = sess.get("csrf_token")
        if not wtok:
            import secrets as _sec

            wtok = _sec.token_hex(24)
            sess["csrf_token"] = wtok
    c2.post(
        "/login",
        data={"username": "worker", "password": "worker123", "csrf_token": wtok},
    )
    r = c2.get("/api/weekly/30")
    chk("Worker /api/weekly", r.status_code, 403)

    r = c2.get("/api/data")
    chk("Worker /api/data", r.status_code, 200)
    wj = r.get_json() or {}
    chk("Worker expenses empty", wj.get("expenses"), [])
    chk("Worker materials empty", wj.get("materials"), [])
    # Cash fields must not appear on daily rows
    daily0 = (wj.get("daily") or [{}])[0] if wj.get("daily") else {}
    if daily0:
        chk("No calculated_cash for worker", "calculated_cash" not in daily0, True)
        chk("No inside_cash for worker", "inside_cash" not in daily0, True)
        chk("No expected_out_cash for worker", "expected_out_cash" not in daily0, True)

    # ── 6. Ownership: worker cannot edit someone else's row ─────────────
    with c2.session_transaction() as sess:
        w_csrf = sess.get("csrf_token") or ""
    # Find a daily row not created by worker (or any row)
    store_daily = (c.get("/api/data").get_json() or {}).get("daily") or []
    foreign = next(
        (row for row in store_daily if row.get("created_by") not in (None, "", "worker")),
        store_daily[0] if store_daily else None,
    )
    if foreign and foreign.get("id"):
        # Ensure created_by is not worker — if missing, ownership still blocks non-owner
        r = c2.put(
            f"/api/daily/{foreign['id']}",
            json={"sold_out": 1},
            headers={"X-CSRF-Token": w_csrf},
        )
        # If worker created it, 200; otherwise 403
        if foreign.get("created_by") == "worker":
            chk("Worker can edit own daily", r.status_code, 200)
        else:
            chk("Worker blocked from foreign daily", r.status_code, 403)

    # ── 7. Admin weekly OK ──────────────────────────────────────────────
    r = c.get("/api/weekly/30")
    chk("Admin weekly", r.status_code, 200)

    # ── 8. Talisman headers ─────────────────────────────────────────────
    r = c.get("/")
    checks = {
        "Content-Security-Policy": "default-src",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "geolocation",
    }
    for hdr, frag in checks.items():
        chk(f"Header {hdr}", (r.headers.get(hdr) or "").startswith(frag) or frag in (r.headers.get(hdr) or ""), True)

    # ── 9. Audit log ────────────────────────────────────────────────────
    r = c.get("/api/audit-log")
    chk("/api/audit-log", r.status_code, 200)
    ad = r.get_json() or {}
    chk("Has 'log' key", "log" in ad, True)
    blob = json.dumps(ad.get("log", [])).lower()
    chk("No raw passwords in log", "password_hash" not in blob, True)

    # ── 10. Bad username rejected (with CSRF) ───────────────────────────
    r = c.post(
        "/api/users",
        json={"username": "<bad>", "password": "test123", "role": "driver"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    chk("Bad username", r.status_code, 400)

    # ── 11. Worker cannot delete ────────────────────────────────────────
    d0 = c2.get("/api/data").get_json() or {}
    sid = (d0.get("daily") or [{}])[0].get("id") if d0.get("daily") else None
    if sid:
        r = c2.delete(f"/api/daily/{sid}", headers={"X-CSRF-Token": w_csrf})
        chk("Worker DELETE blocked", r.status_code, 403)

    # ── 12. Signup locked by default ────────────────────────────────────
    chk("ALLOW_SIGNUP default False", ALLOW_SIGNUP, False)
    r = c.get("/signup")
    chk("Signup page locked message", r.status_code, 200)
    sh = r.data.decode("utf-8", errors="replace").lower()
    chk("Signup disabled text", "disabled" in sh or "ask an admin" in sh, True)
    r = c.post(
        "/signup",
        data={
            "username": "hacker1",
            "password": "hacker1",
            "display_name": "Hacker",
            "role": "driver",
            "csrf_token": "x",
        },
    )
    chk("Signup POST blocked", r.status_code, 403)

    # ── 13. XSS sanitization includes materials.item ────────────────────
    store = {
        "daily": [
            {
                "id": "xs2",
                "date": "2099-01-01",
                "description": "<script>alert(1)</script> owner",
                "produced": 1,
                "sold_out": 1,
            }
        ],
        "settings": {"business_name": "<img src=x onerror=alert(1)> TQ"},
        "expenses": [{"description": "<b>on</b> fuel", "amount": 5}],
        "baggers": [],
        "materials": [{"item": '<img src=x onerror=alert(1)>', "amount": 1}],
    }
    _purge_profiles(store)
    desc = store["daily"][0].get("description", "")
    biz = store["settings"].get("business_name", "")
    exp = store["expenses"][0].get("description", "")
    mat = store["materials"][0].get("item", "")
    chk("Daily: <script> stripped", "<script>" not in desc.lower(), True)
    chk("Settings: <img stripped", "<img" not in biz.lower(), True)
    chk("Expense: use &lt; not literal", "<b>" not in exp, True)
    chk("Materials item sanitized", "<img" not in mat.lower(), True)

    # ── 14. Bad date on import rejected ─────────────────────────────────
    r = c.post(
        "/api/import",
        json={"daily": [{"date": "not-a-date", "produced": 1, "sold_out": 1}]},
        headers={"X-CSRF-Token": admin_csrf},
    )
    chk("Bad date rejected", r.status_code, 400)

print()
if fails:
    print(f"RESULT: {fails} check(s) FAILED")
    raise SystemExit(1)
print("RESULT: all checks passed")
