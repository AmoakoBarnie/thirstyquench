# Thirsty Quench — Balance Sheet (Local Web App)

Professional multi-user balance sheet for **Thirsty Quench**, hosted on your PC for staff on the same Wi‑Fi.

## Start (host on this machine)

Double-click:

```
C:\Users\Amoako\TQ\webapp\start.bat
```

Or:

```powershell
cd C:\Users\Amoako\TQ\webapp
python app.py
```

| Access | URL |
|---|---|
| This PC | http://127.0.0.1:5050 |
| Workers on Wi‑Fi | http://YOUR-LAN-IP:5050 (printed in the console) |

Leave the server window open while people use the app.

## Default logins

| Role | Username | Password |
|---|---|---|
| **Admin** | `admin` | `admin123` |
| **Worker** | `worker` | `worker123` |

**Change these passwords immediately** after first login (My Account). Create staff accounts under **Users** (admin only).

## Security (hardening)

| Control | Default | Notes |
|---|---|---|
| Public signup | **Locked** | Set `TQ_ALLOW_SIGNUP=1` only on a trusted LAN if you need open signup |
| Debug mode | **Off** | Set `TQ_DEBUG=1` only on your own machine — never with tunnels |
| CSRF | **Required** | All mutating requests need a valid CSRF token |
| HTTPS cookies | Off | Set `TQ_HTTPS=1` when serving over TLS |
| Bind address | `0.0.0.0` | Set `TQ_HOST=127.0.0.1` for this-PC-only |

Workers may only **edit records they created**. Expenses/materials/cash fields are **not** returned to non-admin APIs.

## Permissions

### Admin
- Full dashboard (cash in hand, debt, Sir Rich, all totals)
- Add / edit / **delete** all records
- Mark bagger payments as paid
- Weekly cost, settings, import/export
- Create and manage user accounts

### Worker
- Sign in and enter daily production, bagger work, expenses, materials
- See operational dashboard (inventory, production, unpaid dues)
- Edit records they work with
- **Cannot** delete, change settings, manage users, or see full cash controls
- **Cannot** mark bagger pay as paid (admin settles pay)

## Data files

| File | Purpose |
|---|---|
| `data/store.json` | Business records |
| `data/users.json` | Login accounts (hashed passwords) |
| `data/secret.key` | Session security key |

Bag price default: **₵6.50**.
