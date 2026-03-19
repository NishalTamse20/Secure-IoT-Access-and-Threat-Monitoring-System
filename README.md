# 🔐 Secure IoT Access and Threat Monitoring System

A full-stack cybersecurity platform for IoT device authentication, real-time threat detection, and automated incident response.

---

## 📌 Overview

This system provides secure mutual authentication for IoT devices using HMAC-SHA256 challenge-response, monitors security events through a custom SIEM engine, automates threat responses via a SOAR pipeline, and maintains a tamper-evident blockchain audit trail — all managed through a React admin dashboard.

---

## ✨ Features

- **HMAC-SHA256 Device Authentication** — Challenge-response with nonce expiry, replay-attack prevention, and constant-time comparison
- **JWT Role-Based Access Control** — Admin, user, and viewer roles with strict role escalation prevention
- **SIEM Engine** — 5 real-time detection rules: brute-force login, device enumeration, HMAC attacks, replay attacks, blockchain tampering
- **SOAR Automation** — Auto-blocks malicious IPs, locks compromised devices, triggers key rotation — zero manual intervention
- **Blockchain Audit Trail** — SHA-256 linked chain for tamper-evident device key rotation history
- **React Admin Dashboard** — 8 pages with live charts, filters, CSV export, and 30-second auto-refresh
- **Key Rotation Flow** — Pending → confirm two-phase rotation with blockchain record
- **Attack Simulation Script** — Generates brute-force, enumeration, and HMAC attack events for demo

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, SQLAlchemy, Flask-JWT-Extended |
| Auth | JWT, HMAC-SHA256, bcrypt |
| Database | SQLite |
| Frontend | React, TypeScript, Vite, Tailwind CSS, shadcn/ui |
| Charts | Chart.js, react-chartjs-2 |

---

## 📁 Project Structure

```
├── Backup(backend code base till phase 9)/
│   ├── app.py                  # App factory, seeding, startup
│   ├── models.py               # 7 SQLAlchemy models
│   ├── auth.py                 # Register, login, admin create-user
│   ├── device.py               # Device CRUD, challenge-response, revoke/grant
│   ├── siem.py                 # SIEM routes + dashboard stats/charts
│   ├── soar.py                 # SOAR routes, user management, blocked IPs
│   ├── siem_engine.py          # 5 detection rules
│   ├── soar_engine.py          # Automated response actions
│   ├── blockchain_engine.py    # SHA-256 chain, validate, get
│   ├── security.py             # bcrypt + HMAC helpers
│   ├── logging_engine.py       # SecurityEvent logger
│   ├── attack_simulation.py    # Demo attack script
│   ├── requirements.txt
│   └── .env
└── frontend/
    └── src/
        ├── services/api.ts
        ├── context/AuthContext.tsx
        ├── components/          # Sidebar, StatCard, badges, pagination
        └── pages/               # 8 pages: Overview, Devices, Events, Alerts,
                                 #          SOAR, Blockchain, Users, Login
```

---

## 🚀 Getting Started

### Backend

```bash
cd "Backup(backend code base till phase 9)"
python -m venv venv

# Windows
venv\Scripts\Activate.ps1

# macOS / Linux
source venv/bin/activate

python -m pip install -r requirements.txt
python app.py
```

Backend runs on **http://localhost:5000**

On first run, an admin account is auto-created:
```
Username: admin
Password: admin@123
```

### Frontend

```bash
cd frontend
npm install
npm install chart.js react-chartjs-2
npm run dev
```

Frontend runs on **http://localhost:8080**

---

## 🔑 Default Login

| Field | Value |
|---|---|
| URL | http://localhost:8080 |
| Username | `admin` |
| Password | `admin@123` |

---

## 🧪 Running the Attack Simulation

```bash
cd "Backup(backend code base till phase 9)"
python attack_simulation.py
```

Simulates:
- Brute-force login attempts (6 failed logins)
- Device enumeration flood (12 fake device requests)
- HMAC attack attempts (6 wrong HMAC responses)

After running, go to **Alerts** → click **Run Detections + SOAR** to see automated response.

---

## 🔄 Demo Reset

Run this before every demo to unblock IPs and unlock devices:

```bash
python -c "
from app import create_app
from models import db, BlockedIP, Device
app = create_app()
with app.app_context():
    BlockedIP.query.delete()
    for d in Device.query.filter_by(status='LOCKED').all():
        d.status = 'ACTIVE'
    db.session.commit()
    print('Reset complete')
"
```

---

## 🗃 Database Models

| Model | Purpose |
|---|---|
| `User` | Admin/user accounts with login tracking |
| `Device` | IoT device registry with key versioning |
| `DeviceNonce` | Challenge nonces with expiry |
| `SecurityEvent` | All logged security events |
| `Alert` | SIEM-detected threat alerts |
| `BlockedIP` | IPs blocked by SOAR automation |
| `BlockchainBlock` | Immutable key rotation audit trail |

---

## 🛡 Security Hardening

- Role escalation blocked on `/register` — public users can only get `viewer` or `user`
- HMAC validated as 64-char lowercase hex before any DB lookup
- CORS restricted to `http://localhost:8080` only via `.env`
- `debug=False` by default — controlled via `FLASK_DEBUG` env variable
- JWT expiry enforced via `JWT_EXPIRES_MINUTES` env variable
- Input length limits on all endpoints (username: 50, password: 128, device_id: 100)
- `db.session.rollback()` in every exception handler
- Nonce deleted **before** HMAC comparison — closes replay window
- `hmac.compare_digest()` for constant-time comparison
- Same error message for wrong username vs wrong password — prevents user enumeration
- Pagination enforced on all list endpoints — no unbounded `.query.all()`

---

## 📊 Dashboard Pages

| Page | Description |
|---|---|
| Overview | Stat cards, live events feed, 3 real-time charts |
| Devices | Register, revoke, unlock, grant access with key display |
| Security Events | Filterable event log with CSV export |
| Alerts | SIEM-detected threats with SOAR execution status |
| SOAR Actions | Manual pipeline controls + blocked IPs management |
| Blockchain | Chain validity, block explorer, key status history |
| Users | Full user management — create, disable, reset password, delete |

---
---

## 📄 License

This project is open for learning, reference, and contribution. Feel free to fork, explore, and build on top of it.
