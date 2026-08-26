# NetGuardian – Smart Network Monitoring & Security System

NetGuardian is a practical network operations dashboard for homes, labs, classrooms, and small offices. It combines TCP/IP connectivity checks, network monitoring, authentication, security event logging, alerts, and a web dashboard.

## What it does

- Monitor user-defined hosts and TCP services.
- Measure TCP connection latency and availability.
- Track uptime, failures, and recent status.
- Detect repeated failed logins and create security alerts.
- Store monitoring and security events in SQLite.
- Provide a protected web dashboard and JSON API.
- Run periodic checks in a background worker.
- Include automated tests and GitHub Actions CI.

The project intentionally uses **authorized targets only**. It is a monitoring/operations tool, not a network scanner or exploitation framework.

## Architecture

Browser → Flask web/API → Monitoring service → TCP/IP targets
                         ↓
                       SQLite
                         ↓
                 Events + Alerts

Python's `socket` module provides the TCP networking layer. See the official Python socket documentation for the underlying API.

## Quick start

1. Create a virtual environment.
2. Install dependencies:

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

3. Set a strong secret key and admin password in your environment:

```bash
# Linux/macOS
export NETGUARDIAN_SECRET_KEY="change-this-to-a-long-random-value"
export NETGUARDIAN_ADMIN_PASSWORD="change-this-before-production"

# Windows PowerShell
$env:NETGUARDIAN_SECRET_KEY="change-this-to-a-long-random-value"
$env:NETGUARDIAN_ADMIN_PASSWORD="change-this-before-production"
```

4. Start the application:

```bash
python run.py
```

5. Open `http://127.0.0.1:5000` and sign in as `admin`.

On first start the application creates the database, seeds the admin account, and adds a safe localhost example target.

## Environment variables

- `NETGUARDIAN_SECRET_KEY` – Flask session signing key; required for production.
- `NETGUARDIAN_ADMIN_PASSWORD` – initial admin password; required for production.
- `NETGUARDIAN_DB` – SQLite database path, default `data/netguardian.db`.
- `NETGUARDIAN_CHECK_INTERVAL` – monitoring interval in seconds, default `30`.
- `NETGUARDIAN_HOST` – bind host, default `127.0.0.1`.
- `NETGUARDIAN_PORT` – bind port, default `5000`.
- `NETGUARDIAN_COOKIE_SECURE` – set `1` when served over HTTPS.

## Production notes

Run behind a real WSGI server and HTTPS reverse proxy. Change the initial password, set a random secret key, restrict the bind address/firewall, back up the SQLite database, and only monitor systems you own or are authorized to administer.

Security logging follows principles recommended by OWASP: authentication failures and security-relevant events are recorded without storing passwords or session secrets.

## Tests

```bash
pytest -q
```

## Project structure

```text
app/
  __init__.py       Application factory and background monitor
  config.py         Environment configuration
  db.py             SQLite schema and helpers
  security.py       Password hashing and authentication helpers
  monitor.py        TCP connectivity checks and monitor logic
  routes.py         Web pages and JSON API
  templates/        Dashboard/login pages
  static/           CSS and browser JavaScript
run.py              Development entry point
requirements.txt    Python dependencies
tests/              Automated tests
.github/workflows/  Continuous integration
```

## Educational topics demonstrated

1. **TCP/IP networking:** DNS resolution, IPv4/IPv6 address handling, TCP sockets, ports, timeouts and latency.
2. **Network monitoring:** periodic checks, availability percentage, response time, status history and alerts.
3. **Network security:** password hashing, authenticated sessions, login rate limiting, security events and operational alerting.
