# E-Cubed Security System

Enterprise access control dashboard with role-based authentication, real-time monitoring, and comprehensive access logging.

## Quick Start

### 1. Clone & install

```bash
git clone <your-repo-url>
cd e-cubed
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your preferred settings
```

### 3. Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

Default admin credentials (change these after first login):

- Username: `admin`
- Password: `admin123`

### Mobile Access (ngrok)

Location sharing requires HTTPS. For local development, use ngrok to create a secure tunnel:

```bash
# Install ngrok: https://ngrok.com/download (free account required)
ngrok http 5000
```

This gives you a URL like `https://xxxx-xxx.ngrok-free.app`. Open that URL on your phone's browser to access the app with full GPS support.

**Note:** The free ngrok tier gives you a random URL that changes each restart and shows an interstitial page on first visit. Tap "Visit Site" to proceed.

### Docker (alternative)

```bash
docker compose up --build
```

Runs the app under gunicorn + eventlet, reading config from `.env` and
persisting the SQLite database in a named volume across restarts.

Without Compose:

```bash
docker build -t ecube .
docker run -p 5000:5000 --env-file .env -v ecube-data:/app/instance ecube
```

### Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests run against a temporary SQLite database (created and torn down
automatically) — they never touch your local `.env` or `instance/ecube.db`.
Also runs automatically on every push/PR via GitHub Actions.

## Architecture

- **Backend**: Flask + Flask-Login + Flask-SQLAlchemy + Flask-SocketIO
- **Frontend**: Jinja2 templates + Tailwind CSS (CDN)
- **Database**: SQLite (default), easily swappable to PostgreSQL
- **Auth**: bcrypt password hashing, CSRF protection, role-based access, TOTP 2FA, login rate-limiting

## Project Structure

```
e-cubed/
├── app.py                  # Main application (models, routes, forms)
├── requirements.txt
├── requirements-dev.txt    # Adds pytest for running tests/
├── pytest.ini
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .github/workflows/tests.yml
├── tests/
│   ├── conftest.py         # Fixtures: isolated test DB, client, login helper
│   ├── test_auth.py
│   ├── test_rbac.py
│   ├── test_export.py
│   ├── test_rate_limit.py
│   └── test_models.py
├── templates/
│   ├── base.html           # Layout with sidebar navigation
│   ├── index.html          # Landing page
│   ├── login.html          # Login form
│   ├── admin/
│   │   ├── dashboard.html  # Command center with stats & live feed
│   │   ├── users.html      # Personnel management table
│   │   ├── register_user.html
│   │   ├── edit_user.html
│   │   └── logs.html       # Paginated access logs
│   ├── employee/
│   │   └── dashboard.html  # Employee personal dashboard
│   └── errors/
│       ├── 403.html
│       ├── 404.html
│       └── 500.html
└── instance/
    └── ecube.db            # SQLite database (auto-created)
```

## Roadmap

- [X]  **Phase 1**: Core backend, auth, UI shell
- [X]  **Phase 2**: Browser-based location tracking (Geolocation API + Leaflet maps)
- [X]  **Phase 3**: TOTP two-factor authentication (Google Authenticator / Microsoft Authenticator)
- [X]  **Phase 4**: Docker Compose, production hardening, export tools
