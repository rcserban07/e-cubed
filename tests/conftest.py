import os
import tempfile

import pytest

# Must be set before `app` is imported, since app.py reads config from the
# environment at import time (and its top-level code runs db.create_all() /
# seed_admin() immediately on import).
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin123")
os.environ.setdefault("ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")
os.environ.setdefault("FLASK_DEBUG", "false")
os.environ.setdefault("SOCKETIO_CORS_ORIGINS", "*")

from app import app as flask_app, db, limiter, User  # noqa: E402

flask_app.config["WTF_CSRF_ENABLED"] = False

# Flask-Limiter caches `enabled` as an instance attribute during init_app,
# so toggling app.config["RATELIMIT_ENABLED"] afterward has no effect —
# mutate the instance directly instead.
limiter.enabled = False


@pytest.fixture(scope="session", autouse=True)
def _cleanup_db_file():
    yield
    with flask_app.app_context():
        db.engine.dispose()  # release Windows file lock before unlinking
    os.close(_db_fd)
    os.unlink(_db_path)


@pytest.fixture
def app():
    return flask_app


@pytest.fixture(autouse=True)
def _reset_database(app):
    """Wipe and reseed a known baseline before every test.

    The app uses a single global `db`/`app` (no app-factory pattern), so
    per-test isolation comes from resetting tables rather than building a
    fresh app instance.
    """
    with app.app_context():
        db.session.remove()  # drop any stale cached objects from the last test
        db.drop_all()
        db.create_all()

        admin = User(
            username="admin", name="Test Admin",
            email="admin@test.local", role="admin",
        )
        admin.set_password("admin123")

        employee = User(
            username="employee", name="Test Employee",
            email="employee@test.local", role="employee",
        )
        employee.set_password("employee123")

        db.session.add_all([admin, employee])
        db.session.commit()

    yield


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def do_login():
    def _do_login(client, username, password):
        return client.post(
            "/login",
            data={"username": username, "password": password, "submit": "Sign In"},
        )
    return _do_login
