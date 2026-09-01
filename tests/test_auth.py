import pyotp

from app import User, db


def test_login_success_redirects_to_admin_dashboard(client, do_login):
    resp = do_login(client, "admin", "admin123")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/admin"


def test_login_wrong_password_shows_error(client, do_login):
    resp = do_login(client, "admin", "wrong-password")
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_login_records_access_denied_on_failure(client, do_login, app):
    do_login(client, "admin", "wrong-password")
    with app.app_context():
        from app import AccessLog
        log = AccessLog.query.order_by(AccessLog.id.desc()).first()
        assert log.event_type == "access_denied"


def test_2fa_enabled_user_redirected_to_verification(client, do_login, app):
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        user.generate_totp_secret()
        user.totp_enabled = True
        db.session.commit()

    resp = do_login(client, "admin", "admin123")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/verify-2fa"


def test_2fa_correct_code_completes_login(client, do_login, app):
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        user.generate_totp_secret()
        user.totp_enabled = True
        db.session.commit()
        secret = user.totp_secret

    do_login(client, "admin", "admin123")
    code = pyotp.TOTP(secret).now()
    resp = client.post("/verify-2fa", data={"token": code, "submit": "Verify"})

    assert resp.status_code == 302
    assert resp.headers["Location"] == "/admin"


def test_2fa_wrong_code_rejected(client, do_login, app):
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        user.generate_totp_secret()
        user.totp_enabled = True
        db.session.commit()

    do_login(client, "admin", "admin123")
    resp = client.post("/verify-2fa", data={"token": "000000", "submit": "Verify"})

    assert resp.status_code == 200
    assert b"Invalid code" in resp.data


def test_logout_clears_session(client, do_login):
    do_login(client, "admin", "admin123")
    resp = client.get("/logout")
    assert resp.status_code == 302

    resp2 = client.get("/admin")
    assert resp2.status_code == 302
    assert "/login" in resp2.headers["Location"]
