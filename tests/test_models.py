import pyotp

from app import User


def test_password_hash_roundtrip():
    user = User(username="x", name="X", email="x@example.com", role="employee")
    user.set_password("correct horse battery staple")

    assert user.check_password("correct horse battery staple")
    assert not user.check_password("wrong password")


def test_totp_secret_generation_and_verification():
    user = User(username="y", name="Y", email="y@example.com", role="employee")
    user.generate_totp_secret()

    assert user.totp_secret
    assert user.totp_enabled is False  # not enabled until verified

    valid_code = pyotp.TOTP(user.totp_secret).now()
    assert user.verify_totp(valid_code) is True
    assert user.verify_totp("000000") is False


def test_verify_totp_without_secret_returns_false():
    user = User(username="z", name="Z", email="z@example.com", role="employee")
    assert user.verify_totp("123456") is False


def test_is_admin_property():
    admin = User(username="a", name="A", email="a@example.com", role="admin")
    employee = User(username="b", name="B", email="b@example.com", role="employee")

    assert admin.is_admin is True
    assert employee.is_admin is False
