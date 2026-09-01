import pytest

from app import limiter


@pytest.fixture(autouse=True)
def _enable_rate_limit(app):
    limiter.enabled = True
    limiter.reset()
    yield
    limiter.enabled = False
    limiter.reset()


def test_login_rate_limited_after_ten_requests(client):
    codes = [client.get("/login").status_code for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429
