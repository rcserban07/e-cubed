def test_unauthenticated_redirected_to_login(client):
    resp = client.get("/admin")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_employee_forbidden_from_admin_dashboard(client, do_login):
    do_login(client, "employee", "employee123")
    resp = client.get("/admin")
    assert resp.status_code == 403


def test_employee_forbidden_from_admin_users(client, do_login):
    do_login(client, "employee", "employee123")
    resp = client.get("/admin/users")
    assert resp.status_code == 403


def test_admin_can_access_admin_dashboard(client, do_login):
    do_login(client, "admin", "admin123")
    resp = client.get("/admin")
    assert resp.status_code == 200


def test_admin_can_access_employee_dashboard_too(client, do_login):
    do_login(client, "admin", "admin123")
    resp = client.get("/employee")
    assert resp.status_code == 200
