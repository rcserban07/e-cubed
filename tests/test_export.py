def test_admin_users_export_returns_csv(client, do_login):
    do_login(client, "admin", "admin123")
    resp = client.get("/admin/users/export")

    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    body = resp.data.decode()
    assert "username,name,email" in body
    assert "admin" in body
    assert "employee" in body


def test_admin_logs_export_returns_csv(client, do_login):
    do_login(client, "admin", "admin123")
    resp = client.get("/admin/logs/export")

    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert "timestamp,event_type" in resp.data.decode()


def test_employee_forbidden_from_users_export(client, do_login):
    do_login(client, "employee", "employee123")
    resp = client.get("/admin/users/export")
    assert resp.status_code == 403


def test_employee_forbidden_from_logs_export(client, do_login):
    do_login(client, "employee", "employee123")
    resp = client.get("/admin/logs/export")
    assert resp.status_code == 403


def test_unauthenticated_forbidden_from_exports(client):
    resp = client.get("/admin/users/export")
    assert resp.status_code == 302
