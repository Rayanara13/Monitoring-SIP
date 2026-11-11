import yealink_setup


def login(srv, username="admin"):
    with srv.client.session_transaction() as session:
        session["logged_in"] = True
        session["username"] = username


def test_inspection_never_probes_an_unmatched_card_or_non_admin(srv, monkeypatch):
    def forbidden_probe(*args, **kwargs):
        raise AssertionError("Проверка не должна обращаться к телефону")

    monkeypatch.setattr(yealink_setup, "inspect_phone", forbidden_probe)
    payload = {"ip": "10.0.0.11", "username": "admin", "number": "101"}
    assert srv.client.post("/yealink/inspect", json=payload).status_code == 401
    srv.add_user("bob", [])
    login(srv, "bob")
    assert srv.client.post("/yealink/inspect", json=payload).status_code == 403
    login(srv)
    result = srv.client.post("/yealink/inspect", json={**payload, "number": "102"})
    assert result.status_code == 400 and result.get_json()["code"] == "card_mismatch"
    srv.phone("102")["ip"] = payload["ip"]
    assert srv.client.post("/yealink/inspect", json=payload).status_code == 400


def test_admin_gets_safe_profile_summary_from_server_side_access(srv, monkeypatch):
    login(srv)
    monkeypatch.setenv("YEALINK_ALLOWED_CIDRS", "10.0.0.0/24")
    monkeypatch.setenv("YEALINK_ADMIN_USER", "pilot-user")
    monkeypatch.setenv("YEALINK_ADMIN_PASSWORD", "pilot-password-secret")
    monkeypatch.setenv("YEALINK_CERT_SHA256", "a" * 64)
    expected = {"off_hook": "http://monitor/event?token=expected-token-secret"}

    def inspect(ip, **kwargs):
        assert ip == "10.0.0.11"
        assert kwargs["allowed_cidrs"] == ["10.0.0.0/24"]
        assert kwargs["username"] == "pilot-user" and kwargs["password"] == "pilot-password-secret"
        assert kwargs["certificate_sha256"] == "a" * 64
        assert kwargs["expected_urls"] == expected
        return {"status": "compatible", "compatible": True, "model": "SIP-T30",
                "firmware": "124.87.14.1", "mac": "00:15:65:AA:BB:CC",
                "fields": {"off_hook": "match"}, "counts": {"match": 1}}

    monkeypatch.setattr(yealink_setup, "inspect_phone", inspect)
    response = srv.client.post("/yealink/inspect", json={"ip": "10.0.0.11", "username": "admin",
                                                          "number": "101", "expected_urls": expected})
    assert response.status_code == 200 and response.get_json()["counts"] == {"match": 1}
    assert b"pilot-password-secret" not in response.data and b"expected-token-secret" not in response.data
