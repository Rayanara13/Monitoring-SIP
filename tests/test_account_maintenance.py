import json
import logging
import os
import time

import pytest


def admin_client(srv):
    with srv.client.session_transaction() as session:
        session.update(logged_in=True, username="admin")
    return srv.client


@pytest.mark.parametrize("name", ["../operator", "operator/test", "operator\\test", "operator:stream", "operator."])
def test_registration_rejects_names_that_are_unsafe_for_card_files(srv, name):
    assert admin_client(srv).post("/register", json={"username": name}).status_code == 400
    assert set(srv.server.AUTH) == {"admin"}


def test_registration_recovers_from_an_auth_write_failure(srv, monkeypatch):
    before = srv.server.AUTH_FILE.read_bytes()
    admin = admin_client(srv)

    def cannot_write(path, value):
        raise OSError("fixture disk failure")

    with monkeypatch.context() as failed:
        failed.setattr(srv.server, "write_json_atomic", cannot_write)
        assert admin.post("/register", json={"username": "operator"}).status_code == 503

    assert srv.server.AUTH_FILE.read_bytes() == before
    assert "operator" not in srv.server.AUTH
    assert not (srv.server.PHONES_DIR / "phones_operator.json").exists()
    assert admin.post("/register", json={"username": "operator"}).get_json()["ok"]
    assert admin.post("/register", json={"username": "OPERATOR"}).status_code == 409


def test_password_reset_preserves_phone_events_and_ends_old_sessions(srv):
    admin = admin_client(srv)
    created = admin.post("/register", json={"username": "Оператор"}).get_json()
    operator = srv.server.app.test_client()
    login = {"username": "Оператор", "password": created["password"]}
    assert operator.post("/login", json=login).get_json()["ok"]
    assert operator.post("/add_phone", json={"number": "201", "name": "Test", "ip": ""}).get_json()["ok"]
    assert operator.post("/admin/users/password", json={"username": "Оператор"}).status_code == 403
    socket_client = srv.server.socketio.test_client(srv.server.app, flask_test_client=operator)
    assert socket_client.is_connected()
    card = srv.server.PHONES_DIR / "phones_Оператор.json"
    saved_card = card.read_bytes()

    result = admin.post("/admin/users/password", json={"username": "Оператор"})
    assert result.headers["Cache-Control"] == "no-store"
    assert result.get_json()["ok"]
    assert not socket_client.is_connected()
    assert operator.get("/phones").status_code == 401
    assert operator.post("/login", json=login).status_code == 401
    login["password"] = result.get_json()["password"]
    assert operator.post("/login", json=login).get_json()["ok"]
    assert operator.get("/phones").get_json()["phones"][0]["number"] == "201"
    account = json.loads(srv.server.AUTH_FILE.read_text(encoding="utf-8"))["Оператор"]
    assert account["event_token"] == created["event_token"]
    assert card.read_bytes() == saved_card
    assert srv.ev("off_hook", local="201", as_token=created["event_token"]).status_code == 200


def test_http_logs_hide_query_values_even_with_encoded_parameter_names(srv):
    secret = "fixture-credential-that-must-stay-private"
    request_line = f'"GET /event?%74oken={secret}&authorization={secret} HTTP/1.1" 200'
    record = logging.LogRecord("werkzeug", logging.INFO, "", 0, "%s", (request_line,), None)
    assert srv.server.redact_access_log(record)
    assert secret not in record.getMessage()
    assert "/event?" in record.getMessage()

    assert srv.ev("off_hook", extra=secret).status_code == 200
    assert secret not in srv.server.LOG_FILE.read_text(encoding="utf-8")


def test_first_admin_password_is_local_and_removed_after_login(srv, capsys, monkeypatch):
    srv.server.AUTH_FILE.unlink()
    capsys.readouterr()
    account = srv.server.load_or_create_auth()
    monkeypatch.setattr(srv.server, "AUTH", account)
    note = srv.server.FIRST_START_FILE.read_text(encoding="utf-8")
    password = next(line.split(": ", 1)[1] for line in note.splitlines() if line.startswith("Пароль:"))
    console = capsys.readouterr().out
    assert "first-start.txt" in console
    assert password not in console
    assert account["admin"]["event_token"] not in (console + note)
    assert srv.client.post("/login", json={"username": "admin", "password": password}).get_json()["ok"]
    assert not srv.server.FIRST_START_FILE.exists()


def test_operational_log_rolls_by_day_and_prunes_old_archives(srv, tmp_path):
    active = tmp_path / "rollover.jsonl"
    archive = tmp_path / "rollover.jsonl.1"
    active.write_text("previous day\n", encoding="utf-8")
    archive.write_text("expired\n", encoding="utf-8")
    yesterday = time.time() - 24 * 60 * 60
    expired = time.time() - 8 * 24 * 60 * 60
    os.utime(active, (yesterday, yesterday))
    os.utime(archive, (expired, expired))
    handler = srv.server._OperationalLogHandler(active, maxBytes=4096, backupCount=2, encoding="utf-8")
    try:
        assert not archive.exists()
        record = logging.LogRecord("test", logging.INFO, "", 0, "today", (), None)
        handler.emit(record)
    finally:
        handler.close()
    assert archive.read_text(encoding="utf-8") == "previous day\n"
    assert active.read_text(encoding="utf-8") == "today\n"
