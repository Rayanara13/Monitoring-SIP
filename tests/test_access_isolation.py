import sqlite3
import time


def test_socket_updates_require_local_login_and_same_origin(srv):
    server, client = srv.server, srv.client
    assert client.get("/login").status_code == 200
    assert client.get("/phones").status_code == 401

    foreign = client.get("/socket.io/?EIO=4&transport=polling", headers={
        "Origin": "http://other-node.invalid",
        "X-Forwarded-Host": "other-node.invalid",
    })
    assert foreign.status_code == 400
    guest = server.socketio.test_client(server.app, flask_test_client=client)
    assert not guest.is_connected()

    with client.session_transaction() as session:
        session.update(logged_in=True, username=srv.user)
    operator = server.socketio.test_client(server.app, flask_test_client=client)
    assert operator.is_connected()
    assert "server_version" in {message["name"] for message in operator.get_received()}
    operator.disconnect()
    denied = client.post("/add_phone", json={"number": "103"}, headers={"Origin": "http://localhost:1234"})
    assert denied.status_code == 403


def test_operator_history_only_contains_own_calls_even_with_shared_number(srv):
    srv.add_user("operator", [{"number": "101", "ip": "10.0.0.11"}])
    now = time.time()
    with sqlite3.connect(srv.server.DB_FILE) as db:
        db.executemany("""
            INSERT INTO call_log (ts_start, ts_end, duration, local, remote, direction, username)
            VALUES (?, ?, 4, '101', ?, 'incoming', ?)
        """, [(now - 4, now, "102", srv.user), (now - 4, now, "103", "operator")])
    with srv.client.session_transaction() as session:
        session.update(logged_in=True, username="operator")
    records = srv.client.get("/history?number=101&username=admin").get_json()["records"]
    assert [(record["username"], record["remote"]) for record in records] == [("operator", "103")]
