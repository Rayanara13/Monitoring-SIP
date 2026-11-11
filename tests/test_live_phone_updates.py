import pytest


def signed_in(server, username):
    http = server.app.test_client()
    with http.session_transaction() as session:
        session.update(logged_in=True, username=username)
    return http


def messages(socket):
    return [message["name"] for message in socket.get_received()]


def test_node_link_is_admin_only_and_serves_no_center_console(srv, monkeypatch):
    server = srv.server
    monkeypatch.setattr(server, "ROLE", "node")
    srv.add_user("viewer", [])
    viewer = signed_in(server, "viewer")
    admin = signed_in(server, "admin")
    assert srv.client.get("/node-link").status_code == 302
    assert viewer.get("/node-link").status_code == 403
    page = admin.get("/node-link")
    assert page.status_code == 200
    assert page.headers["Cache-Control"] == "no-store"
    assert b"/admin/nodes" not in page.data
    assert b"/admin/update-release" not in page.data


@pytest.fixture
def live(srv):
    server = srv.server
    srv.add_user("viewer", [{"number": "201", "ip": "10.0.0.21"}])
    admin = signed_in(server, "admin")
    viewer = signed_in(server, "viewer")
    sockets = [server.socketio.test_client(server.app, flask_test_client=client)
               for client in (admin, admin, viewer)]
    for socket in sockets:
        assert socket.is_connected()
        assert messages(socket) == ["server_version"]
    yield admin, viewer, sockets
    for socket in sockets:
        if socket.is_connected():
            socket.disconnect()


def test_card_writes_notify_only_own_open_tabs_and_reconnect_reads_snapshot(srv, live):
    server = srv.server
    admin, viewer, (first_tab, second_tab, unrelated_tab) = live
    assert not server.socketio.test_client(server.app).is_connected()

    actions = [
        ("/add_phone", {"number": "103", "name": "Новая", "ip": "10.0.0.13"}),
        ("/update_phone", {"old_number": "103", "number": "104", "name": "Метка", "ip": "10.0.0.14"}),
        ("/delete_phone", {"number": "104"}),
    ]
    for path, payload in actions:
        assert admin.post(path, json=payload).get_json() == {"ok": True}
        assert messages(first_tab) == messages(second_tab) == ["phones_update"]
        assert messages(unrelated_tab) == []
    assert [card["number"] for card in viewer.get("/phones").get_json()["phones"]] == ["201"]

    second_tab.disconnect()
    assert admin.post("/add_phone", json={"number": "105"}).status_code == 200
    second_tab.connect()
    assert messages(second_tab) == ["server_version"]
    assert [card["number"] for card in admin.get("/phones").get_json()["phones"]] == ["101", "102", "105"]


def test_resize_is_local_to_card_owner_and_survives_rename_and_restart(srv, live, monkeypatch):
    server = srv.server
    admin, viewer, (first_tab, second_tab, unrelated_tab) = live
    monkeypatch.setattr(server, "ROLE", "node")
    server.load_phones()
    revision = srv.phone()["revision"]
    payload = {"number": "101", "columns": 4, "min_height": 270}
    assert server.app.test_client().post("/resize_phone", json=payload).status_code == 401
    assert viewer.post("/resize_phone", json=payload).status_code == 404
    assert admin.post("/resize_phone", json={**payload, "columns": True}).status_code == 400
    assert admin.post("/resize_phone", json={**payload, "min_height": 801}).status_code == 400
    assert admin.post("/resize_phone", json=payload).get_json() == {"ok": True}
    assert messages(first_tab) == messages(second_tab) == ["phones_update"]
    assert messages(unrelated_tab) == []
    assert srv.phone()["revision"] == revision

    assert admin.post("/update_phone", json={"old_number": "101", "number": "111", "ip": "10.0.0.11"}).status_code == 200
    server.load_phones()
    cards = admin.get("/phones").get_json()["phones"]
    renamed = next(card for card in cards if card["number"] == "111")
    assert (renamed["columns"], renamed["min_height"]) == (4, 270)
    assert admin.post("/resize_phone", json={"number": "111", "columns": 1, "min_height": 0}).status_code == 200
    server.load_phones()
    assert "columns" not in srv.phone("111")
    assert "min_height" not in srv.phone("111")


def test_reorder_moves_only_current_group_slots(srv, live):
    admin, _, (first_tab, second_tab, unrelated_tab) = live
    for number in ("103", "104"):
        assert admin.post("/add_phone", json={"number": number}).status_code == 200
    srv.phone("102")["state"] = "Разговор"
    for tab in (first_tab, second_tab):
        messages(tab)

    assert admin.post("/reorder", json={"from_number": "101", "to_number": "104", "group": "idle"}).status_code == 200
    assert [card["number"] for card in admin.get("/phones").get_json()["phones"]] == ["103", "102", "104", "101"]
    assert messages(first_tab) == messages(second_tab) == ["phones_update"]
    assert messages(unrelated_tab) == []
    assert admin.post("/reorder", json={"from_number": "101", "to_number": "102", "group": "idle"}).status_code == 409
    assert admin.post("/reorder", json={"from_number": "101", "to_number": "103", "group": "active"}).status_code == 409
    assert admin.post("/reorder", json=["101", "102", "103", "104"]).status_code == 200


def test_reorder_repairs_legacy_duplicate_positions_and_new_cards_append(srv, live):
    admin, viewer, _ = live
    srv.phone("101")["position"] = srv.phone("102")["position"] = 4
    assert admin.post("/add_phone", json={"number": "103"}).status_code == 200
    srv.phone("103")["state"] = "Разговор"
    assert srv.phone("103")["position"] == 5
    assert viewer.post("/toggle_shared").status_code == 200
    assert admin.post("/import_set", json={"username": "viewer"}).status_code == 200
    assert srv.phone("201")["position"] == 6

    assert admin.post("/reorder", json={"from_number": "102", "to_number": "101", "group": "idle"}).status_code == 200
    cards = admin.get("/phones").get_json()["phones"]
    assert [(card["number"], card["position"]) for card in cards] == [
        ("102", 0), ("101", 1), ("103", 2), ("201", 3),
    ]


def test_sip_and_diagnostics_notify_authorized_views(srv, live):
    admin, viewer, (first_tab, second_tab, unrelated_tab) = live
    assert srv.ev("incoming_call", "201", as_token="token-viewer", remote="999", call_id="call-a").status_code == 200
    assert messages(first_tab) == messages(second_tab) == ["recent_events_update"]
    assert messages(unrelated_tab) == ["phones_update"]
    assert viewer.get("/phones").get_json()["phones"][0]["state"] == "Входящий_вызов"
    assert admin.get("/recent_events").get_json()["events"][0]["number"] == "201"
    assert viewer.get("/recent_events").status_code == 403

    # The same call ID is already active. The handler does not alter the call
    # state, but the latest event and diagnostic journal still change.
    assert srv.ev("incoming_call", "201", as_token="token-viewer", remote="999", call_id="call-a").status_code == 200
    assert messages(first_tab) == messages(second_tab) == ["recent_events_update"]
    assert messages(unrelated_tab) == ["phones_update"]
    assert srv.ev("unknown_event", "777", as_token="token-viewer").status_code == 200
    assert messages(first_tab) == messages(second_tab) == ["recent_events_update"]
    assert messages(unrelated_tab) == []


def test_shared_library_and_federation_writes_invalidate_corresponding_tabs(srv, live, monkeypatch):
    server = srv.server
    admin, viewer, (first_tab, second_tab, other_tab) = live
    monkeypatch.setattr(server, "ROLE", "node")
    assert admin.post("/toggle_shared").get_json()["shared"] is True
    assert messages(first_tab) == messages(second_tab) == messages(other_tab) == ["shared_sets_update"]
    result, _ = server.execute_federation_command({
        "action": "phone.add", "payload": {"owner": "admin", "number": "103", "name": "Центр"}
    }, {})
    assert result == "applied"
    assert messages(first_tab) == messages(second_tab) == ["phones_update", "shared_sets_update"]
    assert messages(other_tab) == ["shared_sets_update"]
    assert viewer.post("/import_set", json={"username": "admin"}).get_json()["imported"] == 3
    assert messages(other_tab) == ["phones_update"]
    assert messages(first_tab) == messages(second_tab) == ["phones_update"]  # shared-number visibility recalculated


def test_ping_batch_watchdog_and_stale_ping_results(srv, live, monkeypatch):
    server = srv.server
    _, _, (first_tab, second_tab, other_tab) = live
    batches = []
    monkeypatch.setattr(server, "ping_once", lambda _: None)
    monkeypatch.setattr(server.socketio, "start_background_task", batches.append)
    monkeypatch.setattr(server.socketio, "sleep", lambda _: None)
    for _ in range(3):
        server.ping_card("admin", "101", "10.0.0.11")
    assert len(batches) == 1
    batches.pop()()
    assert srv.phone()["state"] == "OFFLINE"
    assert messages(first_tab) == messages(second_tab) == ["phones_update"]
    assert messages(other_tab) == []
    assert not server.apply_ping_result("admin", "101", "10.0.0.99", 1)
    assert srv.phone()["ping"] == "Недоступен"

    srv.phone().update(state="Входящий_вызов", call_start=1)
    assert server.expire_stuck_calls(now=100)
    assert messages(first_tab) == messages(second_tab) == ["phones_update"]
    assert messages(other_tab) == []
