"""Phone setup and raw Action URL evidence through the real Flask endpoints."""

import pytest


def login_as(srv, username="admin"):
    with srv.client.session_transaction() as session:
        session["logged_in"] = True
        session["username"] = username


def test_catalog_returns_selected_users_cards_and_cfg_parameters(srv):
    srv.add_user("alice", [{"number": "201", "ip": "10.0.0.21"}])
    login_as(srv)
    response = srv.client.get("/action_url_events", query_string={"username": "alice"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["phones"] == [{"number": "201", "name": "201", "ip": "10.0.0.21"}]
    parameters = {item["key"]: item["parameter"] for item in data["events"]}
    assert len(parameters) == 48
    # These two names differ from the event keys in the manufacturer's CFG table.
    assert parameters["view_missed_call"] == "custom.action_url.view_misscall"
    assert parameters["view_forwarded_call"] == "custom.action_url.view_forward"
    assert parameters["incoming_call"] == "action_url.incoming_call"
    assert "event_token" not in str(data)


def test_catalog_cannot_read_another_users_cards(srv):
    srv.add_user("alice", [{"number": "201", "ip": "10.0.0.21"}])
    login_as(srv, "alice")
    assert srv.client.get("/action_url_events?username=admin").status_code == 403
    own = srv.client.get("/action_url_events").get_json()
    assert [p["number"] for p in own["phones"]] == ["201"]


def test_catalog_unknown_user_is_not_silently_replaced(srv):
    login_as(srv)
    assert srv.client.get("/action_url_events?username=missing").status_code == 404


def test_outgoing_called_number_reaches_card_and_call_history(srv):
    srv.ev("outgoing_call", remote="$remote", called_number="202")
    assert srv.phone()["peer"] == "202"
    assert srv.server.recent_events[-1]["remote_source"] == "called_number"
    srv.ev("call_established", remote="", called_number="202")
    assert srv.phone()["peer"] == "202"
    srv.age_call()
    srv.ev("call_terminated")
    assert srv.history()[0][:3] == ("101", "202", "out")


def test_incoming_never_uses_outgoing_callee_as_peer(srv):
    srv.ev("incoming_call", remote="$remote", called_number="101")
    assert srv.phone()["peer"] == "Не определен"
    assert srv.server.recent_events[-1]["remote_source"] == ""


def test_real_remote_has_priority_over_called_number(srv):
    srv.ev("outgoing_call", remote="sip:202@example.test", called_number="999")
    assert srv.phone()["peer"] == "202"
    assert srv.server.recent_events[-1]["remote_source"] == "remote"


def test_unknown_call_direction_does_not_guess_remote(srv):
    srv.ev("call_established", remote="$remote", called_number="101")
    assert srv.phone()["peer"] == "Не определен"
    assert srv.server.recent_events[-1]["remote_source"] == ""


def test_unexpanded_macros_are_kept_as_evidence_not_numbers(srv):
    srv.ev("incoming_call", local="$active_user", remote="$remote",
           called_number="$calledNumber", model="Spectr-test", firmware="test-fw")
    event = srv.server.recent_events[-1]
    assert event["number"] == ""
    assert event["remote"] == ""
    assert event["raw_local"] == "$active_user"
    assert event["raw_remote"] == "$remote"
    assert event["raw_called_number"] == "$calledNumber"
    assert event["model"] == "Spectr-test"
    assert event["firmware"] == "test-fw"
    assert srv.phone()["state"] == "В_покое"


def test_explicit_event_identifies_number_without_mac_learning(srv):
    srv.ev("incoming_call", local="102", remote="202", ip="10.0.0.11",
           mac="001565aabbcc")
    assert srv.phone("102")["peer"] == "202"
    assert srv.phone("102")["state"] == "Входящий_вызов"
    assert srv.phone("101")["state"] == "В_покое"


def test_learning_one_handset_does_not_claim_empty_events_from_shared_base(srv):
    srv.phone("102")["ip"] = srv.phone("101")["ip"]
    srv.ev("off_hook", local="101", ip="10.0.0.11", mac="001565aabbcc")
    srv.ev("on_hook", local="101", ip="10.0.0.11", mac="001565aabbcc")
    srv.ev("incoming_call", local="$active_user", remote="202",
           ip="10.0.0.11", mac="001565aabbcc")
    assert srv.server.recent_events[-1]["number"] == ""
    assert srv.phone("101")["state"] == "В_покое"
    assert srv.phone("102")["state"] == "В_покое"


@pytest.mark.parametrize("answer", ["off_hook", "handfree", "headset"])
def test_incoming_number_first_sent_when_answering_is_not_discarded(srv, answer):
    srv.ev("incoming_call", remote="$remote")
    srv.ev(answer, remote="sip:202@example.test")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "202"
    srv.age_call()
    srv.ev("call_terminated")
    assert srv.history()[0][:3] == ("101", "202", "in")


def test_called_number_never_uses_first_lines_direction_for_second_incoming(srv):
    srv.ev("busy_to_idle")
    srv.ev("outgoing_call", remote="202")
    srv.ev("call_established", remote="202")
    srv.ev("incoming_call", remote="303")
    srv.ev("answer_new_incoming_call", remote="303")
    srv.ev("call_terminated")
    srv.ev("unhold", remote="$remote", called_number="101")
    assert srv.phone()["peer"] != "101"
    assert srv.server.recent_events[-1]["remote_source"] == ""
