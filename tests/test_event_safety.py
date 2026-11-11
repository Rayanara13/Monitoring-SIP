"""События телефона меняют только разрешённые карточки."""

import logging


def test_explicit_number_cannot_update_other_owner_or_teach_its_mac(srv):
    srv.add_user("bob", [{"number": "201", "ip": "10.0.0.21"}])
    assert srv.ev("dnd_on", local="201", mac="001565aabbcc").status_code == 200
    assert srv.ev("off_hook", local="", mac="001565aabbcc").status_code == 200
    assert srv.server.users_phones["bob"]["201"]["state"] == "В_покое"
    assert "201" not in srv.server.phone_flags
    assert (srv.user, "001565aabbcc") not in srv.server.mac_numbers


def test_conflicting_addresses_for_same_number_leave_both_cards_alone(srv):
    bob = srv.add_user("bob", [{"number": "101", "ip": "10.0.0.21"}])
    srv.ev("off_hook", as_token=bob)
    assert srv.phone()["state"] == "В_покое"
    assert srv.server.users_phones["bob"]["101"]["state"] == "В_покое"
    assert srv.server.recent_events[-1]["rejection"] == "ambiguous_number"


def test_same_number_and_ip_can_be_shared(srv):
    bob = srv.add_user("bob", [{"number": "101", "ip": "10.0.0.11"}])
    srv.ev("dnd_on", as_token=bob)
    assert srv.phone()["state"] == "DND"
    assert srv.server.users_phones["bob"]["101"]["state"] == "DND"


def test_event_tokens_are_not_in_http_logs(srv, caplog):
    bad = "pilot-invalid-token-secret"
    assert srv.ev("off_hook", as_token=bad).status_code == 401
    assert srv.ev("off_hook").status_code == 200
    log = srv.server.LOG_FILE.read_text(encoding="utf-8")
    assert "HTTP_REQ" in log
    assert srv.token not in log
    assert bad not in log and "token_prefix" not in log
    with caplog.at_level(logging.INFO, logger="werkzeug"):
        logging.getLogger("werkzeug").info('GET /event?token=%s&state=off_hook HTTP/1.1', srv.token)
    assert srv.token not in caplog.text
    assert "state=off_hook" in caplog.text
