"""Старые 8 значений state — уже прописаны в телефонах, поведение не должно меняться."""


def test_bad_token_rejected(srv):
    r = srv.client.get("/event", query_string={"token": "nope", "state": "Idle", "local": "101"})
    assert r.status_code == 401


def test_outgoing_call_cycle_logged(srv):
    assert srv.ev("Setup", remote="sip:200@pbx").data == b"OK"
    assert srv.phone()["state"] == "Исходящий_вызов"
    assert srv.phone()["peer"] == "200"

    srv.ev("Connected")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "200"          # peer сохранён при пустом remote

    srv.age_call()
    srv.ev("Idle")
    assert srv.phone()["state"] == "В_покое"
    assert srv.phone()["peer"] == ""
    assert srv.history() == [("101", "200", "out", 10)]


def test_incoming_call_and_hold(srv):
    srv.ev("Ringing", remote="300")
    assert srv.phone()["state"] == "Входящий_вызов"
    srv.ev("Connected")
    srv.ev("Hold")
    assert srv.phone()["state"] == "Удержание"
    srv.age_call()
    srv.ev("OnHook")
    assert srv.phone()["state"] == "В_покое"
    assert srv.history() == [("101", "300", "in", 10)]


def test_offhook_ignored_during_call(srv):
    srv.ev("Ringing", remote="300")
    srv.ev("Connected")
    srv.ev("OffHook")
    assert srv.phone()["state"] == "Разговор"


def test_offhook_when_idle(srv):
    srv.ev("OffHook")
    assert srv.phone()["state"] == "Снята_трубка"
    srv.ev("OnHook")
    assert srv.phone()["state"] == "В_покое"


def test_short_call_not_logged(srv):
    srv.ev("Setup", remote="200")
    srv.ev("Idle")
    assert srv.history() == []


def test_dnd_then_idle_clears(srv):
    """Без события «Отключение DND» карточка, как и раньше, выходит из DND по Idle."""
    srv.ev("DND")
    assert srv.phone()["state"] == "DND"
    srv.ev("Idle")
    assert srv.phone()["state"] == "В_покое"


def test_unknown_state_ok(srv):
    assert srv.ev("Whatever").data == b"OK"
    assert srv.phone()["state"] == "В_покое"
