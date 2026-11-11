import pytest


def audio_flags(srv):
    with srv.client.session_transaction() as session:
        session["logged_in"] = True
        session["username"] = srv.user
    phones = srv.client.get("/phones").get_json()["phones"]
    return next(phone["flags"] for phone in phones if phone["number"] == "101")


@pytest.mark.parametrize("button, audio", [("handfree", "handsfree"), ("headset", "headset")])
@pytest.mark.parametrize("on_hold", [False, True])
def test_off_hook_clears_audio_without_interrupting_call(srv, button, audio, on_hold):
    srv.ev("incoming_call", remote="300")
    srv.ev(button)
    # Повтор события нажатия не позволяет отличить новую команду от доставки дубля.
    srv.ev(button)
    srv.ev("mute")
    if on_hold:
        srv.ev("hold")

    assert audio_flags(srv)["audio"] == audio
    state = "Удержание" if on_hold else "Разговор"
    assert srv.phone()["state"] == state
    call_start = srv.phone()["call_start"]
    pending = srv.server.pending_calls["101"].copy()

    for _ in range(2):
        assert srv.ev("off_hook").status_code == 200
        flags = audio_flags(srv)
        assert flags.get("audio") is None
        assert flags["mute"] is True
        assert srv.phone()["state"] == state
        assert srv.phone()["peer"] == "300"
        assert srv.phone()["call_start"] == call_start
        assert srv.server.pending_calls["101"] == pending
        assert srv.history() == []

    srv.age_call(seconds=10)
    srv.ev("call_terminated")
    [(local, remote, direction, duration)] = srv.history()
    assert (local, remote, direction) == ("101", "300", "in")
    assert duration >= 10


def test_off_hook_preserves_conversation_seen_without_call_setup(srv):
    srv.ev("call_established", remote="300")
    srv.ev("handfree")
    assert audio_flags(srv)["audio"] == "handsfree"
    call_start = srv.phone()["call_start"]

    srv.ev("off_hook")

    assert audio_flags(srv).get("audio") is None
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "300"
    assert srv.phone()["call_start"] == call_start


def test_off_hook_during_outgoing_attempt_does_not_confirm_audio_change(srv):
    srv.ev("handfree")
    srv.ev("outgoing_call", remote="300")

    srv.ev("off_hook")

    assert audio_flags(srv)["audio"] == "handsfree"
    assert srv.phone()["state"] == "Исходящий_вызов"
    assert srv.phone()["peer"] == "300"
