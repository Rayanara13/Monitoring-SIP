"""Проверка поздних событий через /event и рабочий проход watchdog."""
import time
from types import SimpleNamespace

import pytest


@pytest.fixture
def advance(srv, monkeypatch):
    current = [time.time()]
    monkeypatch.setattr(srv.server, "time", SimpleNamespace(time=lambda: current[0], strftime=time.strftime))

    def move(seconds):
        current[0] += seconds

    return move


def time_out(srv, advance):
    advance(61)
    assert srv.server.expire_stuck_calls()
    assert srv.phone()["state"] == "В_покое"


@pytest.mark.parametrize("delay", [75, 97])
@pytest.mark.parametrize(("answer", "reported_id"), [
    ("off_hook", "-1"), ("handfree", "$call_id"), ("headset", ""), ("call_established", "late-call"),
])
def test_late_answer_recovers_both_sides_and_records_each_once(srv, advance, delay, answer, reported_id):
    srv.ev("outgoing_call", local="101", remote="102", call_id="late-call")
    srv.ev("incoming_call", local="102", remote="101", call_id="late-call")
    start = srv.phone("102")["call_start"]
    time_out(srv, advance)
    assert srv.phone("102")["state"] == "В_покое"
    advance(delay - 61)

    assert srv.ev(answer, local="102", call_id=reported_id).status_code == 200
    assert srv.ev("call_established", local="101", call_id="late-call").status_code == 200
    for number, peer in (("101", "102"), ("102", "101")):
        assert srv.phone(number)["state"] == "Разговор"
        assert srv.phone(number)["peer"] == peer
        assert srv.phone(number)["call_start"] == start

    advance(5)
    for number in ("101", "102"):
        srv.ev("call_terminated", local=number, call_id="late-call")
        srv.ev("busy_to_idle", local=number, call_id="late-call")
        srv.ev("call_established", local=number, call_id="late-call")
        assert srv.phone(number)["state"] == "В_покое"
    assert srv.history() == [("101", "102", "out", delay + 5), ("102", "101", "in", delay + 5)]


def test_sentinel_id_on_ringing_can_learn_real_id_from_late_answer(srv, advance):
    srv.ev("incoming_call", remote="$remote", call_id="-1")
    time_out(srv, advance)
    advance(14)
    srv.ev("off_hook", remote="sip:902@pbx", call_id="real-902")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "902"
    srv.ev("call_terminated", call_id="real-902")
    srv.ev("call_established", remote="902", call_id="real-902")
    assert srv.phone()["state"] == "В_покое"
    assert srv.history() == [("101", "902", "in", 75)]


def test_answered_idless_timeout_stays_closed_on_repeated_established(srv, advance):
    srv.ev("incoming_call", remote="902", call_id="-1")
    time_out(srv, advance)
    advance(14)
    srv.ev("handfree", call_id="$call_id")
    assert srv.phone()["state"] == "Разговор"
    srv.ev("call_terminated", call_id="-1")
    srv.ev("call_established", remote="902", call_id="-1")
    assert srv.phone()["state"] == "В_покое"
    assert srv.history() == [("101", "902", "in", 75)]


@pytest.mark.parametrize("terminal", ["call_remote_canceled", "reject_incoming_call", "missed_call", "call_terminated"])
def test_terminated_timeout_cannot_be_reopened_by_late_events(srv, advance, terminal):
    srv.ev("incoming_call", remote="902", call_id="cancelled")
    time_out(srv, advance)
    advance(14)
    srv.ev(terminal, remote="sip:@", call_id="-1")
    for event, call_id in (("incoming_call", "cancelled"), ("handfree", "cancelled"), ("off_hook", "cancelled"),
                           ("call_established", "cancelled"), ("call_established", "-1")):
        srv.ev(event, remote="902", call_id=call_id)
        assert srv.phone()["state"] == "В_покое"
    srv.ev("off_hook", call_id="-1")
    assert srv.phone()["state"] == "Снята_трубка"
    assert srv.history() == [("101", "902", "in", 75)]


def test_replacement_survives_delayed_answer_and_end_of_old_call(srv, advance):
    srv.ev("incoming_call", remote="902", call_id="old")
    time_out(srv, advance)
    srv.ev("incoming_call", remote="903", call_id="new")
    for event in ("off_hook", "handfree", "call_established", "call_remote_canceled", "call_terminated", "busy_to_idle"):
        srv.ev(event, remote="902", call_id="old")
        assert srv.phone()["state"] == "Входящий_вызов"
        assert srv.phone()["peer"] == "903"
    srv.ev("headset", remote="902", call_id="-1")
    assert srv.phone()["state"] == "Входящий_вызов"
    srv.ev("headset", remote="903", call_id="new")
    assert srv.phone()["state"] == "Разговор"
    advance(5)
    srv.ev("call_terminated", call_id="new")
    assert srv.history() == [("101", "903", "in", 5)]


def test_expired_attempt_does_not_recover_or_log_a_ghost(srv, advance):
    srv.ev("incoming_call", remote="902", call_id="expired")
    time_out(srv, advance)
    advance(srv.server.LATE_ANSWER_GRACE)
    srv.server.expire_stuck_calls()
    srv.ev("call_established", remote="902", call_id="expired")
    srv.ev("call_established", remote="902", call_id="-1")
    srv.ev("headset", remote="902", call_id="expired")
    assert srv.phone()["state"] == "В_покое"
    srv.ev("off_hook", call_id="-1")
    assert srv.phone()["state"] == "Снята_трубка"
    srv.ev("on_hook")
    assert srv.history() == []


def test_watchdog_leaves_established_and_held_calls(srv, advance):
    for number, peer in (("101", "102"), ("102", "101")):
        srv.ev("incoming_call", local=number, remote=peer)
        srv.ev("call_established", local=number)
    srv.ev("hold", local="102")
    advance(120)
    assert not srv.server.expire_stuck_calls()
    assert srv.phone("101")["state"] == "Разговор"
    assert srv.phone("102")["state"] == "Удержание"
