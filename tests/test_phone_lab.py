"""Поведение трёх виртуальных телефонов, независимо от веб-интерфейса."""
from copy import deepcopy
import importlib
from pathlib import Path

import pytest


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    PhoneLab = importlib.import_module("simulator.engine").PhoneLab
    sent = []
    now = [1000.0]

    def send(phone, event, remote="", call_id=""):
        sent.append({"phone": deepcopy(phone), "event": event,
                     "remote": remote, "call_id": call_id})

    instance = PhoneLab(send, clock=lambda: now[0])
    return instance, sent, now


def phones(instance):
    return {phone["number"]: phone for phone in instance.state()["phones"]}


def connected(instance, answer="answer"):
    instance.action("101", "call", "102")
    instance.action("102", answer)
    return phones(instance)


def test_keypad_builds_number_without_starting_a_call(lab):
    instance, sent, _ = lab
    for digit in "102":
        instance.action("101", "digit", digit)
    assert phones(instance)["101"]["dial"] == "102"
    assert phones(instance)["102"]["state"] == "idle"
    instance.action("101", "backspace")
    assert phones(instance)["101"]["dial"] == "10"
    instance.action("101", "digit", "2")
    instance.action("101", "call")
    assert phones(instance)["102"]["state"] == "ringing"


@pytest.mark.parametrize("answer", ["answer", "hook", "speaker", "headset"])
def test_incoming_can_be_answered_with_every_audio_control(lab, answer):
    instance, sent, _ = lab
    instance.action("101", "call", "102")
    before = phones(instance)
    assert before["101"]["state"] == "calling"
    assert before["102"]["state"] == "ringing"
    instance.action("102", answer)
    active = phones(instance)
    assert active["101"]["state"] == active["102"]["state"] == "connected"
    assert active["101"]["peer"] == "102"
    assert active["102"]["peer"] == "101"
    assert active["101"]["call_id"] == active["102"]["call_id"]
    assert active["101"]["call_id"]

    incoming = next(event for event in sent if event["event"] == "incoming_call")
    assert incoming["phone"]["number"] == "102"
    assert incoming["remote"] == "101"
    answers = [event for event in sent if event["phone"]["number"] == "102"
               and event["event"] in {"off_hook", "handfree", "headset", "call_established"}]
    assert answers
    assert all(event["remote"] == "101" for event in answers)
    assert all(event["call_id"] == active["102"]["call_id"] for event in answers)


def test_hold_resume_and_hangup_preserve_the_other_party(lab):
    instance, sent, now = lab
    connected(instance)
    now[0] += 12
    instance.action("101", "hold")
    held = phones(instance)
    assert held["101"]["state"] == held["102"]["state"] == "held"
    assert held["101"]["peer"] == "102"
    assert held["102"]["peer"] == "101"
    instance.action("101", "hold")
    assert phones(instance)["101"]["state"] == "connected"
    assert phones(instance)["102"]["state"] == "connected"
    instance.action("102", "hangup")
    finished = phones(instance)
    for number in ("101", "102"):
        assert finished[number]["state"] == "idle"
        assert not finished[number]["peer"]
        assert not finished[number]["call_id"]
    ended = [event["phone"]["number"] for event in sent
             if event["event"] == "call_terminated"]
    assert "101" in ended and "102" in ended


def test_caller_cancel_stops_ringing_without_connecting(lab):
    instance, sent, _ = lab
    instance.action("101", "call", "102")
    instance.action("101", "hangup")
    assert all(phone["state"] == "idle" for phone in phones(instance).values())
    assert not any(event["event"] == "call_established" for event in sent)
    assert any(event["event"] == "call_remote_canceled"
               and event["phone"]["number"] == "102" for event in sent)


@pytest.mark.parametrize("mode", ["dnd", "power", "register"])
def test_unavailable_phone_does_not_create_a_call(lab, mode):
    instance, sent, _ = lab
    instance.action("102", mode)
    instance.action("101", "call", "102")
    result = phones(instance)
    assert result["101"]["state"] == "idle"
    assert not result["101"]["peer"]
    assert not result["102"]["peer"]
    assert not result["101"]["call_id"]
    assert not result["102"]["call_id"]
    assert not any(event["event"] == "call_established" for event in sent)
    assert any(event["event"] == "remote_busy" for event in sent)


def test_call_to_busy_phone_does_not_break_its_existing_conversation(lab):
    instance, sent, _ = lab
    before = connected(instance)
    call_id = before["101"]["call_id"]
    instance.action("103", "call", "102")
    after = phones(instance)
    assert after["101"]["state"] == after["102"]["state"] == "connected"
    assert after["101"]["call_id"] == after["102"]["call_id"] == call_id
    assert after["103"]["state"] == "idle"
    assert not after["103"]["peer"]


def test_power_loss_releases_the_other_phone(lab):
    instance, _, _ = lab
    connected(instance)
    instance.action("102", "power")
    after = phones(instance)
    assert after["102"]["state"] == "offline"
    assert not after["102"]["power"]
    assert not after["102"]["registered"]
    assert after["101"]["state"] == "idle"
    assert not after["101"]["peer"]


def test_forwarding_rings_the_third_phone(lab):
    instance, sent, _ = lab
    instance.action("102", "forward", "103")
    instance.action("101", "call", "102")
    result = phones(instance)
    assert result["103"]["state"] == "ringing"
    assert result["103"]["peer"] == "101"
    assert result["102"]["state"] == "idle"
    instance.action("103", "answer")
    assert phones(instance)["101"]["state"] == "connected"
    assert phones(instance)["103"]["state"] == "connected"
    assert any(event["event"] == "incoming_call"
               and event["phone"]["number"] == "103"
               and event["remote"] == "101" for event in sent)


def test_blind_transfer_connects_the_two_remaining_phones(lab):
    instance, sent, _ = lab
    connected(instance)
    instance.action("101", "transfer", "103")
    ringing = phones(instance)
    assert ringing["101"]["state"] == "idle"
    assert not ringing["101"]["peer"]
    assert ringing["103"]["state"] == "ringing"
    instance.action("103", "answer")
    result = phones(instance)
    assert result["102"]["state"] == result["103"]["state"] == "connected"
    assert result["102"]["peer"] == "103"
    assert result["103"]["peer"] == "102"
    assert any(event["event"] == "blind_transfer_call" for event in sent)


@pytest.mark.parametrize("number,action,value", [
    ("101", "call", "999"),
    ("101", "call", "101"),
    ("101", "digit", "x"),
    ("101", "forward", "999"),
    ("101", "forward", "101"),
    ("999", "dnd", None),
    ("101", "unknown-action", None),
])
def test_invalid_commands_leave_all_phones_and_events_unchanged(lab, number, action, value):
    instance, sent, _ = lab
    before = deepcopy(instance.state())
    sent_before = deepcopy(sent)
    with pytest.raises(ValueError):
        instance.action(number, action, value)
    assert instance.state() == before
    assert sent == sent_before


def test_reset_releases_calls_and_restores_modes(lab):
    instance, _, _ = lab
    connected(instance)
    instance.action("103", "dnd")
    instance.reset()
    for phone in phones(instance).values():
        assert phone["state"] == "idle"
        assert phone["power"] and phone["registered"]
        assert not phone["peer"] and not phone["call_id"]
        assert not phone["dnd"] and not phone["mute"]
        assert not phone["forward_to"]
