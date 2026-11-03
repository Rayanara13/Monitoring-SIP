"""Трассы аудиоклавиш не должны выдумывать физическое снятие трубки."""

import importlib
from pathlib import Path

import pytest


@pytest.fixture
def audio_lab(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    phone_lab = importlib.import_module("simulator.engine").PhoneLab
    events = []
    lab = phone_lab(lambda phone, key, remote="", call_id="":
                    events.append((phone["number"], key, remote, call_id)))
    return lab, events


def phones(lab):
    return {phone["number"]: phone for phone in lab.state()["phones"]}


@pytest.mark.parametrize("mode,key", [("speaker", "handfree"), ("headset", "headset")])
def test_audio_key_on_idle_does_not_lift_handset(audio_lab, mode, key):
    lab, events = audio_lab
    lab.action("101", mode)
    assert [event[1] for event in events] == [key]
    phone = phones(lab)["101"]
    assert phone["state"] == "dialing"
    assert phone[mode] is True
    assert phone["hook"] is False


@pytest.mark.parametrize("mode,key", [("speaker", "handfree"), ("headset", "headset")])
def test_audio_key_off_with_handset_keeps_call_and_emits_pressed_key(audio_lab, mode, key):
    lab, events = audio_lab
    lab.action("101", "call", "102")
    lab.action("102", "answer")
    lab.action("102", mode)
    before = phones(lab)
    events.clear()

    lab.action("102", mode)

    assert [event[1] for event in events] == [key]
    after = phones(lab)
    assert after["102"][mode] is False
    assert after["102"]["hook"] is True
    for number in ("101", "102"):
        assert after[number]["state"] == "connected"
        assert after[number]["peer"] == before[number]["peer"]
        assert after[number]["call_id"] == before[number]["call_id"]
        assert after[number]["started_at"] == before[number]["started_at"]


@pytest.mark.parametrize("mode,key", [("speaker", "handfree"), ("headset", "headset")])
def test_last_audio_key_off_precedes_paired_hangup_without_off_hook(audio_lab, mode, key):
    lab, events = audio_lab
    lab.action("101", "call", "102")
    lab.action("102", mode)
    call_id = phones(lab)["102"]["call_id"]
    events.clear()

    lab.action("102", mode)

    assert events[0] == ("102", key, "101", call_id)
    assert "off_hook" not in [event[1] for event in events]
    ended = {(number, remote, event_call_id) for number, event_key, remote, event_call_id
             in events if event_key == "call_terminated"}
    assert ended == {("101", "102", call_id), ("102", "101", call_id)}
    assert all(phone["state"] == "idle" for phone in phones(lab).values())


def test_switching_audio_keys_does_not_fabricate_off_hook(audio_lab):
    lab, events = audio_lab
    lab.action("101", "call", "102")
    lab.action("102", "speaker")
    events.clear()
    lab.action("102", "headset")
    assert [event[1] for event in events] == ["headset"]
    phone = phones(lab)["102"]
    assert phone["state"] == "connected"
    assert phone["headset"] is True
    assert phone["speaker"] is False
    assert phone["hook"] is False


def test_physically_picking_up_handset_emits_off_hook_without_ending_call(audio_lab):
    lab, events = audio_lab
    lab.action("101", "call", "102")
    lab.action("102", "speaker")
    events.clear()
    lab.action("102", "hook")
    assert [event[1] for event in events] == ["off_hook"]
    phone = phones(lab)["102"]
    assert phone["hook"] is True
    assert phone["speaker"] is False
    assert phone["state"] == "connected"
