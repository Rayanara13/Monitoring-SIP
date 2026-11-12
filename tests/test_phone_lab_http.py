"""Реальный loopback HTTP: телефон → /event → мониторинг → история."""
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest


ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def live_lab(tmp_path_factory):
    runtime = tmp_path_factory.mktemp("phone-lab-http")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, data=None):
        body = None if data is None else json.dumps(data).encode("utf-8")
        req = urllib.request.Request(base + path, data=body,
                                     headers={"Content-Type": "application/json"} if body else {})
        with opener.open(req, timeout=8) as response:
            return json.loads(response.read())

    with (runtime / "process.log").open("wb") as log:
        env = {**os.environ, "PYTHONUTF8": "1", "MONITORING_SIP_ROLE": "victoria",
               "VICTORIA_ROLE_GRANT": str(runtime / "missing-grant.json")}
        process = subprocess.Popen([sys.executable, "-m", "simulator", "--port", str(port),
                                    "--data-dir", str(runtime / "data")], cwd=ROOT,
                                   env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail("Стенд завершился при запуске: " + (runtime / "process.log").read_text(encoding="utf-8"))
                try:
                    if request("/lab/api/state")["monitor"]["count"] >= 9:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.1)
            else:
                pytest.fail("Стенд не запустился за отведённое время")
            yield request, base, runtime
        finally:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)


def test_live_call_updates_both_monitor_cards_and_history(live_lab):
    request, _, _ = live_lab
    request("/lab/api/reset", {})
    request("/lab/api/action", {"phone": "101", "action": "call", "value": "102"})
    phones = {p["number"]: p for p in request("/phones")["phones"]}
    assert phones["101"]["state"] == "Исходящий_вызов"
    assert phones["102"]["state"] == "Входящий_вызов"
    request("/lab/api/action", {"phone": "102", "action": "speaker"})
    phones = {p["number"]: p for p in request("/phones")["phones"]}
    assert phones["101"]["state"] == phones["102"]["state"] == "Разговор"
    assert phones["101"]["peer"] == "102"
    assert phones["102"]["peer"] == "101"
    request("/lab/api/action", {"phone": "102", "action": "hold"})
    assert {p["number"]: p for p in request("/phones")["phones"]}["101"]["state"] == "Удержание"
    request("/lab/api/action", {"phone": "102", "action": "hold"})
    # История настоящего сервера исключает разговоры короче трёх секунд.
    time.sleep(3.1)
    request("/lab/api/action", {"phone": "101", "action": "hangup"})
    phones = {p["number"]: p for p in request("/phones")["phones"]}
    assert phones["101"]["state"] == phones["102"]["state"] == "В_покое"
    records = request("/history")["records"]
    assert {(r["local"], r["remote"], r["direction"]) for r in records} >= {
        ("101", "102", "out"), ("102", "101", "in")}


def test_live_modes_forwarding_and_isolation(live_lab):
    request, _, runtime = live_lab
    request("/lab/api/reset", {})
    request("/lab/api/action", {"phone": "102", "action": "dnd"})
    phones = {p["number"]: p for p in request("/phones")["phones"]}
    assert phones["102"]["flags"]["dnd"] is True
    state = request("/lab/api/action", {"phone": "101", "action": "call", "value": "102"})
    assert all(p["state"] not in {"ringing", "connected"} for p in state["phones"])
    request("/lab/api/action", {"phone": "102", "action": "dnd"})
    request("/lab/api/action", {"phone": "102", "action": "forward", "value": "103"})
    state = request("/lab/api/action", {"phone": "101", "action": "call", "value": "102"})
    assert next(p for p in state["phones"] if p["number"] == "103")["state"] == "ringing"
    phones = {p["number"]: p for p in request("/phones")["phones"]}
    assert phones["103"]["state"] == "Входящий_вызов"
    assert state["monitor"]["ok"] and state["monitor"]["count"] > 9
    assert (runtime / "data" / "users_data" / "call_history.db").exists()
    request("/lab/api/reset", {})


@pytest.mark.parametrize("path,body", [
    ("/lab/api/action", b'{"phone":"101","action":"dnd"}'),
    ("/lab/api/action-url-event", b'{"phone":"101","event":"dnd_on"}'),
])
def test_lab_rejects_cross_site_actions(live_lab, path, body):
    _, base, _ = live_lab
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(base + path, data=body,
                                     headers={"Content-Type": "application/json", "Origin": "https://other.example"})
    with pytest.raises(urllib.error.HTTPError) as error:
        opener.open(request, timeout=8)
    assert error.value.code == 403


def test_manual_catalog_delivers_every_supported_event_to_real_monitor(live_lab):
    request, _, _ = live_lab
    initial = request("/lab/api/reset", {})
    catalog = request("/lab/api/action-url-events")["events"]
    keys = {row["key"] for row in catalog}
    assert len(catalog) == len(keys) == 48
    assert keys == {event["key"] for event in request("/action_url_events")["events"]}

    for index, item in enumerate(catalog, 1):
        result = request("/lab/api/action-url-event", {"phone": "101", "event": item["key"], "remote": "102"})
        assert result["monitor"]["count"] == initial["monitor"]["count"] + index
        assert result["phones"] == initial["phones"]
        event = result["events"][-1]
        assert (event["state"], event["remote"], event["call_id"], event["source"]) == (item["key"], "102", "", "manual")

    observed = request("/recent_events")["events"][:len(catalog)]
    assert {row["key"] for row in observed if row["known"] and not row["rejection"] and row["number"] == "101"} == keys

    for key in ("busy_fwd_on", "no_answer_fwd_on", "call_waiting_on", "vpn_ip"):
        request("/lab/api/action-url-event", {"phone": "101", "event": key})

    def first_phone():
        return next(phone for phone in request("/phones")["phones"] if phone["number"] == "101")

    flags = first_phone()["flags"]
    assert flags["fwd_busy"] and flags["fwd_noanswer"] and flags["call_waiting"] and flags["vpn_ip"]
    request("/lab/api/reset", {})
    assert first_phone()["state"] == "В_покое"
    flags = first_phone()["flags"]
    assert not any(flags.get(key) for key in ("fwd_busy", "fwd_noanswer", "call_waiting", "vpn_ip"))


def test_manual_endpoint_does_not_interrupt_a_call_or_accept_custom_targets(live_lab):
    request, _, _ = live_lab
    ready = request("/lab/api/reset", {})
    valid = {"phone": "101", "event": "call_terminated"}
    for invalid in ({"phone": "999"}, {"event": "undefined"}, {"remote": "101"},
                    {"remote": "999"}, {"ip": "127.0.0.1"}, {"event": []}):
        with pytest.raises(urllib.error.HTTPError) as error:
            request("/lab/api/action-url-event", {**valid, **invalid})
        assert error.value.code == 400
    assert request("/lab/api/state")["monitor"]["count"] == ready["monitor"]["count"]
    ringing = request("/lab/api/action", {"phone": "101", "action": "call", "value": "102"})
    with pytest.raises(urllib.error.HTTPError) as error:
        request("/lab/api/action-url-event", valid)
    assert error.value.code == 400
    result = request("/lab/api/state")
    assert result["phones"] == ringing["phones"]
    assert result["monitor"]["count"] == ringing["monitor"]["count"]
    request("/lab/api/reset", {})


def test_lab_session_allows_real_same_origin_socketio(live_lab):
    request, base, _ = live_lab
    assert request("/user_info")["server_role"] == "standalone"
    with pytest.raises(urllib.error.HTTPError) as error:
        request("/yealink/inspect", {"ip": "192.0.2.101"})
    assert error.value.code == 403

    cookies = CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookies))

    def exchange(path, data=None):
        headers = {"Origin": base}
        if data is not None:
            headers["Content-Type"] = "text/plain; charset=UTF-8"
        with opener.open(urllib.request.Request(base + path, data=data, headers=headers), timeout=8) as response:
            return response.read().decode("utf-8")

    assert "<html" in exchange("/lab/monitor")
    assert [cookie.name for cookie in cookies] == ["sip_phone_lab_session"]
    polling = "/socket.io/?EIO=4&transport=polling"
    handshake = exchange(polling)
    assert handshake.startswith("0")
    session_path = polling + "&sid=" + json.loads(handshake[1:])["sid"]
    assert exchange(session_path, b"40") == "OK"
    assert any(packet.startswith("40") for packet in exchange(session_path).split("\x1e"))
    request("/lab/api/action-url-event", {"phone": "101", "event": "dnd_on"})
    assert any(packet.startswith('42["phones_update"') for packet in exchange(session_path).split("\x1e"))
    assert exchange(session_path, b"41") == "OK"
    request("/lab/api/reset", {})
