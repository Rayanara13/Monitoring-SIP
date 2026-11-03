"""Реальный loopback HTTP: телефон → /event → мониторинг → история."""
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
        process = subprocess.Popen([sys.executable, "-m", "simulator", "--port", str(port),
                                    "--data-dir", str(runtime / "data")], cwd=ROOT,
                                   env={**os.environ, "PYTHONUTF8": "1"}, stdout=log, stderr=log)
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


def test_lab_rejects_cross_site_actions(live_lab):
    _, base, _ = live_lab
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(base + "/lab/api/action", data=b'{"phone":"101","action":"dnd"}',
                                     headers={"Content-Type": "application/json", "Origin": "https://other.example"})
    with pytest.raises(urllib.error.HTTPError) as error:
        opener.open(request, timeout=8)
    assert error.value.code == 403
