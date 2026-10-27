"""Дублирование GET на центральный сервер — только если TARGET_IP задан в .env."""
import time
from pathlib import Path


def capture_urlopen(srv, monkeypatch):
    calls = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(url, timeout=None):
        calls.append(url)
        return _Resp()

    monkeypatch.setattr(srv.server.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_no_default_target(srv):
    """В коде нет адреса центрального сервера по умолчанию — только из .env."""
    assert srv.server.get_env_value("TARGET_IP", "") == ""
    source = Path(srv.server.__file__).read_text(encoding="utf-8")
    assert 'TARGET_IP = get_env_value("TARGET_IP", "")' in source


def test_no_target_no_duplication(srv, monkeypatch):
    calls = capture_urlopen(srv, monkeypatch)
    monkeypatch.setattr(srv.server, "TARGET_IP", "")
    srv.ev("dnd_on")
    time.sleep(0.3)
    assert calls == []


def test_target_set_duplicates(srv, monkeypatch):
    calls = capture_urlopen(srv, monkeypatch)
    monkeypatch.setattr(srv.server, "TARGET_IP", "10.1.2.3")
    srv.ev("dnd_on")
    for _ in range(20):
        if calls:
            break
        time.sleep(0.05)
    assert calls and calls[0].startswith("http://10.1.2.3:8000/event?")
