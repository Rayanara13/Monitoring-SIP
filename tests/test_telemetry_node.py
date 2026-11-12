import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

import pytest

from telemetry_node import MAX_REPORT_PORT, MIN_REPORT_PORT, REPORT_PATH, ReportError, TelemetryReporter


NODE_ID = "a" * 32


class Probe:
    def __init__(self):
        self.measurements = {}
        self.targets = {}
        self.observer_id = None

    def set_targets(self, targets, *, observer_id):
        self.targets = targets
        self.observer_id = observer_id

    def results(self):
        return self.measurements

    def start(self):
        pass

    def stop(self):
        pass


@contextmanager
def endpoint(replies):
    requests = []
    pending = iter(replies)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, dict(self.headers.items()), body))
            status, headers, reply = next(pending)
            raw = json.dumps(reply).encode()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, _format, *_args):
            pass

    for port in range(MAX_REPORT_PORT, MIN_REPORT_PORT - 1, -1):
        try:
            server = HTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    else:
        pytest.fail("Нет свободного локального порта для теста отчётов.")

    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_reports_only_cards_and_probe_data_over_plain_http(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    card = {"id": "1", "owner": "operator", "number": "123", "state": "idle"}
    snapshot = {
        "phones": [{**card, "event_token": "never-send"}],
        "users": [
            {"username": "operator", "shared": True, "password": "never-send"},
            {"username": "without_cards", "shared": False},
        ],
        "recent_events": [{"peer": "never-send"}],
        "history": [{"record": "never-send"}],
    }
    probe = Probe()
    with endpoint([
        (200, {}, {"node_id": NODE_ID, "availability": {"revision": 4, "targets": [[2, "10.12.3.4"]]}}),
        (200, {}, {"node_id": NODE_ID, "availability": {"revision": 4}}),
    ]) as (port, requests):
        reporter = TelemetryReporter("127.0.0.1", port, "1.4.test", lambda: snapshot, probe)
        assert reporter.status()["enrolled"] is False
        reporter.sync_once()
        assert probe.targets == {2: "10.12.3.4"}
        assert probe.observer_id == NODE_ID
        probe.measurements = {2: ("ok", 2.4, 10)}
        reporter.sync_once()

    assert len(requests) == 2
    path, headers, first = requests[0]
    assert path == REPORT_PATH
    assert "Authorization" not in headers
    assert "Cookie" not in headers
    assert first == {
        "version": "1.4.test",
        "snapshot": {"phones": [card], "users": [{"username": "operator", "shared": True}], "recent_events": []},
        "availability": {"revision": -1, "results": []},
    }
    assert requests[1][2]["availability"] == {"revision": 4, "results": [[2, "ok", 2.4, 10]]}
    status = reporter.status()
    assert status["mode"] == "report" and status["enrolled"] is True
    assert status["node_id"] == NODE_ID and status["last_sync"] is not None and status["error"] is None


def test_report_does_not_follow_redirects_and_shows_http_error():
    snapshot = {"phones": [], "users": []}
    with endpoint([(307, {"Location": "/another-url"}, {})]) as (port, requests):
        disconnected = threading.Event()
        reporter = TelemetryReporter(
            "127.0.0.1", port, "1.4.test", lambda: snapshot, Probe(),
            on_connection=lambda outcome: disconnected.set() if outcome == "disconnected" else None,
        )
        reporter.start()
        try:
            assert disconnected.wait(3)
            assert "HTTP 307" in reporter.status()["error"]
            assert reporter.status()["last_sync"] is None
        finally:
            reporter.stop()
    assert [path for path, _, _ in requests] == [REPORT_PATH]


def test_report_rejects_response_containing_commands():
    snapshot = {"phones": [], "users": []}
    reply = {"node_id": NODE_ID, "availability": {"revision": 0, "targets": []}, "commands": []}
    with endpoint([(200, {}, reply)]) as (port, _requests):
        reporter = TelemetryReporter("127.0.0.1", port, "1.4.test", lambda: snapshot, Probe())
        with pytest.raises(ReportError, match="некорректный ответ"):
            reporter.sync_once()
        assert reporter.status()["last_sync"] is None
