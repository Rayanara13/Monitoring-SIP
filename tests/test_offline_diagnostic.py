from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
import json
import ssl
from threading import Thread
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

from offline import diagnose


def check_codes(report):
    return {check.code: check.status for check in report.checks}


def test_snapshot_and_report_include_only_allowlisted_values(tmp_path, monkeypatch):
    monkeypatch.delenv("FEDERATION_MASTER_IP", raising=False)
    data = tmp_path / "data"
    data.mkdir()
    users = data / "users_data"
    users.mkdir()
    token = "fixture-secret-do-not-export"
    (data / ".env").write_text(f"APP_SECRET_KEY={token}\nFEDERATION_MASTER_IP=10.1.2.3\n", encoding="utf-8")
    (users / "diagnostic-status.json").write_text(json.dumps({
        "schema": 1,
        "updated_at": time.time(),
        "last_event_at": time.time() - 180,
        "last_sync": time.time() - 120,
        "link_state": "invitation_expired",
        "event_error": "invalid_token",
        "version": "Rel 1.5",
        "logging_ok": False,
        "details": f"https://10.1.2.3/event?token={token}",
    }), encoding="utf-8")
    before = {file.relative_to(data): file.read_bytes() for file in data.rglob("*") if file.is_file()}
    report = diagnose.Report()
    diagnose.inspect_data(data, report)
    diagnose.inspect_snapshot(data, diagnose.settings_from(data, None), report)
    assert check_codes(report)["NODE_INVITATION_EXPIRED"] == "FAIL"
    assert check_codes(report)["NODE_LAST_SYNC"] == "WARN"
    assert check_codes(report)["PHONE_EVENT_INVALID_TOKEN"] == "WARN"
    assert check_codes(report)["APP_LOG_WRITE_FAILED"] == "WARN"
    base = tmp_path / "report"
    diagnose.save_report(base, report)
    for suffix in ("txt", "json"):
        contents = base.with_suffix(f".{suffix}").read_text(encoding="utf-8")
        assert token not in contents and "10.1.2.3" not in contents
    with pytest.raises(FileExistsError):
        diagnose.save_report(base, report)
    assert before == {file.relative_to(data): file.read_bytes() for file in data.rglob("*") if file.is_file()}


def test_linux_active_interface_with_wrong_address(monkeypatch):
    responses = iter([
        json.dumps([{"ifname": "eth1", "flags": ["UP", "LOWER_UP"],
                     "addr_info": [{"local": "10.20.30.40", "dynamic": True}]}]),
        json.dumps([{"dst": "default", "gateway": "10.20.30.1"}]),
    ])
    monkeypatch.setattr(diagnose, "run_readonly", lambda _command: next(responses))
    report = diagnose.Report()
    diagnose.inspect_linux_network("10.22.99.11", report)
    assert check_codes(report)["LINK_WITHOUT_STATIC_IP"] == "FAIL"
    assert not any(value in report.text() for value in ("10.20.30.40", "10.20.30.1", "10.22.99.11"))


def make_loopback_certificate(folder):
    now = datetime.now(timezone.utc)
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Node diagnostic fixture")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]),
                           critical=False).sign(key, algorithm=None))
    path = folder / "fixture.crt"
    path.write_bytes(cert.public_bytes(Encoding.PEM))
    (folder / "tls.key").write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return path


@contextmanager
def fixture_server(tls_dir=None):
    requests = []
    identity = {"center_id": "fixture-center"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization")))
            body = (json.dumps(identity).encode() if self.path == diagnose.API_IDENTITY
                    else b'<form id="login-form"></form>')
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        ca = None
        if tls_dir is not None:
            cert = make_loopback_certificate(tls_dir)
            ca = cert.read_text(encoding="ascii")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, tls_dir / "tls.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, ca, requests, identity
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_explicit_victoria_probe_verifies_tls_and_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnose, "KIT", tmp_path)
    users = tmp_path / "users_data"
    users.mkdir()
    with fixture_server(tmp_path) as (port, ca, requests, identity):
        link = {"schema": 1, "url": f"https://127.0.0.1:{port}", "tls_ca": ca, "center_id": "fixture-center"}
        path = users / "diagnostic-link.json"
        path.write_text(json.dumps(link), encoding="utf-8")
        report = diagnose.Report()
        report.role = "node"
        diagnose.probe_victoria(tmp_path, {}, None, report)
        assert check_codes(report)["VICTORIA_IDENTITY_OK"] == "PASS"
        assert requests == [(diagnose.API_IDENTITY, None)]
        identity["center_id"] = "wrong-center"
        diagnose.probe_victoria(tmp_path, {}, None, report)
        assert check_codes(report)["VICTORIA_IDENTITY_MISMATCH"] == "FAIL"
        assert len(requests) == 2
        path.write_text(json.dumps({**link, "tls_ca": "invalid local CA"}), encoding="utf-8")
        diagnose.probe_victoria(tmp_path, {}, None, report)
        assert check_codes(report)["VICTORIA_TLS_UNTRUSTED"] == "FAIL"
        assert len(requests) == 2
        path.write_text(json.dumps({**link, "url": "https://8.8.8.8"}), encoding="utf-8")
        diagnose.probe_victoria(tmp_path, {}, None, report)
        assert check_codes(report)["VICTORIA_TRUST_MISSING"] == "SKIP"
