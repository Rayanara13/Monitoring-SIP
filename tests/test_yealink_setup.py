"""Протокол веб-интерфейса пилотного T30 через подставной HTTPS-транспорт."""

from hashlib import sha256
from html import escape
from importlib import import_module
import json
from pathlib import Path
import ssl
from urllib.parse import parse_qs, urlsplit

import pytest

PHONE = "192.168.123.77"
CERTIFICATE = b"test-certificate"
PASSWORD = "test-phone-admin-password"
EXPECTED = "http://monitoring.example.invalid:18081/event?token=test-secret-one&state=incoming_call"
FOREIGN = "https://other.example/event?token=test-secret-two"


class Response:
    def __init__(self, payload, status=200, headers=()):
        self.payload = payload.encode()
        self.status = status
        self.headers = headers

    def read(self, limit):
        return self.payload[:limit]

    def getheaders(self):
        return self.headers


class FakeHTTPS:
    def __init__(self, monkeypatch, module):
        self.module = module
        self.requests = []
        self.connections = []
        self.responses = []
        self.certificates = []
        monkeypatch.setattr(module, "HTTPSConnection", self.connection)

    def connection(self, host, *, port, context, timeout):
        assert (host, port) == (PHONE, 443)
        self.connections.append(context)
        transport = self

        class Connection:
            sock = None

            def connect(self):
                self.certificate = transport.certificates.pop(0) if transport.certificates else CERTIFICATE
                if isinstance(self.certificate, Exception):
                    raise self.certificate
                self.sock = self

            def getpeercert(self, *, binary_form):
                assert binary_form
                return self.certificate

            def request(self, method, path, body, headers):
                assert self.sock is not None
                assert headers["Origin"] == f"https://{PHONE}"
                assert urlsplit(path).path == "/servlet"
                transport.requests.append((method, parse_qs(urlsplit(path).query), body, headers))

            def getresponse(self):
                return transport.responses.pop(0)

            def close(self):
                self.sock = None

        return Connection()

    def inspect(self, **overrides):
        options = dict(ip=PHONE, allowed_cidrs=("192.168.123.0/24",), username="test-admin", password=PASSWORD)
        options.update(overrides)
        return self.module.inspect_phone(**options)


@pytest.fixture
def phone(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return FakeHTTPS(monkeypatch, import_module("yealink_setup"))


def login_form(model="T30"):
    return Response(f'''<title>Yealink {model} Phone</title><script>
var g_phonetype = "{model}";
var g_rsa_n = "{'f' * 256}";
var g_rsa_e = "10001";
</script>''', headers=[("Set-Cookie", "JSESSIONID=fixture-cookie; Path=/; HttpOnly")])


def status_page(firmware="124.87.14.1"):
    return Response(f'''<script>var g_phonetype = "T30"; var g_strFirmware = "{firmware}";</script>
<label id="PhoneFirmware" dvalue="{firmware}"></label><td id="tdMACAddress">001565123456</td>''')


def action_page(phone, missing=None):
    values = {"AUIncomingCall": EXPECTED, "AUCallOut": FOREIGN, "AUViewForWard": "https://enabled.example"}
    return Response("".join(
        f'<input name="{field}" dvalue="{escape(values.get(field, ""), quote=True)}">'
        for field in phone.module.T30_ACTION_FIELDS.values() if field != missing
    ))


def requests_summary(phone):
    return [(method, query["p"][0], query["q"][0]) for method, query, _, _ in phone.requests]


@pytest.mark.parametrize("pinned", [False, True])
def test_pilot_profile_reads_and_compares_without_exposing_values(phone, pinned):
    phone.responses = [login_form(), Response('<div id="_RES_INFO_">{"authstatus":"done"}</div>'),
                       status_page(), action_page(phone), Response("")]
    pin = sha256(CERTIFICATE).hexdigest() if pinned else None
    result = phone.inspect(expected_urls={"incoming_call": EXPECTED, "outgoing_call": EXPECTED},
                           certificate_sha256=pin)
    assert result["status"] == "compatible"
    assert result["compatible"] is True
    assert (result["model"], result["firmware"], result["mac"]) == ("SIP-T30", "124.87.14.1", "00:15:65:12:34:56")
    assert len(result["fields"]) == 48
    assert result["fields"]["incoming_call"] == "match"
    assert result["fields"]["outgoing_call"] == "conflict"
    assert result["fields"]["view_forwarded_call"] == "configured"
    assert result["fields"]["dnd_on"] == "empty"
    assert result["counts"] == {"match": 1, "conflict": 1, "configured": 1, "empty": 45, "missing": 0}
    serialized = json.dumps(result)
    for secret in (EXPECTED, FOREIGN, PASSWORD, "test-secret-one", "test-secret-two", "fixture-cookie"):
        assert secret not in serialized
    assert requests_summary(phone) == [
        ("GET", "login", "loginForm"), ("POST", "login", "login"),
        ("GET", "status", "load"), ("GET", "features-actionurl", "load"),
        ("GET", "login", "logout"),
    ]
    _, _, body, headers = phone.requests[1]
    form = parse_qs(body.decode("ascii"))
    assert form["username"] == ["test-admin"]
    assert form["pwd"][0] != PASSWORD
    assert int(form["pwd"][0], 16) > 0
    assert headers["Cookie"] == "JSESSIONID=fixture-cookie"
    verify_mode = ssl.CERT_NONE if pinned else ssl.CERT_REQUIRED
    assert all(context.check_hostname is not pinned and context.verify_mode == verify_mode for context in phone.connections)


@pytest.mark.parametrize(("address", "code"), [
    ("https://192.168.123.77", "invalid_ip"), ("192.168.123.77:443", "invalid_ip"),
    ("phone.local", "invalid_ip"), ("fe80::1%eth0", "invalid_ip"),
    ("192.168.123.77\n", "invalid_ip"), ("::ffff:192.168.123.77", "address_not_allowed"),
    ("127.0.0.1", "address_not_allowed"), ("192.168.51.77", "address_not_allowed"),
    ("192.168.123.0", "address_not_allowed"), ("192.168.123.255", "address_not_allowed"),
])
def test_only_literal_hosts_in_allowed_lan_may_connect(phone, address, code):
    with pytest.raises(phone.module.YealinkSetupError) as error:
        phone.inspect(ip=address)
    assert error.value.code == code
    assert phone.connections == []


@pytest.mark.parametrize("cidrs", [[], ["0.0.0.0/0"], ["192.168.123.77/24"], ["192.168.123.77"]])
def test_bad_server_network_configuration_fails_closed(phone, cidrs):
    with pytest.raises(phone.module.YealinkSetupError) as error:
        phone.inspect(allowed_cidrs=cidrs)
    assert error.value.code == "invalid_networks"
    assert phone.connections == []


def test_chain_verification_failure_prevents_http(phone):
    phone.certificates = [ssl.SSLCertVerificationError("untrusted")]
    with pytest.raises(phone.module.YealinkSetupError) as error:
        phone.inspect()
    assert error.value.code == "certificate_untrusted"
    assert phone.requests == []


def test_certificate_change_before_login_cannot_send_password(phone):
    phone.responses = [login_form()]
    phone.certificates = [CERTIFICATE, b"changed-certificate"]
    with pytest.raises(phone.module.YealinkSetupError) as error:
        phone.inspect(certificate_sha256=sha256(CERTIFICATE).hexdigest())
    assert error.value.code == "certificate_mismatch"
    assert requests_summary(phone) == [("GET", "login", "loginForm")]


def test_no_redirect_followed(phone):
    phone.responses = [Response("", 302, [("Location", "https://other.example/")])]
    with pytest.raises(phone.module.YealinkSetupError) as error:
        phone.inspect()
    assert error.value.code == "redirect_rejected"
    assert len(phone.connections) == len(phone.requests) == 1


def test_t30p_is_rejected_before_login_even_with_valid_pin(phone):
    phone.responses = [login_form("T30P")]
    result = phone.inspect(certificate_sha256=sha256(CERTIFICATE).hexdigest())
    assert result["status"] == "unsupported_profile"
    assert result["model"] == "SIP-T30P"
    assert result["fields"] == {}
    assert requests_summary(phone) == [("GET", "login", "loginForm")]


def test_unknown_t30_firmware_is_not_used_to_read_action_urls(phone):
    phone.responses = [login_form(), Response('{"authstatus":"done"}'), status_page("124.87.14.2"), Response("")]
    result = phone.inspect()
    assert result["status"] == "unsupported_profile"
    assert result["firmware"] == "124.87.14.2"
    assert result["fields"] == {}
    assert requests_summary(phone)[-2:] == [("GET", "status", "load"), ("GET", "login", "logout")]


def test_incomplete_web_layout_returns_missing_key_and_blocks_compatibility(phone):
    phone.responses = [login_form(), Response('{"authstatus":"done"}'), status_page(),
                       action_page(phone, missing="AUIncomingCall"), Response("")]
    result = phone.inspect(expected_urls={"incoming_call": EXPECTED})
    assert result["status"] == "unsupported_layout"
    assert result["compatible"] is False
    assert result["fields"]["incoming_call"] == "missing"
    assert result["counts"]["missing"] == 1


def test_remote_login_error_does_not_escape_to_ui(phone):
    phone.responses = [login_form(), Response(json.dumps({"authstatus": "failed", "msg": PASSWORD}))]
    with pytest.raises(phone.module.YealinkSetupError) as error:
        phone.inspect()
    assert error.value.code == "login_failed"
    assert PASSWORD not in str(error.value)
