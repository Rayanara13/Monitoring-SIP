"""Проверка Action URL на SIP-T30 через его веб-интерфейс."""

from collections.abc import Iterable, Mapping
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
from http.client import HTTPException, HTTPSConnection
from http.cookies import CookieError, SimpleCookie
from ipaddress import ip_address, ip_network
import hmac
import json
import math
import re
import secrets
import ssl
import time
from types import MappingProxyType
from urllib.parse import urlencode


SUPPORTED_MODEL = "SIP-T30"
SUPPORTED_FIRMWARE = "124.87.14.1"

# Имена полей прочитаны из веб-интерфейса аппарата в пилоте 11.11.2026.
T30_ACTION_FIELDS = MappingProxyType({
    "setup_completed": "AUSetupCompleted",
    "registered": "AULogOn",
    "unregistered": "AULogOff",
    "register_failed": "AURegisterFailed",
    "off_hook": "AUOffHook",
    "on_hook": "AUOnHook",
    "incoming_call": "AUIncomingCall",
    "outgoing_call": "AUCallOut",
    "call_established": "AUEstablished",
    "call_terminated": "AUTerminated",
    "dnd_on": "AUOpenDnd",
    "dnd_off": "AUCloseDnd",
    "always_fwd_on": "AUOpenAlwaysForward",
    "always_fwd_off": "AUCloseAlwaysForward",
    "busy_fwd_on": "AUOpenBusyForward",
    "busy_fwd_off": "AUCloseBusyForward",
    "no_answer_fwd_on": "AUOpenNoAnswerForward",
    "no_answer_fwd_off": "AUCloseNoAnswerForward",
    "transfer_call": "AUTransferCall",
    "blind_transfer_call": "AUBlindTransfer",
    "attended_transfer_call": "AUAttendedTransfer",
    "hold": "AUHold",
    "unhold": "AUUnHold",
    "mute": "AUMute",
    "unmute": "AUUnMute",
    "missed_call": "AUMissedCall",
    "ip_change": "AUIpChanged",
    "idle_to_busy": "AUIdleToBusy",
    "busy_to_idle": "AUBusyToIdle",
    "reject_incoming_call": "AURejectIncomingCall",
    "answer_new_incoming_call": "AUAnswerNewInCall",
    "transfer_failed": "AUTransferFailed",
    "transfer_finished": "AUTransferFinished",
    "forward_incoming_call": "AUForwardIncomingCall",
    "setup_autop_finish": "AUAutopFinish",
    "call_waiting_on": "AUOpenCallWait",
    "call_waiting_off": "AUCloseCallWait",
    "headset": "AUHeadSet",
    "handfree": "AUHandFree",
    "cancel_callout": "AUCancelCallOut",
    "remote_busy": "AURemoteBusy",
    "call_remote_canceled": "AUCallRemoteCanceled",
    "view_missed_call": "AUViewMissCall",
    "view_forwarded_call": "AUViewForWard",
    "peripheral_information": "AUPeripheralInformation",
    "vpn_ip": "AUVPNIPChange",
    "sip_info_display_update": "AUSipInfoDisplayUpdate",
    "conference": "AUConference",
})

_LAN_NETWORKS = tuple(map(ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
_STATUS_PATH = "/servlet?m=mod_data&p=status&q=load"
_ACTION_PATH = "/servlet?m=mod_data&p=features-actionurl&q=load"
_LOGIN_PATH = "/servlet?m=mod_listener&p=login"
_MAX_RESPONSE = 1024 * 1024
_FIELD_STATUSES = ("match", "empty", "conflict", "configured", "missing")


class YealinkSetupError(Exception):
    """Ошибка с безопасным для UI сообщением и стабильным кодом."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _validate_address(value, allowed_cidrs):
    if not isinstance(value, str) or "%" in value:
        raise YealinkSetupError("invalid_ip", "Введите IP-адрес телефона.")
    try:
        address = ip_address(value)
    except ValueError:
        raise YealinkSetupError("invalid_ip", "Введите IP-адрес телефона.") from None

    entries = (allowed_cidrs,) if isinstance(allowed_cidrs, str) else allowed_cidrs
    try:
        networks = []
        for entry in entries:
            if not isinstance(entry, str) or "/" not in entry or "%" in entry:
                raise ValueError
            network = ip_network(entry, strict=True)
            if not any(network.version == lan.version and network.subnet_of(lan) for lan in _LAN_NETWORKS):
                raise ValueError
            networks.append(network)
    except (TypeError, ValueError):
        raise YealinkSetupError("invalid_networks", "Неверно заданы разрешённые телефонные сети.") from None

    if not networks:
        raise YealinkSetupError("invalid_networks", "Разрешённые телефонные сети не настроены.")
    for network in networks:
        if address not in network:
            continue
        if network.version == 4 and network.prefixlen < 31 and address in (network.network_address, network.broadcast_address):
            continue
        return address.compressed
    raise YealinkSetupError("address_not_allowed", "IP-адрес вне разрешённых телефонных сетей.")


def _certificate_pin(value):
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}|(?:[a-f0-9]{2}:){31}[a-f0-9]{2}", value, re.I):
        raise YealinkSetupError("invalid_certificate_pin", "Неверный формат отпечатка SHA-256 сертификата.")
    return value.replace(":", "").lower()


class _PhoneSession:
    def __init__(self, ip, pin, timeout):
        self.ip = ip
        self.pin = pin
        self.timeout = timeout
        self.host = f"[{ip}]" if ":" in ip else ip
        self.origin = f"https://{self.host}"
        self.cookies = SimpleCookie()
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if pin is None:
            self.tls.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            self.tls.check_hostname = False
            self.tls.verify_mode = ssl.CERT_NONE

    def request(self, path, form=None):
        headers = {
            "Host": self.host,
            "User-Agent": "Mozilla/5.0",
            "Origin": self.origin,
            "Referer": self.origin + _STATUS_PATH,
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.cookies:
            headers["Cookie"] = "; ".join(cookie.OutputString(attrs=[]) for cookie in self.cookies.values())
        body = None
        if form is not None:
            body = urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        connection = HTTPSConnection(self.ip, port=443, context=self.tls, timeout=self.timeout)
        try:
            connection.connect()
            # Проверяем каждый новый TLS-канал до HTTP, включая запрос с паролем.
            if self.pin is not None:
                certificate = connection.sock.getpeercert(binary_form=True)
                if not certificate or not hmac.compare_digest(sha256(certificate).hexdigest(), self.pin):
                    raise YealinkSetupError("certificate_mismatch", "Сертификат телефона не совпадает с закреплённым.")
            connection.request("POST" if body is not None else "GET", path, body, headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise YealinkSetupError("redirect_rejected", "Веб-интерфейс телефона вернул перенаправление.")
            payload = response.read(_MAX_RESPONSE + 1)
            if len(payload) > _MAX_RESPONSE:
                raise YealinkSetupError("invalid_response", "Ответ телефона превышает допустимый размер.")
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    self.cookies.load(value)
            return response.status, payload.decode("utf-8", errors="replace")
        except ssl.SSLCertVerificationError:
            raise YealinkSetupError("certificate_untrusted", "Не удалось подтвердить сертификат и IP телефона.") from None
        except ssl.SSLError:
            raise YealinkSetupError("tls_error", "Не удалось установить HTTPS-соединение с телефоном.") from None
        except (OSError, HTTPException):
            raise YealinkSetupError("network_error", "Веб-интерфейс телефона недоступен.") from None
        except (CookieError, ValueError):
            raise YealinkSetupError("invalid_response", "Телефон вернул неподдерживаемый ответ.") from None
        finally:
            connection.close()

    def get(self, path):
        status, source = self.request(path)
        if status != 200:
            raise YealinkSetupError("unexpected_http_status", "Не удалось прочитать веб-страницу телефона.")
        return source

    def login(self, source, username, password):
        modulus = _js_value(source, "g_rsa_n", r"[a-fA-F0-9]{128,1024}")
        exponent = _js_value(source, "g_rsa_e", r"[a-fA-F0-9]{1,8}")
        encrypted = _encrypt_password(password, modulus, exponent)
        status, payload = self.request(
            f"{_LOGIN_PATH}&q=login&Rajax={time.time()}",
            {"username": username, "pwd": encrypted},
        )
        try:
            result = json.loads(payload)
        except ValueError:
            match = re.search(r'<div id="_RES_INFO_"[^>]*>(.*?)</div>', payload, re.S)
            try:
                result = json.loads(unescape(match[1])) if match else None
            except ValueError:
                result = None
        if status != 200 or not isinstance(result, dict) or result.get("authstatus") != "done":
            raise YealinkSetupError("login_failed", "Не удалось войти в веб-интерфейс телефона.")

    def logout(self):
        if self.cookies:
            try:
                self.request(f"{_LOGIN_PATH}&q=logout")
            except YealinkSetupError:
                pass
            finally:
                self.cookies.clear()


def _js_value(source, name, pattern):
    match = re.search(rf"\b{re.escape(name)}\s*=\s*(['\"])({pattern})\1", source)
    return match[2] if match else None


def _encrypt_password(password, modulus, exponent):
    if modulus is None or exponent is None:
        raise YealinkSetupError("invalid_response", "Веб-интерфейс телефона не предоставил ключ входа.")
    number, power = int(modulus, 16), int(exponent, 16)
    if not 512 <= number.bit_length() <= 4096 or number % 2 == 0 or not 3 <= power <= 65537 or power % 2 == 0:
        raise YealinkSetupError("invalid_response", "Телефон предоставил неподдерживаемый ключ входа.")
    size = (number.bit_length() + 7) // 8
    message = password.encode("utf-8")
    if len(message) > size - 11:
        raise YealinkSetupError("invalid_credentials", "Пароль слишком длинный для веб-интерфейса телефона.")
    # Формат RSA PKCS#1 v1.5, который использует веб-форма этой прошивки.
    padding = bytes(secrets.randbelow(255) + 1 for _ in range(size - len(message) - 3))
    block = b"\x00\x02" + padding + b"\x00" + message
    ciphertext = format(pow(int.from_bytes(block, "big"), power, number), "x")
    return ciphertext if len(ciphertext) % 2 == 0 else "0" + ciphertext


class _PageFields(HTMLParser):
    def __init__(self, source, names, ids=()):
        super().__init__()
        self.names = set(names)
        self.ids = set(ids)
        self.fields = {}
        self.text_field = None
        self.text_parts = []
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        field_id = attrs.get("id")
        name = attrs.get("name")
        if field_id in self.ids:
            name = field_id
        elif tag not in ("input", "textarea", "select") or name not in self.names:
            return
        if "dvalue" in attrs or "value" in attrs:
            self._store(name, attrs.get("dvalue", attrs.get("value")) or "")
        elif tag != "input" and (field_id in self.ids or tag == "textarea"):
            self.text_field = (tag, name)
            self.text_parts = []

    def handle_data(self, data):
        if self.text_field:
            self.text_parts.append(data)

    def handle_endtag(self, tag):
        if self.text_field and tag == self.text_field[0]:
            self._store(self.text_field[1], "".join(self.text_parts).strip())
            self.text_field = None

    def _store(self, name, value):
        if name in self.fields and self.fields[name] != value:
            raise YealinkSetupError("invalid_response", "Веб-страница телефона содержит противоречивые значения.")
        self.fields[name] = value


def _model(source):
    value = _js_value(source, "g_phonetype", r"(?:SIP-)?T[0-9]{2,3}[A-Za-z]{0,4}")
    return "SIP-" + value.upper().removeprefix("SIP-") if value else None


def _firmware(source, field=None):
    pattern = r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
    advertised = _js_value(source, "g_strFirmware", pattern)
    if not field:
        return advertised
    if not re.fullmatch(pattern, field) or (advertised and advertised != field):
        return None
    return field


def _mac(value):
    if not value or not re.fullmatch(r"[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}", value, re.I):
        return None
    normalized = value.replace(":", "").replace("-", "").upper()
    return ":".join(normalized[i:i + 2] for i in range(0, 12, 2))


def _summary(status, model, firmware, mac=None, fields=None):
    fields = {} if fields is None else fields
    return {
        "status": status,
        "compatible": status == "compatible",
        "model": model,
        "firmware": firmware,
        "mac": mac,
        "fields": fields,
        "counts": {value: sum(field == value for field in fields.values()) for value in _FIELD_STATUSES},
    }


def inspect_phone(ip: str, *, allowed_cidrs: Iterable[str] | str, username: str, password: str,
                  expected_urls: Mapping[str, str] | None = None, certificate_sha256: str | None = None,
                  timeout: float = 5.0) -> dict:
    """Сверить поддержанный профиль и вернуть только статусы полей Action URL.

    `allowed_cidrs` задаётся сервером и ограничен RFC 1918 или IPv6 ULA.
    `expected_urls` сопоставляет ключи событий полным ожидаемым URL.
    """
    address = _validate_address(ip, allowed_cidrs)
    pin = _certificate_pin(certificate_sha256)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30 or not math.isfinite(timeout):
        raise YealinkSetupError("invalid_timeout", "Неверно задано время ожидания телефона.")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise YealinkSetupError("invalid_credentials", "Серверный профиль доступа к телефону не настроен.")
    try:
        username.encode("utf-8")
        password.encode("utf-8")
    except UnicodeError:
        raise YealinkSetupError("invalid_credentials", "Серверный профиль доступа к телефону содержит некорректные данные.") from None
    expected = {} if expected_urls is None else expected_urls
    if not isinstance(expected, Mapping) or any(
        key not in T30_ACTION_FIELDS or not isinstance(value, str) or not value.strip()
        for key, value in expected.items()
    ):
        raise YealinkSetupError("invalid_expected_urls", "Неверно заданы ожидаемые параметры Action URL.")

    try:
        session = _PhoneSession(address, pin, timeout)
    except OSError:
        raise YealinkSetupError("tls_error", "Не удалось настроить проверку HTTPS-сертификата телефона.") from None
    login_page = session.get(f"{_LOGIN_PATH}&q=loginForm&Random={time.time()}")
    model = _model(login_page)
    firmware = _firmware(login_page)
    if model != SUPPORTED_MODEL or (firmware and firmware != SUPPORTED_FIRMWARE):
        return _summary("unsupported_profile", model, firmware)

    session.login(login_page, username, password)
    try:
        status_page = session.get(_STATUS_PATH)
        device = _PageFields(status_page, (), ("PhoneFirmware", "tdMACAddress")).fields
        model = _model(status_page)
        firmware = _firmware(status_page, device.get("PhoneFirmware"))
        mac = _mac(device.get("tdMACAddress"))
        if model != SUPPORTED_MODEL or firmware != SUPPORTED_FIRMWARE:
            return _summary("unsupported_profile", model, firmware, mac)
        if mac is None:
            return _summary("unsupported_layout", model, firmware)

        source = session.get(_ACTION_PATH)
        current = _PageFields(source, T30_ACTION_FIELDS.values()).fields
        fields = {}
        for state, field in T30_ACTION_FIELDS.items():
            if field not in current:
                fields[state] = "missing"
            elif not current[field].strip():
                fields[state] = "empty"
            elif state not in expected:
                fields[state] = "configured"
            else:
                fields[state] = "match" if current[field] == expected[state] else "conflict"
        status = "unsupported_layout" if "missing" in fields.values() else "compatible"
        return _summary(status, model, firmware, mac, fields)
    finally:
        session.logout()
