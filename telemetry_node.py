"""Отправка карточек и результатов пинга без регистрации узла."""

from contextlib import closing
from http.client import HTTPConnection, HTTPException
from ipaddress import IPv4Address
import json
import logging
import random
import re
import threading
import time

from availability_protocol import read_config


REPORT_PATH = "/api/federation/v1/report"
MIN_REPORT_PORT = 8500
MAX_REPORT_PORT = 8900
MAX_REPORT_REPLY = 16 * 1024
_REPORT_ID = re.compile(r"[0-9a-f]{32}")
_PHONE_FIELDS = (
    "id", "revision", "owner", "number", "name", "ip", "state", "peer",
    "call_start", "position", "ping", "flags",
)
LOG = logging.getLogger(__name__)


class ReportError(Exception):
    """Ошибка отправки, которую можно показать в панели узла."""


class TelemetryReporter:
    def __init__(self, host, port, version, snapshot, availability_probe, *,
                 interval=5, timeout=5, on_connection=None):
        if not isinstance(host, str) or str(IPv4Address(host)) != host:
            raise ValueError("Адрес Виктории для отчётов должен быть IPv4.")
        if type(port) is not int or not MIN_REPORT_PORT <= port <= MAX_REPORT_PORT:
            raise ValueError(f"Порт отчётов должен быть от {MIN_REPORT_PORT} до {MAX_REPORT_PORT}.")
        self._host = host
        self._port = port
        self._address = f"{host}:{port}"
        self._version = version
        self._snapshot = snapshot
        self._probe = availability_probe
        self._interval = interval
        self._timeout = timeout
        self._on_connection = on_connection
        self._revision = -1
        self._targets = {}
        self._node_id = None
        self._last_sync = None
        self._error = None
        self._status_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def status(self):
        with self._status_lock:
            return {
                "mode": "report", "configured": True, "url": f"http://{self._address}",
                "last_sync": self._last_sync, "enrolled": self._last_sync is not None,
                "error": self._error, "node_id": self._node_id,
                "fallback_url": None, "history_queued": 0,
            }

    def _payload(self):
        source = self._snapshot()
        phones = [
            {field: card[field] for field in _PHONE_FIELDS if field in card}
            for card in source["phones"]
        ]
        owners = {card["owner"] for card in phones}
        users = [
            {"username": item["username"], "shared": item.get("shared", False)}
            for item in source["users"] if item["username"] in owners
        ]
        return {
            "version": self._version,
            "snapshot": {"phones": phones, "users": users, "recent_events": []},
            "availability": {
                "revision": self._revision,
                "results": [[key, *result] for key, result in self._probe.results().items()],
            },
        }

    def _exchange(self, payload):
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        # HTTPConnection обращается к заданному адресу напрямую, без прокси и редиректов.
        with closing(HTTPConnection(self._host, self._port, timeout=self._timeout)) as connection:
            try:
                connection.connect()
            except OSError:
                raise ReportError(f"Нет TCP-соединения с Викторией на {self._address}.") from None
            try:
                connection.request("POST", REPORT_PATH, body, {
                    "Content-Type": "application/json", "Accept": "application/json",
                    "Connection": "close",
                })
                with connection.getresponse() as response:
                    if response.status != 200:
                        raise ReportError(f"Виктория вернула HTTP {response.status} на {self._address}.")
                    raw = response.read(MAX_REPORT_REPLY + 1)
            except (OSError, HTTPException):
                raise ReportError(f"Не удалось получить HTTP-ответ от Виктории на {self._address}.") from None
        if len(raw) > MAX_REPORT_REPLY:
            raise ReportError("Ответ Виктории слишком большой.")
        try:
            reply = json.loads(raw)
            if not isinstance(reply, dict) or set(reply) != {"node_id", "availability"}:
                raise ValueError
            node_id = reply["node_id"]
            if not isinstance(node_id, str) or _REPORT_ID.fullmatch(node_id) is None:
                raise ValueError
            revision, targets = read_config(reply["availability"])
        except (ValueError, RecursionError):
            raise ReportError("Получен некорректный ответ Виктории.") from None
        return node_id, revision, targets

    def sync_once(self):
        node_id, revision, targets = self._exchange(self._payload())
        if targets is None and revision != self._revision:
            # Запросим полный список целей при следующей отправке.
            self._revision = -1
            self._targets = {}
            self._probe.set_targets({}, observer_id=node_id)
            raise ReportError("Виктория не прислала список адресов для пинга.")
        if targets is not None:
            self._targets = targets
            self._revision = revision
        if targets is not None or node_id != self._node_id:
            self._probe.set_targets(self._targets, observer_id=node_id)
        with self._status_lock:
            self._node_id = node_id
            self._last_sync = time.time()
            self._error = None

    def start(self):
        if self._thread is None:
            self._probe.start()
            self._thread = threading.Thread(target=self._loop, name="victoria-report", daemon=True)
            self._thread.start()

    def stop(self):
        self._stop.set()
        self._probe.stop()

    def _loop(self):
        delay = self._interval
        previous = None
        while not self._stop.is_set():
            try:
                self.sync_once()
                error = None
            except ReportError as failure:
                error = str(failure)
            except Exception as failure:
                error = "Не удалось сформировать отчёт для Виктории."
                LOG.debug("Report failed: %s", type(failure).__name__)
            with self._status_lock:
                self._error = error
            outcome = "connected" if error is None else "disconnected"
            if outcome != previous and self._on_connection is not None:
                self._on_connection(outcome)
            previous = outcome
            delay = self._interval if error is None else min(delay * 2, 60)
            self._stop.wait(min(delay + random.uniform(0, min(delay / 4, 3)), 60))
