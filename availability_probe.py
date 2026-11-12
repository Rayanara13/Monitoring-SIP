"""Локальные ICMP-замеры для распределённой доступности."""

from collections import deque
import ctypes
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
from ipaddress import IPv4Address
import os
import re
import struct
import subprocess
import threading
import time
from typing import Literal


PROBE_INTERVAL = 10
FRESH_SECONDS = 30
_LOSS_WINDOW = 10
_PAYLOAD_SIZE = 16  # iputils использует 16 байт для временной метки на 64-битной системе.
_TIMEOUT_MS = 1000
_UNREACHABLE_WINDOWS = {
    11002, 11003, 11004, 11005,  # IP_DEST_*_UNREACHABLE
    11010, 11012, 11013, 11014,  # Тайм-аут, ошибка маршрута или истёкший TTL.
    11040, 1231, 1232,  # Недоступность назначения в кодах IP Helper и Win32.
}
_UNREACHABLE_LINUX = re.compile(r"(?:network is unreachable|no route to host|destination .* unreachable)", re.I)
_RTT_LINUX = re.compile(r"\btime[=<]\s*(\d+(?:\.\d+)?)\s*ms\b")

ProbeStatus = Literal["ok", "unreachable", "error"]


@lru_cache(maxsize=1)
def _windows_icmp():
    from ctypes import wintypes

    api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)  # System32.
    api.IcmpCreateFile.argtypes = ()
    api.IcmpCreateFile.restype = wintypes.HANDLE
    api.IcmpCloseHandle.argtypes = (wintypes.HANDLE,)
    api.IcmpCloseHandle.restype = wintypes.BOOL
    api.IcmpSendEcho.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.WORD,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    )
    api.IcmpSendEcho.restype = wintypes.DWORD
    return api


def _ping_windows(address: IPv4Address) -> tuple[ProbeStatus, float | None]:
    api = _windows_icmp()
    handle = api.IcmpCreateFile()
    if handle in (None, ctypes.c_void_p(-1).value):
        return "error", None

    try:
        destination, = struct.unpack("=I", address.packed)
        payload = ctypes.create_string_buffer(_PAYLOAD_SIZE)
        # Заголовок ICMP_ECHO_REPLY, данные, IP-опции и запас для сообщения об ошибке.
        reply = ctypes.create_string_buffer(128)
        count = api.IcmpSendEcho(handle, destination, payload, len(payload), None, reply, len(reply), _TIMEOUT_MS)
        if count:
            # Первые три DWORD имеют одинаковую раскладку на Windows x86 и x64.
            source, status, rtt = struct.unpack_from("=III", reply)
            if status == 0 and source == destination:
                return "ok", float(rtt)
        else:
            status = ctypes.get_last_error()
        return ("unreachable" if status in _UNREACHABLE_WINDOWS else "error"), None
    finally:
        api.IcmpCloseHandle(handle)


def _ping_linux(address: IPv4Address) -> tuple[ProbeStatus, float | None]:
    result = subprocess.run(
        ["ping", "-4", "-n", "-c", "1", "-w", "1", "-W", "1", "-s", str(_PAYLOAD_SIZE), str(address)],
        capture_output=True, encoding="ascii", errors="replace", timeout=2,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode == 0:
        rtt = _RTT_LINUX.search(result.stdout)
        if rtt:
            return "ok", float(rtt.group(1))
    if _UNREACHABLE_LINUX.search(result.stderr) or (result.returncode == 1 and not result.stderr):
        return "unreachable", None
    return "error", None


def probe_ipv4(ip: str) -> tuple[ProbeStatus, float | None]:
    try:
        address = IPv4Address(ip)
        if os.name == "nt":
            return _ping_windows(address)
        return _ping_linux(address)
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return "error", None


@dataclass
class _Target:
    ip: str
    next_check: float
    measurement: tuple[ProbeStatus, float | None, float] | None = None
    valid_attempts: deque[tuple[bool, float]] = field(default_factory=lambda: deque(maxlen=_LOSS_WINDOW))


class AvailabilityProbe:
    def __init__(self, observer_id: str, max_workers: int = 16):
        self._observer_id = observer_id
        self._max_workers = max_workers
        self._condition = threading.Condition()
        self._thread: threading.Thread | None = None
        self._stopping = False
        self._targets: dict[int, _Target] = {}
        self._running: set[int] = set()

    def start(self) -> None:
        with self._condition:
            if self._thread is None:
                self._stopping = False
                self._thread = threading.Thread(target=self._loop, name="availability", daemon=True)
                self._thread.start()

    def stop(self) -> None:
        with self._condition:
            thread = self._thread
            if thread is None:
                return
            self._stopping = True
            self._condition.notify_all()
        thread.join()
        with self._condition:
            if self._thread is thread:
                self._thread = None
                for target in self._targets.values():
                    target.measurement = None
                    target.valid_attempts.clear()

    def set_targets(self, targets: dict[int, str], *, observer_id: str | None = None) -> None:
        with self._condition:
            if observer_id is not None and observer_id != self._observer_id:
                self._observer_id = observer_id
                self._targets.clear()
            now = time.monotonic()
            updated = {}
            for target_id, ip in targets.items():
                target = self._targets.get(target_id)
                if target is None or target.ip != ip:
                    digest = hashlib.blake2s(f"{self._observer_id}:{target_id}".encode(), digest_size=4).digest()
                    phase = int.from_bytes(digest, "big") * PROBE_INTERVAL / (1 << 32)
                    target = _Target(ip, now + (phase - now) % PROBE_INTERVAL)
                updated[target_id] = target
            self._targets = updated
            self._condition.notify_all()

    def results(self) -> dict[int, tuple[ProbeStatus, float | None, int]]:
        with self._condition:
            now = time.monotonic()
            latest = {}
            for target_id, target in self._targets.items():
                if target.measurement is None:
                    continue
                status, rtt, checked_at = target.measurement
                age = now - checked_at
                if age < FRESH_SECONDS:
                    latest[target_id] = (status, rtt, int(age * 1000))
            return latest

    def packet_loss(self) -> dict[int, tuple[float, int]]:
        """Процент потерь и число попыток для целей со свежим валидным замером."""
        with self._condition:
            now = time.monotonic()
            loss = {}
            for target_id, target in self._targets.items():
                attempts = target.valid_attempts
                if attempts and now - attempts[-1][1] < FRESH_SECONDS:
                    samples = len(attempts)
                    loss[target_id] = (round(100 * sum(lost for lost, _ in attempts) / samples, 2), samples)
            return loss

    def _check(self, target_id: int, target: _Target) -> None:
        try:
            status, rtt = probe_ipv4(target.ip)
        except Exception:
            status, rtt = "error", None
        checked_at = time.monotonic()
        with self._condition:
            self._running.remove(target_id)
            if not self._stopping and self._targets.get(target_id) is target:
                target.measurement = (status, rtt, checked_at)
                if status in ("ok", "unreachable"):
                    target.valid_attempts.append((status == "unreachable", checked_at))
            self._condition.notify_all()

    def _loop(self) -> None:
        with ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="icmp") as executor:
            with self._condition:
                while not self._stopping:
                    candidates = (
                        (target_id, target) for target_id, target in self._targets.items()
                        if target_id not in self._running
                    )
                    next_target = min(candidates, key=lambda item: item[1].next_check, default=None)
                    if next_target is None or len(self._running) >= self._max_workers:
                        self._condition.wait()
                        continue

                    target_id, target = next_target
                    now = time.monotonic()
                    if target.next_check > now:
                        self._condition.wait(target.next_check - now)
                        continue

                    # Пропускаем просроченные интервалы, чтобы после задержки не отправлять серию запросов.
                    intervals = (now - target.next_check) // PROBE_INTERVAL + 1
                    target.next_check += intervals * PROBE_INTERVAL
                    self._running.add(target_id)
                    try:
                        executor.submit(self._check, target_id, target)
                    except RuntimeError:
                        self._running.remove(target_id)
                        return  # При завершении интерпретатора executor уже может быть закрыт.
