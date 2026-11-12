"""Read-only offline checks, with explicit TLS and isolated lab modes."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import http.client
import importlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


KIT = Path(__file__).resolve().parent
API_IDENTITY = "/api/federation/v1/identity"
VERSION_PATTERN = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")
CONFIG_KEYS = {
    "MONITORING_SIP_ROLE", "MONITORING_SIP_HOST", "MONITORING_SIP_PORT",
    "VICTORIA_ROLE_GRANT", "VICTORIA_TLS_CA", "VICTORIA_TLS_CERT", "VICTORIA_TLS_KEY",
    "VICTORIA_BEHIND_PROXY", "VICTORIA_EVENT_HOST", "VICTORIA_EVENT_PORT",
    "FEDERATION_MASTER_IP", "FEDERATION_MASTER_PORT", "FEDERATION_INVITATION",
    "FEDERATION_POLL_SECONDS", "FEDERATION_REPORT_IP",
}
LINK_STATE = {
    "unconfigured": ("WARN", "Узел ещё не подключён.", "Импортируйте приглашение на панели узла."),
    "unregistered": ("WARN", "Приглашение ещё не зарегистрировано.", "Проверьте связь с Викторией."),
    "registered": ("PASS", "В последнем снимке узел зарегистрирован.", "Сверьте время последней синхронизации."),
    "disconnected": ("WARN", "Последний обмен с Викторией не состоялся.", "Проверьте маршрут и HTTPS."),
    "invitation_expired": ("FAIL", "Виктория отклонила истёкшее приглашение.", "Выпустите новое приглашение."),
    "auth_failed": ("FAIL", "Виктория отклонила полномочия узла.", "Сверьте привязку в реестре Виктории."),
    "tls_failed": ("FAIL", "Последняя синхронизация завершилась ошибкой TLS.", "Проверьте часы и сертификат."),
    "report_only": ("PASS", "Узел работает в режиме одностороннего отчёта.", "Сверьте статус на Виктории."),
}
EVENT_ERRORS = {
    "invalid_token": "Сверьте токен в Action URL с карточкой телефона.",
    "missing_token": "Проверьте, что телефон получил полный Action URL.",
    "unknown_phone": "Сверьте номер и принадлежность карточки.",
    "invalid_event": "Сверьте событие с профилем телефона.",
    "rate_limited": "Проверьте частоту повторов событий.",
    "bad_request": "Проверьте профиль Action URL.",
    "rejected": "Сверьте очищенный журнал событий на панели.",
}


@dataclass(frozen=True)
class Check:
    status: str
    code: str
    observation: str
    next_step: str


class Report:
    def __init__(self):
        self.version = None
        self.role = None
        self.checks: list[Check] = []

    def add(self, status, code, observation, next_step):
        self.checks.append(Check(status, code, observation, next_step))

    def document(self):
        return {
            "schema": 1,
            "version": self.version,
            "role": self.role,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "checks": [asdict(check) for check in self.checks],
        }

    def text(self):
        lines = [f"Диагностика Инея {self.version or '—'} · роль {self.role or 'не определена'}"]
        for check in self.checks:
            lines.append(f"[{check.status}] {check.code} — {check.observation} {check.next_step}")
        return "\n".join(lines) + "\n"

    @property
    def failed(self):
        return any(check.status == "FAIL" for check in self.checks)


def limited_text(path, limit=65_536):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("not a bounded regular file")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("file exceeded limit")
    return content.decode("utf-8-sig")


def local_path(data, value):
    candidate = Path(value)
    return candidate if candidate.is_absolute() else data / candidate


def settings_from(data, config):
    values = {}
    paths = (data / ".env", config)
    for path in paths:
        if path is None or (path == paths[0] and not path.exists()):
            continue
        current = {}
        for line in limited_text(path).splitlines():
            name, separator, value = line.partition("=")
            if separator and name in CONFIG_KEYS:
                current.setdefault(name, value.strip())
        values.update(current)
    values.update({key: os.environ[key] for key in CONFIG_KEYS if key in os.environ})
    return values


def inspect_kit(kit, report):
    profile = None
    try:
        profile = limited_text(kit / "PROFILE.txt", 128).strip()
        stamp = limited_text(kit / "VERSION.txt", 1024)
        match = VERSION_PATTERN.search(stamp)
        if profile not in {"public_node", "internal_victoria"} or not match:
            raise ValueError("invalid package stamp")
        report.version = match.group()
        target = "Windows x64" if os.name == "nt" else (
            "Linux aarch64" if platform.machine().lower() in {"aarch64", "arm64"} else "Linux x86_64"
        )
        if target not in stamp and "Linux+Windows" not in stamp:
            report.add("FAIL", "KIT_WRONG_PLATFORM", "Комплект не соответствует платформе запуска.",
                       "Распакуйте архив для этой ОС и архитектуры.")
        else:
            report.add("PASS", "KIT_PLATFORM_OK", f"Комплект подходит для {target}.", "")
    except (OSError, ValueError):
        report.add("FAIL", "KIT_INCOMPLETE", "Отсутствует или повреждён паспорт офлайн-комплекта.",
                   "Распакуйте готовый архив целиком.")

    runtime = ("runtime/windows/python.exe" if os.name == "nt"
               else "runtime/linux/python/bin/python3.13")
    required = (runtime, "run.py", "app/server.py", "app/release_install.py")
    if not all((kit / name).is_file() for name in required):
        report.add("FAIL", "KIT_FILES_MISSING", "Отсутствует Python, лаунчер или файлы приложения.",
                   "Распакуйте готовый комплект в новый каталог.")
    else:
        report.add("PASS", "KIT_RUNTIME_OK", f"Python {sys.version_info.major}.{sys.version_info.minor} доступен.", "")

    sys.path[:0] = [str(kit / "app"), str(kit / "vendor")]
    for name, module in (
        ("flask", "flask"), ("flask_socketio", "flask_socketio"), ("werkzeug", "werkzeug"),
        ("cryptography", "cryptography.hazmat.primitives.asymmetric.ed25519"),
    ):
        try:
            if not (kit / "vendor" / name / "__init__.py").is_file():
                raise ImportError
            importlib.import_module(module)
        except Exception:
            report.add("FAIL", "KIT_DEPENDENCY_FAILED", f"Не загружается компонент {name}.",
                       "Сверьте платформу архива и комплектность распаковки.")
            break
    else:
        report.add("PASS", "KIT_DEPENDENCIES_OK", "Зависимости приложения загружаются.", "")
    return profile


def inspect_data(data, report):
    if not data.is_dir() or not os.access(data, os.R_OK | os.X_OK):
        report.add("FAIL", "DATA_DIR_UNREADABLE", "Каталог данных отсутствует или недоступен.",
                   "Укажите рабочий каталог через --data-dir и проверьте права.")
        return
    if not os.access(data, os.W_OK):
        report.add("WARN", "DATA_DIR_READ_ONLY", "Текущая учётная запись не имеет права записи.",
                   "Сверьте права именно для учётной записи службы.")
    else:
        report.add("PASS", "DATA_DIR_OK", "Каталог данных доступен текущей учётной записи.", "")
    try:
        free = shutil.disk_usage(data).free // (1024 * 1024)
        report.add("WARN" if free < 256 else "PASS", "DATA_DISK_SPACE", f"Свободно {free} МиБ.",
                   "Освободите место для истории и обновлений." if free < 256 else "")
    except OSError:
        report.add("SKIP", "DATA_DISK_UNKNOWN", "Не удалось определить свободное место.", "")
    db = data / "users_data" / "call_history.db"
    if not db.is_file():
        report.add("WARN", "DATABASE_NOT_FOUND", "База истории не найдена.", "Сверьте каталог данных и первый запуск.")
    elif not os.access(db, os.R_OK):
        report.add("FAIL", "DATABASE_UNREADABLE", "Нет права чтения файла базы.",
                   "Сверьте права на файл под учётной записью службы.")
    else:
        report.add("PASS", "DATABASE_FILE_OK", "Файл базы истории доступен.", "")


def inspect_role(profile, data, settings, report):
    grant_setting = settings.get("VICTORIA_ROLE_GRANT", "")
    grant = local_path(data, grant_setting or "victoria-role.json")
    if grant_setting or grant.is_file() or profile == "internal_victoria":
        cert = settings.get("VICTORIA_TLS_CERT")
        if not grant.is_file() or not cert:
            report.add("FAIL", "ROLE_GRANT_MISSING", "Назначение роли или сертификат Виктории не найдены.",
                       "Сверьте каталог данных и передайте файл окружения службы через --config.")
            return None
        try:
            from federation_identity import load_victoria_grant

            url = load_victoria_grant(grant, KIT / "app" / "victoria_role_authority.pem", local_path(data, cert))
        except (ImportError, OSError, ValueError, RuntimeError):
            report.add("FAIL", "ROLE_GRANT_INVALID", "Не подтверждены назначение и сертификат Виктории.",
                       "Проверьте внутренний комплект, назначение и соответствие сертификата.")
            return None
        report.role = "victoria"
        report.add("PASS", "ROLE_VICTORIA", "Подтверждено подписанное назначение Виктории.", "")
        return urlsplit(url)
    role = settings.get("MONITORING_SIP_ROLE", "node").strip().lower()
    if role not in {"node", "slave", "standalone"}:
        report.add("FAIL", "ROLE_INVALID", "Указана неподдерживаемая роль запуска.",
                   "Проверьте параметры установки.")
    else:
        report.role = "node" if role in {"node", "slave"} else "standalone"
        report.add("PASS", "ROLE_LOCAL", "Проверен профиль узла или автономного запуска.", "")
    return None


def run_readonly(command, timeout=1.5):
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.decode("utf-8", errors="replace") if len(result.stdout) <= 262_144 else None


def inspect_service(report):
    if os.name == "nt":
        report.add("SKIP", "SERVICE_WINDOWS_MANUAL", "Режим запуска службы Windows не определён.",
                   "Сверьте состояние панели или автозапуска в установщике.")
        return
    service = "inei-victoria.service" if report.role == "victoria" else "monitoring-sip.service"
    result = run_readonly(["systemctl", "show", "--no-pager", "-p", "LoadState", "-p", "ActiveState", service])
    if not result or "LoadState=not-found" in result:
        report.add("SKIP", "SERVICE_NOT_DISCOVERED", "Стандартная служба не найдена.",
                   "Если запуск выполнен вручную, ориентируйтесь на проверку панели.")
    elif "ActiveState=active\n" in result:
        report.add("PASS", "SERVICE_ACTIVE", "Служба Инея активна.", "")
    else:
        report.add("WARN", "SERVICE_STOPPED", "Служба Инея сейчас не активна.",
                   "Проверьте её состояние и причину остановки локально.")


def inspect_linux_network(expected_ip, report):
    raw = run_readonly(["ip", "-j", "address", "show"])
    if raw is None:
        report.add("SKIP", "NETWORK_UNKNOWN", "Состояние интерфейсов недоступно.", "Сверьте сетевой профиль локально.")
        return
    try:
        interfaces = [item for item in json.loads(raw) if "LOOPBACK" not in item.get("flags", [])]
        active = [item for item in interfaces if "LOWER_UP" in item.get("flags", [])]
        matched = [addr for item in active for addr in item.get("addr_info", [])
                   if addr.get("local") == expected_ip]
    except (ValueError, TypeError, AttributeError):
        report.add("SKIP", "NETWORK_UNKNOWN", "Не удалось прочитать список интерфейсов.", "")
        return
    if not active:
        report.add("WARN", "NETWORK_LINK_DOWN", "Сетевые интерфейсы без активного линка.",
                   "Проверьте кабель и порт коммутатора.")
    elif expected_ip and not matched:
        report.add("FAIL", "LINK_WITHOUT_STATIC_IP", "Линк активен, ожидаемого адреса на активных интерфейсах нет.",
                   "Сверьте Ethernet-порт, статический профиль и DHCP.")
    else:
        report.add("PASS", "NETWORK_LINK_OK", "Обнаружен активный линк.", "")
        if matched and all(addr.get("dynamic") is True for addr in matched):
            report.add("WARN", "NETWORK_DYNAMIC_ADDRESS", "Ожидаемый адрес помечен как динамический.",
                       "Сверьте настройки статического профиля.")
    routes = run_readonly(["ip", "-j", "route", "show"])
    if routes is None:
        report.add("SKIP", "NETWORK_ROUTE_UNKNOWN", "Таблица маршрутов недоступна.", "")
    else:
        report.add("PASS" if routes.strip() != "[]" else "WARN", "NETWORK_ROUTE",
                   "Маршруты присутствуют." if routes.strip() != "[]" else "Маршруты не найдены.",
                   "Сверьте маршрут до Виктории на площадке.")


def inspect_windows_network(expected_ip, report):
    program = (
        "$ErrorActionPreference='Stop'; "
        "$adapters=@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | "
        "Where-Object {$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}); "
        "$properties=@($adapters | ForEach-Object {$_.GetIPProperties()}); "
        "$addresses=@($properties | ForEach-Object {$_.UnicastAddresses} | "
        "ForEach-Object {$_.Address.ToString()}); "
        "$gateways=@($properties | ForEach-Object {$_.GatewayAddresses}); "
        "@{link=($adapters.Count -gt 0); addresses=$addresses; "
        "route=($gateways.Count -gt 0)} | ConvertTo-Json -Compress"
    )
    raw = run_readonly(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program], timeout=3)
    try:
        data = json.loads(raw or "null")
        if (not isinstance(data, dict) or type(data.get("link")) is not bool
                or type(data.get("route")) is not bool or not isinstance(data.get("addresses"), list)):
            raise ValueError
    except ValueError:
        report.add("SKIP", "NETWORK_UNKNOWN", "Сведения об интерфейсах Windows недоступны.", "")
        return
    if not data["link"]:
        report.add("WARN", "NETWORK_LINK_DOWN", "Сетевые интерфейсы без активного линка.",
                   "Проверьте кабель и сетевой адаптер.")
    elif expected_ip and expected_ip not in data["addresses"]:
        report.add("FAIL", "LINK_WITHOUT_STATIC_IP", "Линк активен, ожидаемого адреса на активных интерфейсах нет.",
                   "Сверьте адрес и настройки адаптера.")
    else:
        report.add("PASS", "NETWORK_LINK_OK", "Обнаружен активный сетевой интерфейс.", "")
    report.add("PASS" if data["route"] else "WARN", "NETWORK_ROUTE",
               "Настроен сетевой шлюз." if data["route"] else "Сетевой шлюз не обнаружен.",
               "Если Виктория в другой сети, проверьте маршрут до неё.")


def inspect_firewall(data, report):
    snapshot = data / "ping-trust.json"
    try:
        policy = json.loads(limited_text(snapshot))
        from ping_trust import trust_snapshot

        if (not isinstance(policy, dict) or set(policy) != {"addresses"} or
                not isinstance(policy["addresses"], list) or len(policy["addresses"]) > 1024):
            raise ValueError
        trust_snapshot(policy["addresses"])
    except FileNotFoundError:
        report.add("SKIP", "ICMP_SNAPSHOT_MISSING", "Снимок доверенных адресов отсутствует.",
                   "Сверьте регистрацию узла и настройку помощника ICMP.")
    except (OSError, ValueError, ImportError):
        report.add("WARN", "ICMP_SNAPSHOT_INVALID", "Не удалось подтвердить список доверенных адресов.",
                   "Проверьте обмен с Викторией и права на снимок.")
    else:
        report.add("PASS", "ICMP_SNAPSHOT_OK", "Список доверенных адресов читается.", "")
    if os.name == "nt":
        program = (
            "$ErrorActionPreference='Stop'; $env:PSModulePath=Join-Path $PSHOME 'Modules'; "
            "$task=Get-ScheduledTask -TaskPath '\\' -TaskName 'Inei Ping Firewall'; "
            "$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore | "
            "Where-Object {$_.Name -like 'Inei.PingFirewall.*' -and $_.Enabled -eq 'True'}); "
            "if ($task.State -ne 'Disabled' -and $rules.Count -gt 0) { Write-Output 'active' }"
        )
        result = run_readonly(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program], timeout=2)
    else:
        result = run_readonly(["systemctl", "is-active", "inei-ping-firewall.timer"])
    if (result or "").strip() == "active":
        report.add("PASS", "ICMP_HELPER_ACTIVE", "Помощник обновления правил активен.", "")
    else:
        report.add("SKIP", "ICMP_HELPER_UNKNOWN", "Активность помощника правил не подтверждена.",
                   "Проверьте задачу или таймер с правами администратора.")


def worker(mode, payload, timeout):
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8", str(Path(__file__).resolve()), "--_worker", mode],
            input=json.dumps(payload), text=True, encoding="utf-8", capture_output=True, timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else "error"
    except (OSError, subprocess.TimeoutExpired):
        return "timeout"


def request_worker(config):
    host = config["connect"]
    port = config["port"]
    address = ipaddress.ip_address(host)
    path = config["path"]
    if (type(port) is not int or not 1 <= port <= 65535 or "%" in str(address)
            or path not in {"/login", API_IDENTITY}
            or (path == "/login" and not address.is_loopback)
            or (path == API_IDENTITY and (
                not address.is_private or address.is_unspecified or address.is_multicast
                or config.get("server_name") != host or not config.get("identity") or not config.get("ca")
            ))):
        return "error"
    try:
        connection = socket.create_connection((host, port), timeout=1.3)
    except OSError:
        return "tcp"
    try:
        if config.get("ca"):
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_verify_locations(cadata=config["ca"])
            connection = tls.wrap_socket(connection, server_hostname=config["server_name"])
        with connection:
            authority = f"[{host}]" if ":" in host else host
            connection.sendall(
                f"GET {config['path']} HTTP/1.1\r\nHost: {authority}:{port}\r\n"
                "Connection: close\r\nAccept: */*\r\n\r\n".encode("ascii")
            )
            with http.client.HTTPResponse(connection) as response:
                response.begin()
                if config.get("identity"):
                    if response.status != 200:
                        return "http"
                    body = response.read(4097)
                    if len(body) > 4096:
                        return "http"
                    identity = json.loads(body)
                    return "ok" if identity == {"center_id": config["identity"]} else "identity"
                if response.status == 403 and config.get("proxy"):
                    return "proxy"
                if response.status != 200:
                    return "http"
                return "ok" if b'id="login-form"' in response.read(131_072) else "http"
    except ssl.SSLError:
        return "tls"
    except (OSError, ValueError, http.client.HTTPException):
        return "http"
    finally:
        connection.close()


def loopback_for(address):
    if address == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if ip.is_unspecified:
        return "127.0.0.1" if ip.version == 4 else "::1"
    return str(ip) if ip.is_loopback else None


def listeners(settings, endpoint, role):
    proxy = role == "victoria" and settings.get("VICTORIA_BEHIND_PROXY") == "1"
    bind = settings.get("MONITORING_SIP_HOST", "127.0.0.1" if proxy else (
        endpoint.hostname if endpoint else "0.0.0.0"))
    port = int(settings.get("MONITORING_SIP_PORT", (endpoint.port or 443) if endpoint and not proxy else 8000))
    phone = int(settings.get("VICTORIA_EVENT_PORT", 0 if proxy else 8000)) if role == "victoria" else 0
    phone_bind = settings.get("VICTORIA_EVENT_HOST", (
        "::" if endpoint and ":" in endpoint.hostname else "0.0.0.0") if proxy else bind)
    if not 1 <= port <= 65535 or not 0 <= phone <= 65535:
        raise ValueError("invalid port")
    return bind, port, phone_bind, phone, proxy


def local_listener_table():
    if os.name == "nt":
        program = (
            "$rows=@([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | "
            "ForEach-Object {$_.ToString()}); ConvertTo-Json -InputObject $rows -Compress"
        )
        raw = run_readonly(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program])
        try:
            rows = json.loads(raw or "null")
            if not isinstance(rows, list):
                return None
        except ValueError:
            return None
    else:
        raw = run_readonly(["ss", "-H", "-ltn"])
        if raw is None:
            return None
        rows = [columns[3] for line in raw.splitlines() if len(columns := line.split()) >= 5]
    result = set()
    for row in rows:
        if not isinstance(row, str):
            continue
        host, _, port = row.rpartition(":")
        try:
            host = host.strip("[]").partition("%")[0]
            result.add((str(ipaddress.ip_address(host)) if host != "*" else host, int(port)))
        except ValueError:
            continue
    return result


def inspect_bound_port(table, bind, port, report, *, phone=False):
    subject, code = ("HTTP-порт телефонов", "PHONE_HTTP") if phone else ("Порт панели", "LOCAL_UI")
    try:
        address = ipaddress.ip_address(bind)
    except ValueError:
        address = None
    if table is None or address is None:
        report.add("SKIP", code + "_NON_LOOPBACK", f"{subject} привязан к сетевому интерфейсу.",
                   "Проверьте доступ с разрешённого компьютера.")
        return
    candidates = {str(address), "*", "0.0.0.0" if address.version == 4 else "::"}
    if any((candidate, port) in table for candidate in candidates):
        report.add("PASS", code + "_BOUND", f"{subject} есть в локальной таблице слушателей.",
                   "Проверьте фактический ответ из разрешённой сети.")
    else:
        report.add("FAIL", code + "_DOWN", f"{subject} не слушает на настроенном интерфейсе.",
                   "Сверьте адрес, порт и состояние службы.")


def inspect_listeners(data, settings, endpoint, report):
    if report.role is None:
        return
    try:
        bind, port, phone_bind, phone, proxy = listeners(settings, endpoint, report.role)
    except ValueError:
        report.add("FAIL", "PORT_CONFIG_INVALID", "В параметрах запуска указан неверный порт.",
                   "Сверьте порт панели и порт телефонов.")
        return
    if phone and phone == port and (
        bind == phone_bind or bind in {"0.0.0.0", "::"} or phone_bind in {"0.0.0.0", "::"}
    ):
        report.add("FAIL", "PORT_CONFIG_CONFLICT", "Панель и HTTP-приём телефонов настроены на один порт.",
                   "Укажите разные порты для этих слушателей.")
    loopback = loopback_for(bind)
    phone_loopback = loopback_for(phone_bind) if phone else None
    table = local_listener_table() if loopback is None or (phone and phone_loopback is None) else None
    if loopback is None:
        inspect_bound_port(table, bind, port, report)
    else:
        payload = {"connect": loopback, "port": port, "path": "/login", "proxy": proxy}
        try:
            if endpoint and not proxy:
                payload.update(ca=limited_text(local_path(data, settings.get("VICTORIA_TLS_CA", ""))),
                               server_name=endpoint.hostname)
            result = worker("request", payload, timeout=2.5)
        except (OSError, ValueError):
            result = "tls"
        if result == "ok":
            report.add("PASS", "LOCAL_UI_OK", "Локальная страница входа Инея отвечает.", "")
        elif result == "proxy":
            report.add("WARN", "LOCAL_UI_PROXY", "Локальный слушатель отвечает с ограничением HTTPS.",
                       "Проверьте внешний HTTPS-прокси с разрешённого компьютера.")
        elif result == "tls":
            report.add("FAIL", "LOCAL_UI_TLS_FAILED", "Локальный сертификат панели не подтверждён.",
                       "Сверьте цепочку доверия, срок и системные часы.")
        elif result == "http":
            report.add("FAIL", "LOCAL_UI_UNEXPECTED", "На порту не подтверждена страница входа Инея.",
                       "Сверьте порт, службу и возможный конфликт с другим приложением.")
        else:
            report.add("FAIL", "LOCAL_UI_DOWN", "Локальная панель не отвечает.",
                       "Сверьте службу и порт прослушивания.")
    if not phone:
        return
    if phone_loopback is None:
        inspect_bound_port(table, phone_bind, phone, report, phone=True)
        return
    try:
        with socket.create_connection((phone_loopback, phone), timeout=0.8):
            report.add("PASS", "PHONE_HTTP_TCP_OK", "Локальный TCP-порт телефонов доступен.",
                       "Фактическую доставку смотрите в последнем событии.")
    except OSError:
        report.add("FAIL", "PHONE_HTTP_DOWN", "Локальный TCP-порт HTTP-приёма телефонов недоступен.",
                   "Сверьте порт Action URL и прослушивание на Виктории.")


def timestamp(value):
    if type(value) not in (int, float) or not 0 < value <= time.time() + 60:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def inspect_snapshot(data, settings, report):
    try:
        snapshot = json.loads(limited_text(data / "users_data" / "diagnostic-status.json"))
        if (not isinstance(snapshot, dict) or type(snapshot.get("schema")) is not int
                or snapshot["schema"] != 1 or not timestamp(snapshot.get("updated_at"))):
            raise ValueError
    except (OSError, ValueError):
        report.add("SKIP", "APP_SNAPSHOT_MISSING", "Свежесть событий и синхронизации не подтверждена снимком.",
                   "Проверьте журнал на панели после запуска службы.")
        return
    version = snapshot.get("version")
    if isinstance(version, str) and re.fullmatch(r"Rel \d+\.\d+(?:\.\d+)?", version):
        report.add("PASS", "APP_VERSION_REPORTED", f"Последний снимок создан приложением {version}.", "")
    if time.time() - snapshot["updated_at"] > 45:
        report.add("WARN", "APP_SNAPSHOT_STALE", "Снимок состояния давно не обновлялся.",
                   "Сверьте состояние службы.")
    last_event = timestamp(snapshot.get("last_event_at"))
    if last_event:
        report.add("PASS", "PHONE_LAST_EVENT", f"Последнее подтверждённое событие {last_event}.", "")
    else:
        report.add("SKIP", "PHONE_EVENT_UNKNOWN", "В снимке нет подтверждённого события телефона.", "")
    error = snapshot.get("event_error")
    if isinstance(error, str) and error in EVENT_ERRORS:
        report.add("WARN", "PHONE_EVENT_" + error.upper(), "Последний отказ приёма события.", EVENT_ERRORS[error])
    if snapshot.get("logging_ok") is False:
        report.add("WARN", "APP_LOG_WRITE_FAILED", "В снимке отмечена ошибка записи технического журнала.",
                   "Сверьте права на каталог и свободное место.")
    state = snapshot.get("link_state")
    if isinstance(state, str) and state in LINK_STATE:
        status, observation, step = LINK_STATE[state]
        report.add(status, "NODE_" + state.upper(), observation, step)
    last_sync = timestamp(snapshot.get("last_sync"))
    if last_sync:
        try:
            interval = max(1, min(int(settings.get("FEDERATION_POLL_SECONDS", "5")), 30))
        except ValueError:
            interval = 5
        recent = time.time() - snapshot["last_sync"] <= max(30, interval * 3)
        report.add("PASS" if recent else "WARN", "NODE_LAST_SYNC",
                   f"Последняя успешная синхронизация {last_sync}.",
                   "Проверьте связь с Викторией, замер устарел." if not recent else "")
    return snapshot


def probe_settings(data, settings):
    try:
        link_path = data / "users_data" / "diagnostic-link.json"
        stored = link_path.exists()
        if not stored:
            if not settings.get("FEDERATION_INVITATION"):
                return None
            link_path = local_path(data, settings["FEDERATION_INVITATION"])
        link = json.loads(limited_text(link_path, limit=131_072))
        if not isinstance(link, dict) or (stored and link.get("schema") != 1):
            return None
        endpoint = urlsplit(link["url"])
        ip = ipaddress.ip_address(endpoint.hostname)
        port = endpoint.port or 443
        if (endpoint.scheme != "https" or endpoint.username is not None or endpoint.password is not None
                or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment or "%" in str(ip)
                or not ip.is_private or ip.is_unspecified or ip.is_multicast or not 1 <= port <= 65535):
            return None
        if not stored and settings.get("FEDERATION_MASTER_IP") and (
            ip != ipaddress.ip_address(settings["FEDERATION_MASTER_IP"]) or
            port != int(settings.get("FEDERATION_MASTER_PORT", "443"))
        ):
            return None
        identity, ca = link["center_id"], link["tls_ca"]
        if (not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", identity)
                or not isinstance(ca, str) or not 1 <= len(ca) <= 65_536):
            return None
        return {"connect": str(ip), "server_name": str(ip), "port": port, "ca": ca,
                "identity": identity, "path": API_IDENTITY}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def probe_victoria(data, settings, snapshot, report):
    if report.role != "node" or settings.get("FEDERATION_REPORT_IP") or (
        snapshot and snapshot.get("link_state") == "report_only"
    ) or (KIT / "app" / "report-target.json").exists():
        report.add("SKIP", "VICTORIA_PROBE_UNAVAILABLE", "Проверка TLS доступна узлу с доверенной привязкой.",
                   "Сверьте режим подключения.")
        return
    payload = probe_settings(data, settings)
    if payload is None:
        report.add("SKIP", "VICTORIA_TRUST_MISSING", "Нет подтверждённого адреса и доверия для HTTPS-пробы.",
                   "Настройте доверенную привязку узла.")
        return
    result = worker("request", payload, timeout=3.5)
    messages = {
        "ok": ("PASS", "VICTORIA_IDENTITY_OK", "HTTPS и идентификатор Виктории подтверждены.", ""),
        "tcp": ("FAIL", "VICTORIA_TCP_DOWN", "TCP-подключение к Виктории не установлено.", "Сверьте маршрут и порт."),
        "tls": ("FAIL", "VICTORIA_TLS_UNTRUSTED", "TLS-сертификат Виктории не подтверждён.", "Сверьте доверие и часы."),
        "identity": ("FAIL", "VICTORIA_IDENTITY_MISMATCH", "Виктория вернула другой идентификатор.",
                     "Сверьте реестр и файл подключения."),
    }
    report.add(*messages.get(result, (
        "FAIL", "VICTORIA_RESPONSE_UNAVAILABLE", "Ответ Виктории не получен или неверен.",
        "Сверьте состояние HTTPS и протокола федерации.",
    )))


def lab_worker(workspace):
    sys.path[:0] = [str(KIT / "app"), str(KIT / "vendor")]
    from simulator.app import QuietRequests, create_lab
    from werkzeug.serving import make_server
    import logging

    logging.getLogger("werkzeug").addFilter(QuietRequests())
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    class LoopbackSocket(socket.socket):
        def connect(self, address):
            if self.family in (socket.AF_INET, socket.AF_INET6) and not ipaddress.ip_address(address[0]).is_loopback:
                raise OSError("Only loopback is allowed in the lab")
            return super().connect(address)

    normal_socket = socket.socket
    socket.socket = LoopbackSocket
    with tempfile.TemporaryDirectory(prefix="phones-", dir=workspace) as folder:
        previous = Path.cwd()
        try:
            with make_server("127.0.0.1", 0, None, threaded=True) as listener:
                port = listener.server_port
                server, lab, _, send_event = create_lab(Path(folder), port)
                listener.app = server.app
                thread = threading.Thread(target=listener.serve_forever, daemon=True)
                thread.start()
                try:
                    check_lab(lab, send_event, port)
                finally:
                    listener.shutdown()
                    thread.join(timeout=1)
        finally:
            logging.shutdown()
            os.chdir(previous)
            socket.socket = normal_socket


def check_lab(lab, send_event, port):
    phones = lab.state()["phones"]
    if {phone["number"] for phone in phones if phone["registered"]} != {"101", "102", "103"}:
        raise RuntimeError("lab registration")
    for phone in phones:
        for event in ("setup_completed", "registered", "busy_to_idle"):
            send_event(phone, event)

    def request(path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request("GET" if body is None else "POST", path,
                               None if body is None else json.dumps(body),
                               {"Content-Type": "application/json"})
            with connection.getresponse() as response:
                if response.status != 200:
                    raise RuntimeError("lab response")
                return json.load(response)
        finally:
            connection.close()

    def action(number, command, **kwargs):
        return request("/lab/api/action", {"phone": number, "action": command, **kwargs})

    if request("/lab/api/state")["monitor"]["count"] < 9:
        raise RuntimeError("lab events not delivered")
    call = action("101", "call", value="102")
    if not any(phone["number"] == "102" and phone["state"] == "ringing" for phone in call["phones"]):
        raise RuntimeError("lab ringing")
    action("102", "speaker")
    monitoring = {phone["number"]: phone["state"] for phone in request("/phones")["phones"]}
    if monitoring.get("101") != "Разговор" or monitoring.get("102") != "Разговор":
        raise RuntimeError("lab call not monitored")
    time.sleep(3.1)
    idle = action("101", "hangup")
    if any(phone["state"] != "idle" for phone in idle["phones"]):
        raise RuntimeError("lab hangup")
    pairs = {(row["local"], row["remote"]) for row in request("/history")["records"]}
    if not {("101", "102"), ("102", "101")} <= pairs:
        raise RuntimeError("lab history")


def save_report(base, report):
    files = ((Path(str(base) + ".txt"), report.text()),
             (Path(str(base) + ".json"), json.dumps(report.document(), ensure_ascii=False, indent=2) + "\n"))
    created = []
    try:
        for path, text in files:
            with path.open("x", encoding="utf-8") as stream:
                created.append(path)
                stream.write(text)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Офлайн-диагностика Инея")
    parser.add_argument("--data-dir", type=Path, default=KIT / "app")
    parser.add_argument("--config", type=Path, help="Файл окружения службы, только чтение")
    parser.add_argument("--report", type=Path, help="Путь и имя новых файлов TXT и JSON без расширения")
    parser.add_argument("--probe-victoria", action="store_true", help="Проверить настроенную Викторию по HTTPS")
    parser.add_argument("--lab", action="store_true", help="Проверить три телефона на временном loopback-стенде")
    parser.add_argument("--_worker", choices=("request", "lab"), help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options._worker:
        try:
            payload = json.load(sys.stdin)
            if options._worker == "lab":
                lab_worker(payload["workspace"])
                print("ok")
            else:
                print(request_worker(payload))
            return 0
        except Exception:
            return 1
    if not options.data_dir.is_absolute() or (options.config and not options.config.is_absolute()):
        parser.error("--data-dir и --config требуют абсолютного пути")

    report = Report()
    profile = inspect_kit(KIT, report)
    inspect_data(options.data_dir, report)
    try:
        settings = settings_from(options.data_dir, options.config)
    except (OSError, ValueError):
        settings = None
        report.add("FAIL", "CONFIG_UNREADABLE", "Не удалось прочитать настройки запуска.",
                   "Сверьте путь и права на файл.")
    if settings is not None:
        endpoint = inspect_role(profile, options.data_dir, settings, report)
        inspect_service(report)
        expected = settings.get("MONITORING_SIP_HOST") or (endpoint.hostname if endpoint else None)
        if expected and loopback_for(expected):
            expected = None
        if os.name == "nt":
            inspect_windows_network(expected, report)
        else:
            inspect_linux_network(expected, report)
        inspect_listeners(options.data_dir, settings, endpoint, report)
        if report.role in {"node", "victoria"}:
            inspect_firewall(options.data_dir, report)
        snapshot = inspect_snapshot(options.data_dir, settings, report)
        if options.probe_victoria:
            probe_victoria(options.data_dir, settings, snapshot, report)
    if options.lab:
        with tempfile.TemporaryDirectory(prefix="inei-diagnostic-lab-") as workspace:
            lab_result = worker("lab", {"workspace": workspace}, timeout=12)
        if lab_result == "ok":
            report.add("PASS", "LAB_OK", "Три телефона зарегистрированы. Вызов, ответ и отбой записаны в историю.", "")
        else:
            report.add("FAIL", "LAB_FAILED", "Изолированная самопроверка не завершилась успешно.",
                       "Сверьте зависимости и запустите виртуальные телефоны отдельно.")
    print(report.text(), end="")
    if options.report:
        try:
            save_report(options.report, report)
        except OSError:
            print("Не удалось сохранить новый отчёт TXT и JSON.", file=sys.stderr)
            return 2
    return int(report.failed)


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
