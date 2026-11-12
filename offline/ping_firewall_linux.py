"""Применение локального списка источников ICMP в отдельной таблице nftables."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


STATE_DIR = Path("/etc/inei-ping-firewall")
HELPER = Path("/usr/local/lib/inei-ping-firewall/ping_firewall_linux.py")
UNITS_DIR = Path("/etc/systemd/system")
SERVICE = "inei-ping-firewall.service"
TIMER = "inei-ping-firewall.timer"
TABLE = "inei_ping"
MARKER = "inei-ping-v1:"
TRUST_FILE = "ping-trust.json"
MAX_BYTES = 64 * 1024
MAX_ADDRESSES = 1024
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": SAFE_PATH, "LC_ALL": "C"}


class FirewallError(Exception):
    pass


class TrustFileError(FirewallError):
    pass


def _run(*args, data=None, check=True):
    try:
        return subprocess.run(args, input=data, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=ENV,
                              timeout=20, check=check)
    except subprocess.CalledProcessError as error:
        raise FirewallError(f"Не удалось выполнить {args[0]}: {error.stderr.strip()}") from error
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FirewallError(f"Не удалось выполнить {args[0]}: {error}") from error


def _native_nft_only():
    active = _run("systemctl", "is-active", "--quiet", "firewalld.service", check=False).returncode == 0
    enabled = _run("systemctl", "is-enabled", "firewalld.service", check=False).stdout.strip()
    if active or enabled in {"enabled", "enabled-runtime"}:
        raise FirewallError("Обнаружен активный или включённый firewalld. Используйте правила firewalld.")
    if shutil.which("ufw", path=SAFE_PATH):
        state = _run("ufw", "status").stdout.splitlines()
        if not state or state[0] != "Status: inactive":
            raise FirewallError("Обнаружен активный UFW или его статус неизвестен. Используйте правила UFW.")
    if not shutil.which("nft", path=SAFE_PATH):
        raise FirewallError("Установите системный пакет nftables для вашей ОС.")


def _address(value):
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise ValueError
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError
    return address


def _read_addresses(path):
    try:
        # Даже если приложение заменило файл ссылкой или FIFO, root читает только обычный файл.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError
            data = source.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError
        document = json.loads(data)
        if not isinstance(document, dict) or set(document) != {"addresses"}:
            raise ValueError
        values = document["addresses"]
        if not isinstance(values, list) or len(values) > MAX_ADDRESSES:
            raise ValueError
        addresses = {_address(value) for value in values}
    except FileNotFoundError:
        raise
    except (OSError, ValueError, RecursionError) as error:
        raise TrustFileError(f"Не удалось прочитать корректный список из {path}.") from error
    return sorted(addresses, key=lambda address: (address.version, int(address)))


def _policy(addresses):
    digest = hashlib.sha256("\n".join(map(str, addresses)).encode("ascii")).hexdigest()
    marker = MARKER + digest
    lines = [f"add table inet {TABLE}", f"delete table inet {TABLE}", f"table inet {TABLE} {{",
             f'    comment "{marker}"']
    for version, address_type in ((4, "ipv4_addr"), (6, "ipv6_addr")):
        lines.extend([f"    set trusted{version} {{", f"        type {address_type}"])
        elements = ", ".join(str(address) for address in addresses if address.version == version)
        if elements:
            lines.append(f"        elements = {{ {elements} }}")
        lines.append("    }")
    lines.extend([
        "    chain input {",
        "        type filter hook input priority -10; policy accept;",
        '        iifname != "lo" ip saddr != @trusted4 icmp type echo-request counter drop',
        '        iifname != "lo" ip6 saddr != @trusted6 icmpv6 type echo-request counter drop',
        "    }",
        "}",
        "",
    ])
    return marker, "\n".join(lines)


def _current_marker():
    tables = json.loads(_run("nft", "-j", "list", "tables").stdout)["nftables"]
    if not any(item.get("table", {}).get("family") == "inet" and item["table"].get("name") == TABLE
               for item in tables):
        return None
    current = json.loads(_run("nft", "-j", "list", "table", "inet", TABLE).stdout)["nftables"]
    table = next(item["table"] for item in current if "table" in item)
    marker = table.get("comment", "")
    if not re.fullmatch(re.escape(MARKER) + r"[0-9a-f]{64}", marker):
        raise FirewallError(f"Таблица inet {TABLE} уже используется другой конфигурацией.")
    return marker


def _atomic_write(path, content, mode=0o600):
    fd, staging = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            os.fchmod(target.fileno(), mode)
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(staging, path)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)


def _require_owned_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise FirewallError(f"Каталог {path} должен принадлежать root и быть защищён от записи другими пользователями.")


@contextmanager
def _locked():
    _require_owned_directory(STATE_DIR)
    with (STATE_DIR / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def _apply(marker, rules, *, dry_run=False):
    current = _current_marker()
    if dry_run or marker != current:
        _run("nft", "-c", "-f", "-", data=rules)
    if dry_run:
        return
    if marker != current:
        _run("nft", "-f", "-", data=rules)
    snapshot = STATE_DIR / "rules.nft"
    if not snapshot.is_file() or snapshot.read_text(encoding="utf-8") != rules:
        _atomic_write(snapshot, rules)


def _refresh():
    _native_nft_only()
    with _locked():
        settings = json.loads((STATE_DIR / "settings.json").read_text(encoding="utf-8"))
        try:
            addresses = _read_addresses(settings["path"])
        except (TrustFileError, FileNotFoundError) as error:
            snapshot = (STATE_DIR / "rules.nft").read_text(encoding="utf-8")
            match = re.search(r'comment "(' + re.escape(MARKER) + r'[0-9a-f]{64})"', snapshot)
            if match is None:
                raise FirewallError("Не удалось восстановить последнее правило Инея.") from error
            _apply(match.group(1), snapshot)
            if isinstance(error, TrustFileError):
                raise
            return
        _apply(*_policy(addresses))


def _install_units():
    service = f"""[Unit]
Description=Inei inbound ICMP allowlist
After=local-fs.target nftables.service
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I {HELPER} --refresh
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={STATE_DIR}
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=network-pre.target
"""
    timer = f"""[Unit]
Description=Refresh the Inei inbound ICMP allowlist

[Timer]
OnBootSec=5s
OnUnitInactiveSec=10s
AccuracySec=1s
Unit={SERVICE}

[Install]
WantedBy=timers.target
"""
    HELPER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _require_owned_directory(HELPER.parent)
    _atomic_write(HELPER, Path(__file__).read_text(encoding="utf-8"), 0o644)
    _atomic_write(UNITS_DIR / SERVICE, service, 0o644)
    _atomic_write(UNITS_DIR / TIMER, timer, 0o644)
    _run("systemctl", "daemon-reload")
    _run("systemctl", "enable", SERVICE)
    _run("systemctl", "enable", "--now", TIMER)


@contextmanager
def _installation_rollback():
    units = [UNITS_DIR / name for name in (TIMER, SERVICE)]
    files = [*units, HELPER, STATE_DIR / "settings.json", STATE_DIR / "rules.nft"]
    previous = {path: (path.read_text(encoding="utf-8"), stat.S_IMODE(path.stat().st_mode))
                for path in files if path.is_file()}
    enabled = {path.name for path in units if path in previous and
               _run("systemctl", "is-enabled", path.name, check=False).stdout.strip() == "enabled"}
    timer_running = (units[0] in previous and
                     _run("systemctl", "is-active", "--quiet", TIMER, check=False).returncode == 0)
    prior_marker = _current_marker()
    prior_table = (_run("nft", "list", "table", "inet", TABLE).stdout if prior_marker else None)
    try:
        yield
    except BaseException as original:
        failures = []

        def restore(action):
            try:
                action()
            except (FirewallError, OSError, ValueError) as error:
                failures.append(str(error))

        def disable_new_unit(unit):
            if _run("systemctl", "is-enabled", unit, check=False).stdout.strip() == "enabled":
                _run("systemctl", "disable", unit)

        def restore_table():
            current = _current_marker()
            if current == prior_marker:
                return
            if prior_table is None:
                _run("nft", "delete", "table", "inet", TABLE)
            else:
                _run("nft", "-f", "-", data=f"add table inet {TABLE}\ndelete table inet {TABLE}\n{prior_table}")

        if not timer_running and units[0].is_file():
            restore(lambda: _run("systemctl", "stop", TIMER))
        for path in units:
            if path.is_file() and path.name not in enabled:
                restore(lambda: disable_new_unit(path.name))
        restore(restore_table)
        for path in files:
            if path in previous:
                restore(lambda: _atomic_write(path, *previous[path]))
            else:
                restore(lambda: path.unlink(missing_ok=True))
        restore(lambda: _run("systemctl", "daemon-reload"))
        if failures:
            raise FirewallError(f"{original}. Откат завершён с ошибками: {'; '.join(failures)}") from original
        raise


def _install(data_dir, master_ip, dry_run):
    _native_nft_only()
    directory = Path(data_dir).resolve(strict=True)
    if not directory.is_dir():
        raise FirewallError("Каталог данных Инея не найден.")
    if master_ip is not None:
        try:
            master_ip = _address(master_ip)
        except ValueError as error:
            raise FirewallError("--master-ip принимает один IP-адрес.") from error
    path = directory / TRUST_FILE
    try:
        addresses = _read_addresses(path)
    except FileNotFoundError as error:
        if master_ip is None:
            raise FirewallError(f"Файл {path} ещё не создан. Для первого запуска укажите --master-ip.") from error
        addresses = [master_ip]
    marker, rules = _policy(addresses)
    _apply(marker, rules, dry_run=True)
    if dry_run:
        print(f"Список проверен. Доверенных адресов: {len(addresses)}. Правила не изменены.")
        return

    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    with _locked(), _installation_rollback():
        _install_units()
        _atomic_write(STATE_DIR / "settings.json", json.dumps({"path": str(path)}))
        _apply(marker, rules)
    print(f"Ограничение входящего ICMP установлено. Доверенных адресов: {len(addresses)}.")


def _remove():
    if not STATE_DIR.is_dir():
        return
    with _locked():
        current = _current_marker()
        for unit in (TIMER, SERVICE):
            if (UNITS_DIR / unit).is_file():
                _run("systemctl", "disable", "--now", unit)
        if current is not None:
            _run("nft", "delete", "table", "inet", TABLE)
        for file in (UNITS_DIR / TIMER, UNITS_DIR / SERVICE, HELPER,
                     STATE_DIR / "settings.json", STATE_DIR / "rules.nft"):
            file.unlink(missing_ok=True)
        _run("systemctl", "daemon-reload")
    print("Ограничение входящего ICMP Инея удалено.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="проверить список и правила без применения")
    mode.add_argument("--remove", action="store_true", help="удалить ограничение Инея")
    mode.add_argument("--refresh", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--data-dir", help="каталог данных Инея с ping-trust.json")
    parser.add_argument("--master-ip", help="доверенный IP Виктории до появления ping-trust.json")
    args = parser.parse_args()
    if args.remove or args.refresh:
        if args.data_dir is not None or args.master_ip is not None:
            parser.error("--data-dir и --master-ip относятся к установке и проверке")
    elif args.data_dir is None:
        parser.error("требуется --data-dir")
    if os.geteuid() != 0:
        parser.error("требуются права root")

    try:
        if args.remove:
            _remove()
        elif args.refresh:
            _refresh()
        else:
            _install(args.data_dir, args.master_ip, args.check)
    except (FirewallError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
