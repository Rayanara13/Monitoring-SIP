"""Trust snapshots for the local inbound ICMP firewall."""

import hashlib
import ipaddress
import json
import logging
import os
import stat
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlsplit


MAX_TRUSTED_IPS = 1024
LOG = logging.getLogger(__name__)


def normalize_ip(value):
    if not isinstance(value, str) or len(value) > 64 or '%' in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified or address.is_multicast or str(address) == '255.255.255.255':
        return None
    return str(address)


def endpoint_ip(url):
    if not isinstance(url, str):
        return None
    try:
        return normalize_ip(urlsplit(url).hostname)
    except ValueError:
        return None


def trust_snapshot(addresses):
    canonical = set()
    for value in addresses:
        address = normalize_ip(value)
        if address is None:
            raise ValueError('Нужны отдельные доверенные IPv4 или IPv6 адреса.')
        canonical.add(address)
        if len(canonical) > MAX_TRUSTED_IPS:
            raise ValueError('Слишком много доверенных IP-адресов.')
    addresses = sorted(canonical)
    revision = hashlib.sha256(','.join(addresses).encode('ascii')).hexdigest()
    return {'revision': revision, 'addresses': addresses}


def read_trust_snapshot(value):
    if not isinstance(value, dict) or set(value) != {'revision', 'addresses'}:
        raise ValueError('Некорректный список доверенных IP.')
    addresses = value['addresses']
    if not isinstance(addresses, list) or len(addresses) > MAX_TRUSTED_IPS:
        raise ValueError('Некорректный список доверенных IP.')
    snapshot = trust_snapshot(addresses)
    if snapshot != value:
        raise ValueError('Некорректная версия списка доверенных IP.')
    return snapshot


class PingTrustFile:
    """Publish complete, bounded local data without running firewall commands."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def publish(self, addresses):
        policy = {'addresses': trust_snapshot(addresses)['addresses']}
        data = (json.dumps(policy, separators=(',', ':')) + '\n').encode('ascii')
        with self._lock:
            temporary = None
            try:
                try:
                    info = self.path.lstat()
                    if stat.S_ISREG(info.st_mode) and info.st_size == len(data):
                        with self.path.open('rb') as current:
                            if current.read(len(data) + 1) == data:
                                return True
                except FileNotFoundError:
                    pass
                with tempfile.NamedTemporaryFile(dir=self.path.parent, prefix='.ping-trust-', delete=False) as output:
                    temporary = Path(output.name)
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, self.path)
                return True
            except OSError as error:
                LOG.warning('Не удалось обновить файл доверенных IP: %s', error)
                return False
            finally:
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError as error:
                        LOG.warning('Не удалось удалить временный файл доверенных IP: %s', error)
