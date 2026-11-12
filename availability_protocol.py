"""Bounded, versioned availability data carried by the federation sync."""

import ipaddress
import math


MAX_TARGETS = 100
FRESH_MS = 30_000
MAX_INTEGER = (1 << 53) - 1
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def target_address(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid address")
    address = ipaddress.IPv4Address(value.strip())
    if not any(address in network and address not in (network.network_address, network.broadcast_address)
               for network in PRIVATE_NETWORKS):
        raise ValueError("address outside the private ranges")
    return str(address)


def target_id(value):
    if type(value) is not int or not 1 <= value <= MAX_INTEGER:
        raise ValueError("invalid target id")
    return value


def _revision(value, *, minimum):
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise ValueError("invalid target revision")
    return value


def read_config(value):
    if not isinstance(value, dict):
        raise ValueError("invalid target configuration")
    revision = _revision(value.get("revision"), minimum=0)
    if "targets" not in value:
        return revision, None
    rows = value["targets"]
    if not isinstance(rows, list) or len(rows) > MAX_TARGETS:
        raise ValueError("invalid target list")
    targets = {}
    for row in rows:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("invalid target")
        key, address = target_id(row[0]), target_address(row[1])
        if key in targets or address in targets.values():
            raise ValueError("duplicate target")
        targets[key] = address
    return revision, targets


def read_report(value):
    if not isinstance(value, dict):
        raise ValueError("invalid probe report")
    revision = _revision(value.get("revision"), minimum=-1)
    rows = value.get("results")
    if not isinstance(rows, list) or len(rows) > MAX_TARGETS:
        raise ValueError("invalid probe results")
    results = {}
    for row in rows:
        if not isinstance(row, list) or len(row) != 4:
            raise ValueError("invalid probe result")
        key, status, rtt_ms, age_ms = row
        key = target_id(key)
        if (key in results or status not in ("ok", "unreachable", "error")
                or type(age_ms) is not int or not 0 <= age_ms < FRESH_MS):
            raise ValueError("invalid probe result")
        if status == "ok":
            if type(rtt_ms) not in (int, float) or not 0 <= rtt_ms <= 10_000 or not math.isfinite(rtt_ms):
                raise ValueError("invalid RTT")
        elif rtt_ms is not None:
            raise ValueError("unexpected RTT")
        results[key] = (status, rtt_ms, age_ms)
    return revision, results
