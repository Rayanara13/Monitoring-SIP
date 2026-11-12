import subprocess
import threading
from ipaddress import IPv4Address
from types import SimpleNamespace

import availability_probe


def test_linux_probe_reports_actual_rtt_and_distinguishes_local_errors(monkeypatch):
    address = IPv4Address("10.1.2.3")

    def run_ping(args, **kwargs):
        assert args[args.index("-s") + 1] == "16"
        assert kwargs["env"]["LC_ALL"] == "C"
        return subprocess.CompletedProcess(args, 0, "24 bytes from 10.1.2.3: icmp_seq=1 ttl=64 time=1.267 ms", "")

    monkeypatch.setattr(availability_probe.subprocess, "run", run_ping)
    assert availability_probe._ping_linux(address) == ("ok", 1.267)

    for status, stderr, expected in (
        (1, "", "unreachable"),
        (2, "ping: connect: Network is unreachable", "unreachable"),
        (2, "ping: socket: Operation not permitted", "error"),
        (1, "ping: socket: Operation not permitted", "error"),
        (0, "", "error"),
    ):
        monkeypatch.setattr(availability_probe.subprocess, "run", lambda args, **kwargs: subprocess.CompletedProcess(
            args, status, "", stderr,
        ))
        assert availability_probe._ping_linux(address) == (expected, None)


def test_result_from_replaced_target_does_not_become_fresh(monkeypatch):
    first_started = threading.Event()
    first_release = threading.Event()
    second_started = threading.Event()
    second_release = threading.Event()
    monkeypatch.setattr(availability_probe, "PROBE_INTERVAL", 0.05)

    def check(ip):
        if ip == "10.1.2.3":
            first_started.set()
            first_release.wait(3)
            return "ok", 2.0
        second_started.set()
        second_release.wait(3)
        return "unreachable", None

    monkeypatch.setattr(availability_probe, "probe_ipv4", check)
    probe = availability_probe.AvailabilityProbe("node", max_workers=1)
    probe.set_targets({1: "10.1.2.3"})
    probe.start()
    try:
        assert first_started.wait(2)
        probe.set_targets({1: "10.1.2.4"})
        first_release.set()
        assert second_started.wait(2)
        assert probe.results() == {}
        assert probe.packet_loss() == {}
    finally:
        first_release.set()
        second_release.set()
        probe.stop()


def test_packet_loss_rolls_over_valid_attempts_and_ages_out(monkeypatch):
    now = 1000.0
    monkeypatch.setattr(availability_probe, "time", SimpleNamespace(monotonic=lambda: now))
    probe = availability_probe.AvailabilityProbe("victoria")
    targets = {1: "10.1.2.3"}
    probe.set_targets(targets)
    assert probe.packet_loss() == {}

    def complete(status):
        rtt = 1.0 if status == "ok" else None
        monkeypatch.setattr(availability_probe, "probe_ipv4", lambda _ip: (status, rtt))
        probe._running.add(1)
        probe._check(1, probe._targets[1])

    complete("error")
    assert probe.packet_loss() == {}
    complete("ok")
    assert probe.packet_loss() == {1: (0.0, 1)}

    for _ in range(3):
        complete("unreachable")
    for _ in range(6):
        complete("ok")
    assert probe.packet_loss() == {1: (30.0, 10)}

    now += 10
    complete("error")
    assert probe.packet_loss() == {1: (30.0, 10)}
    complete("ok")
    complete("ok")
    assert probe.packet_loss() == {1: (20.0, 10)}

    now += availability_probe.FRESH_SECONDS
    complete("error")
    assert probe.results()[1][0] == "error"
    assert probe.packet_loss() == {}

    complete("unreachable")
    probe.set_targets({})
    probe.set_targets(targets)
    assert probe.packet_loss() == {}
