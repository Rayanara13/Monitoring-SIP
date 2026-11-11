"""Предложение и запрос установки переживают потерю связи и перезапуск узла."""

from contextlib import closing
from copy import deepcopy
from types import SimpleNamespace
from urllib.error import URLError

import pytest

import federation_node as node


NODE_ID = "test-node"
CENTER_ID = "test-victoria"
PRIMARY = "https://victoria.example.invalid"
OFFER = {"package_id": "a" * 64, "version": "Rel 1.3.3", "platform": "linux", "arch": "x86_64"}
REPLACEMENT = {**OFFER, "package_id": "b" * 64, "version": "Rel 1.3.4"}


@pytest.fixture
def federation(tmp_path, monkeypatch):
    database = tmp_path / "node.db"
    with closing(node.connect(database)) as db, db:
        db.execute("""
            CREATE TABLE call_log (
                id INTEGER PRIMARY KEY, ts_start REAL, ts_end REAL, duration INTEGER,
                direction TEXT, local TEXT, remote TEXT, username TEXT
            )
        """)
        node.init_node_tables(db)

    monkeypatch.delenv("INEI_RUNNING_PACKAGE", raising=False)
    monkeypatch.setattr(node, "_local_target", lambda: ("linux", "x86_64"))
    center = SimpleNamespace(reply={}, outbound=[], offline=False, executed=[])

    def request(_sync, link, path, payload, *, authenticated=False):
        assert path == "/sync" and authenticated
        assert (link["url"], link["center_id"], payload["node_id"]) == (PRIMARY, CENTER_ID, NODE_ID)
        center.outbound.append(deepcopy(payload))
        if center.offline:
            raise URLError("Connection interrupted")
        return {
            "center_id": CENTER_ID,
            "history_ack": [entry["id"] for entry in payload["history"]],
            "result_ack": [entry["id"] for entry in payload["results"]],
            "commands": [],
            **center.reply,
        }

    def run_command(command, _link):
        center.executed.append(command["id"])
        return "applied", {}

    def restart():
        return node.NodeSync(database, "Rel 1.3.2", lambda: {"phones": []}, run_command)

    monkeypatch.setattr(node.NodeSync, "_request", request)
    sync = restart()
    sync._save_link({"url": PRIMARY, "node_id": NODE_ID, "center_id": CENTER_ID, "enrolled": True})
    return SimpleNamespace(sync=sync, restart=restart, center=center, database=database)


def test_offer_and_exact_request_nonce_survive_restart_and_offline_retries(federation):
    sync, center = federation.sync, federation.center
    with pytest.raises(node.FederationError):
        sync.request_update(OFFER["package_id"])
    center.reply = {"update_offer": {**OFFER, "private": "discard unrecognized metadata"}}
    assert sync.sync_once()
    assert center.outbound[-1]["target"] == {"platform": "linux", "arch": "x86_64"}
    assert center.outbound[-1]["installed_package"] is None
    assert center.outbound[-1]["update_request"] is None

    center.offline = True
    restarted = federation.restart()
    assert restarted.update_status() == {"offer": OFFER, "waiting": False, "last_status": None}
    for package_id in (REPLACEMENT["package_id"], "unverified"):
        with pytest.raises(node.FederationError):
            restarted.request_update(package_id)
    assert restarted.update_status()["waiting"] is False

    restarted.request_update(OFFER["package_id"])
    restarted.request_update(OFFER["package_id"])
    assert restarted.update_status()["waiting"] is True
    with pytest.raises(URLError):
        restarted.sync_once()
    pending = center.outbound[-1]["update_request"]
    assert set(pending) == {"id", "package_id"}
    assert node.valid(pending["id"], node.ID)
    assert pending["package_id"] == OFFER["package_id"]

    restarted = federation.restart()
    assert restarted.update_status() == {"offer": OFFER, "waiting": True, "last_status": None}
    restarted.request_update(OFFER["package_id"])
    with pytest.raises(URLError):
        restarted.sync_once()
    assert center.outbound[-1]["update_request"] == pending

    center.offline = False
    center.reply = {"update_offer": OFFER, "update_request_ack": pending["id"]}
    assert restarted.sync_once()
    assert center.outbound[-1]["update_request"] == pending
    assert restarted.update_status()["waiting"] is False
    center.reply = {"update_offer": OFFER}
    assert federation.restart().sync_once()
    assert center.outbound[-1]["update_request"] is None


def test_installed_package_suppresses_cached_offer_and_is_reported_on_reconnect(federation, monkeypatch):
    federation.center.reply = {"update_offer": OFFER}
    assert federation.sync.sync_once()
    assert federation.sync.update_status()["offer"] == OFFER
    monkeypatch.setenv("INEI_RUNNING_PACKAGE", OFFER["package_id"])
    restarted = federation.restart()
    assert restarted.update_status()["offer"] is None
    with pytest.raises(node.FederationError):
        restarted.request_update(OFFER["package_id"])

    federation.center.reply = {"update_offer": None}
    assert restarted.sync_once()
    sent = federation.center.outbound[-1]
    assert sent["installed_package"] == OFFER["package_id"]
    assert sent["update_request"] is None
    monkeypatch.delenv("INEI_RUNNING_PACKAGE")
    assert federation.restart().update_status()["offer"] is None


@pytest.mark.parametrize("new_offer", [None, REPLACEMENT])
def test_changed_or_withdrawn_offer_clears_the_pending_request(federation, new_offer):
    sync, center = federation.sync, federation.center
    center.reply = {"update_offer": OFFER}
    assert sync.sync_once()
    sync.request_update(OFFER["package_id"])
    center.reply = {"update_offer": new_offer}
    assert sync.sync_once()
    restarted = federation.restart()
    assert restarted.update_status() == {"offer": new_offer, "waiting": False, "last_status": None}
    with pytest.raises(node.FederationError):
        restarted.request_update(OFFER["package_id"])
    assert restarted.sync_once()
    assert center.outbound[-1]["update_request"] is None


@pytest.mark.parametrize("invalid", [
    {"update_offer": []},
    {"update_offer": {**OFFER, "package_id": "x" * 64}},
    {"update_offer": {**OFFER, "platform": "windows"}},
    {"update_offer": {**OFFER, "arch": "aarch64"}},
    {"update_offer": {**OFFER, "version": "v" * 65}},
    {"update_request_ack": "incorrect_nonce"},
    {"update_request_ack": {"id": "incorrect_type"}},
])
def test_invalid_offer_or_ack_leaves_history_and_durable_request_untouched(federation, invalid):
    sync, center = federation.sync, federation.center
    center.reply = {"update_offer": OFFER}
    assert sync.sync_once()
    sync.request_update(OFFER["package_id"])
    previous_sync = sync.status()["last_sync"]
    with closing(node.connect(federation.database)) as db, db:
        node.queue_call(db, 100, 104, 4, "0101", "Test", "0102", "out", "admin")

    center.reply = {"update_offer": OFFER, "commands": [
        {"id": "test-command", "action": "phone.add", "payload": {}},
    ], **invalid}
    with pytest.raises(node.FederationError):
        sync.sync_once()
    submitted = center.outbound[-1]
    restarted = federation.restart()
    assert restarted.update_status() == {"offer": OFFER, "waiting": True, "last_status": None}
    assert restarted.status()["last_sync"] == previous_sync
    assert restarted.status()["history_queued"] == 1
    assert center.executed == []

    center.reply = {"update_offer": OFFER, "update_request_ack": submitted["update_request"]["id"]}
    assert restarted.sync_once()
    assert center.outbound[-1]["update_request"] == submitted["update_request"]
    assert center.outbound[-1]["history"] == submitted["history"]
    assert restarted.status()["history_queued"] == 0
    assert restarted.update_status()["waiting"] is False
