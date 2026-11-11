"""Границы хранения, пагинации и передачи структурированного журнала."""

import json
import sqlite3

import pytest

import federation_logs as logs


def test_journal_keeps_only_structured_fields_on_disk_and_in_result(tmp_path):
    path = tmp_path / "journal.db"
    journal = logs.FederationJournal(path)
    synthetic_secret = "synthetic_private_value"
    assert journal.record("service_started")
    assert journal.record("service_exception", exception=f"failure: {synthetic_secret}")
    assert journal.record("auth_result", outcome="success", username=synthetic_secret)
    assert journal.record("sip_rejected", reason="bad_token", token=synthetic_secret)
    assert journal.record("sip_event", event="incoming_call", phone_number="1001", query=synthetic_secret)
    assert journal.record("sip_event", event="registered", phone_number="sip:user@secret.invalid")
    assert journal.record("federation_status", outcome="disconnected", error=synthetic_secret)
    assert journal.record("admin_action", action="node.invite", token=synthetic_secret)
    assert journal.record("phone_reachability", phone_number="+1234", status="offline", raw_log=synthetic_secret)
    assert not journal.record("raw_log", line=synthetic_secret)
    assert not journal.record("sip_event", event=synthetic_secret)
    assert not journal.record("phone_reachability", phone_number=synthetic_secret, status="online")
    assert not journal.record("auth_result", outcome=synthetic_secret)
    assert not journal.record("admin_action", action="http://host/?token=" + synthetic_secret)

    result = logs.FederationJournal(path).read()
    assert [(row["kind"], row["fields"]) for row in result["entries"]] == [
        ("phone_reachability", {"phone_number": "+1234", "status": "offline"}),
        ("admin_action", {"action": "node.invite"}),
        ("federation_status", {"outcome": "disconnected"}),
        ("sip_event", {"event": "registered"}),
        ("sip_event", {"event": "incoming_call", "phone_number": "1001"}),
        ("sip_rejected", {"reason": "bad_token"}),
        ("auth_result", {"outcome": "success"}),
        ("service_exception", {}), ("service_started", {}),
    ]
    assert result["next_before"] is None
    assert synthetic_secret not in json.dumps(result)
    assert synthetic_secret.encode() not in path.read_bytes()


def test_retention_and_cursor_are_stable_across_new_entries_and_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(logs, "MAX_ENTRIES", 5)
    path = tmp_path / "journal.db"
    journal = logs.FederationJournal(path)
    for _ in range(9):
        assert journal.record("service_started")
    first = journal.read(limit=2)
    assert [item["id"] for item in first["entries"]] == [9, 8]
    assert first["next_before"] == 8
    journal = logs.FederationJournal(path)
    assert journal.record("service_exception")
    second = journal.read(limit=2, before=first["next_before"])
    assert [item["id"] for item in second["entries"]] == [7, 6]
    assert second["next_before"] is None
    assert [item["id"] for item in journal.read()["entries"]] == [10, 9, 8, 7, 6]
    assert journal.read(before=6) == {"entries": [], "next_before": None}


@pytest.mark.parametrize("payload", [
    {"limit": 0}, {"limit": True}, {"limit": 101}, {"limit": "5"}, {"before": -1},
    {"before": 2**53}, {"path": "app.log"}, {"command": "tail"}, None,
])
def test_journal_request_only_accepts_bounded_page_parameters(payload):
    with pytest.raises(logs.JournalError):
        logs.validate_journal_request(payload)


def test_maximum_page_fits_federation_result_budget(tmp_path):
    journal = logs.FederationJournal(tmp_path / "journal.db")
    for _ in range(101):
        assert journal.record("sip_event", event="sip_info_display_update", phone_number="+1234567890123456")
    result = journal.read()
    assert len(result["entries"]) == 100
    assert result["next_before"] == 2
    assert len(json.dumps(result).encode()) < 65_536
    assert logs.validate_journal_result(result) == result


@pytest.mark.parametrize("entry_update", [
    {"message": "free text"}, {"fields": {"event": "off_hook", "token": "private"}},
    {"fields": {"event": "off_hook", "phone_number": "sip:secrets@example.invalid"}},
    {"fields": {"event": {"raw": "value"}}}, {"kind": "raw_log"}, {"ts": float("inf")}, {"id": True},
])
def test_center_rejects_nonconforming_record_payload(entry_update):
    entry = {"id": 2, "ts": 10, "kind": "sip_event", "fields": {"event": "off_hook"}, **entry_update}
    with pytest.raises(logs.JournalError):
        logs.validate_journal_result({"entries": [entry], "next_before": None})


def test_invalid_cursor_and_repeated_identifiers_are_rejected():
    entry = {"id": 2, "ts": 10, "kind": "service_started", "fields": {}}
    with pytest.raises(logs.JournalError):
        logs.validate_journal_result({"entries": [entry], "next_before": 3})
    with pytest.raises(logs.JournalError):
        logs.validate_journal_result({"entries": [entry, entry], "next_before": None})


def test_database_failure_never_breaks_event_processing(tmp_path):
    path = tmp_path / "journal.db"
    journal = logs.FederationJournal(path)
    path.unlink()
    assert journal.record("service_started") is False
    with pytest.raises(logs.JournalError, match="прочитать"):
        journal.read()


def test_existing_unstructured_database_row_is_rejected(tmp_path):
    path = tmp_path / "journal.db"
    journal = logs.FederationJournal(path)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO federation_journal(ts, kind, fields) VALUES (10, 'service_started', ?)",
                   (json.dumps({"token": "synthetic_secret"}),))
    with pytest.raises(logs.JournalError, match="поля"):
        journal.read()
