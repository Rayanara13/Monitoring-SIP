"""Локальный журнал диагностики с фиксированной схемой для федерации."""

from contextlib import closing
import json
import re
import sqlite3
import time


MAX_ENTRIES = 2000
MAX_PAGE_SIZE = 100
_MAX_ID = 2**53 - 1
_MAX_TIMESTAMP = 253402300799
_PHONE_NUMBER = re.compile(r"\+?[0-9]{1,16}")

# Ключи из каталога Action URL и старый DND. Значения с телефона напрямую
# в журнал не попадают: поле должно совпасть с одним из известных ключей.
_SIP_EVENTS = frozenset("""
    setup_completed registered unregistered register_failed off_hook on_hook
    incoming_call outgoing_call call_established call_terminated dnd_on dnd_off DND
    always_fwd_on always_fwd_off busy_fwd_on busy_fwd_off no_answer_fwd_on no_answer_fwd_off
    transfer_call blind_transfer_call attended_transfer_call hold unhold mute unmute
    missed_call ip_change idle_to_busy busy_to_idle reject_incoming_call answer_new_incoming_call
    transfer_failed transfer_finished forward_incoming_call setup_autop_finish
    call_waiting_on call_waiting_off headset handfree cancel_callout remote_busy call_remote_canceled
    view_missed_call view_forwarded_call peripheral_information vpn_ip sip_info_display_update conference
""".split())
_ENUM_FIELDS = {
    "service_started": {},
    "service_exception": {},
    "sip_event": {"event": _SIP_EVENTS},
    "sip_rejected": {"reason": {"rate_limited", "bad_token", "unknown_phone", "unsupported_event"}},
    "phone_reachability": {"status": {"online", "offline"}},
    "auth_result": {"outcome": {"success", "failed", "blocked"}},
    "federation_status": {"outcome": {"connected", "disconnected"}},
    "admin_action": {"action": {"node.create", "node.invite", "node.revoke", "command.queue", "package.upload"}},
}


class JournalError(ValueError):
    """Ошибка журнала, безопасная для передачи серверу."""


def _integer_in_range(value, maximum, minimum=1):
    return type(value) is int and minimum <= value <= maximum


def _safe_fields(kind, fields):
    if not isinstance(kind, str) or kind not in _ENUM_FIELDS or not isinstance(fields, dict):
        raise JournalError("Неизвестный тип записи журнала.")
    safe = {}
    for field, choices in _ENUM_FIELDS[kind].items():
        value = fields.get(field)
        if not isinstance(value, str) or value not in choices:
            raise JournalError("Недопустимое поле записи журнала.")
        safe[field] = value
    if kind in {"sip_event", "phone_reachability"}:
        number = fields.get("phone_number")
        if isinstance(number, str) and _PHONE_NUMBER.fullmatch(number):
            safe["phone_number"] = number
        elif kind == "phone_reachability":
            raise JournalError("Недопустимый номер телефона в журнале.")
    return safe


def validate_journal_result(result):
    """Проверить схему ответа перед сохранением на сервере."""
    if not isinstance(result, dict) or set(result) != {"entries", "next_before"}:
        raise JournalError("Некорректный ответ журнала.")
    entries, cursor = result["entries"], result["next_before"]
    if not isinstance(entries, list) or len(entries) > MAX_PAGE_SIZE:
        raise JournalError("Недопустимый размер страницы журнала.")
    safe = []
    previous = _MAX_ID + 1
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "ts", "kind", "fields"}:
            raise JournalError("Некорректная запись журнала.")
        entry_id, ts, kind = entry["id"], entry["ts"], entry["kind"]
        if not _integer_in_range(entry_id, previous - 1) or not _integer_in_range(ts, _MAX_TIMESTAMP, 0):
            raise JournalError("Недопустимые идентификатор или время записи журнала.")
        fields = _safe_fields(kind, entry["fields"])
        if fields != entry["fields"]:
            raise JournalError("Недопустимые поля записи журнала.")
        safe.append({"id": entry_id, "ts": ts, "kind": kind, "fields": fields})
        previous = entry_id
    if cursor is not None and (not _integer_in_range(cursor, _MAX_ID) or not safe or cursor != previous):
        raise JournalError("Некорректный указатель страницы журнала.")
    return {"entries": safe, "next_before": cursor}


def validate_journal_request(payload):
    if not isinstance(payload, dict) or set(payload) - {"limit", "before"}:
        raise JournalError("Недопустимые параметры чтения журнала.")
    limit, before = payload.get("limit", MAX_PAGE_SIZE), payload.get("before")
    if not _integer_in_range(limit, MAX_PAGE_SIZE):
        raise JournalError("Допустимый размер страницы журнала от 1 до 100.")
    if before is not None and not _integer_in_range(before, _MAX_ID):
        raise JournalError("Недопустимый указатель страницы журнала.")
    return {"limit": limit, "before": before}


class FederationJournal:
    """Ограниченное число записей, с транзакцией для каждой вставки и очистки."""

    def __init__(self, db_file):
        self.db_file = db_file
        try:
            with closing(self._connect()) as db, db:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS federation_journal (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        kind TEXT NOT NULL,
                        fields TEXT NOT NULL
                    )
                """)
        except sqlite3.Error:
            raise JournalError("Локальное хранилище журнала недоступно.") from None

    def _connect(self):
        return sqlite3.connect(self.db_file, timeout=0.25)

    def record(self, kind, **fields):
        """Записать только разрешённые поля. Сбой не прерывает обработку события."""
        try:
            safe = _safe_fields(kind, fields)
            with closing(self._connect()) as db, db:
                insert = db.execute("INSERT INTO federation_journal(ts, kind, fields) VALUES (?, ?, ?)",
                                    (int(time.time()), kind, json.dumps(safe, separators=(",", ":"))))
                db.execute("DELETE FROM federation_journal WHERE id <= ?", (insert.lastrowid - MAX_ENTRIES,))
        except (JournalError, sqlite3.Error):
            return False
        return True

    def read(self, limit=MAX_PAGE_SIZE, before=None):
        """Страница от новых записей к старым. before — исключающая граница по ID."""
        validate_journal_request({"limit": limit, "before": before})
        try:
            with closing(self._connect()) as db:
                rows = db.execute("""
                    SELECT id, ts, kind, fields FROM federation_journal
                    WHERE id < ? ORDER BY id DESC LIMIT ?
                """, (_MAX_ID + 1 if before is None else before, limit + 1)).fetchall()
            entries = [{"id": entry_id, "ts": ts, "kind": kind, "fields": json.loads(fields)}
                       for entry_id, ts, kind, fields in rows[:limit]]
        except (sqlite3.Error, ValueError, RecursionError):
            raise JournalError("Не удалось прочитать локальный журнал.") from None
        return validate_journal_result({"entries": entries,
                                        "next_before": entries[-1]["id"] if len(rows) > limit else None})
