"""Локальный журнал диагностики с фиксированной схемой для федерации."""

from contextlib import closing
import json
import os
import re
import sqlite3
import time


MAX_ENTRIES = 2000
MAX_PAGE_SIZE = 100
AUDIT_MAX_ENTRIES = 50_000
AUDIT_RETENTION_SECONDS = 30 * 86400
_AUDIT_DB_BYTES = 60 * 1024 * 1024
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
    "admin_action": {"action": {"node.create", "node.invite", "node.revoke", "command.queue", "package.upload",
                                "availability.add", "availability.edit", "availability.delete"}},
}

AUDIT_MAINTENANCE_ACTIONS = frozenset({"server.restart", "server.file.write", "server.file.delete"})
AUDIT_ACTIONS = AUDIT_MAINTENANCE_ACTIONS | frozenset({
    "node.create", "node.invite", "node.revoke", "node.enroll",
    "phone.add", "phone.update", "phone.delete", "phone.reorder",
    "endpoint.stage", "update.install", "yealink.inspect", "action_url.events",
    "set.toggle_shared", "set.import", "logs.read", "diagnostics.read",
    "package.upload", "release.upload", "release.apply", "release.pilot", "release.open",
    "availability.add", "availability.edit", "availability.delete", "monitoring.pin", "monitoring.unpin",
    "user.create", "user.password.reset", "user.password.change", "user.token.rotate", "user.disable",
})
AUDIT_OUTCOMES = frozenset({
    "queued", "applied", "failed", "rolled_back", "cancelled", "expired", "staged", "uncertain", "rejected",
})
AUDIT_CODES = frozenset({
    "restart_verified", "restart_failed", "file_change_rejected", "installation_rolled_back",
    "interrupted_rolled_back", "package_cannot_be_installed", "invalid_release", "invalid_package",
    "master_update_failed", "update_busy", "managed_update_unavailable", "maintenance_unavailable",
    "maintenance_status_missing", "previous_execution_unconfirmed", "local_executor_not_configured",
    "executor_start_failed", "executor_failed", "executor_timeout", "executor_result_not_recorded",
    "data_write_failed",
})
_AUDIT_ID = re.compile(r"[A-Za-z0-9_-]{1,96}")
_AUDIT_LOGIN = re.compile(r"[\w.@-]{1,80}")
_AUDIT_HASH = re.compile(r"[a-f0-9]{64}")
_AUDIT_PATH = re.compile(r"[\w][\w .-]*(?:/[\w][\w .-]*)*")
_AUDIT_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .+_-]{0,63}")
_AUDIT_TARGETS = {
    "node": _AUDIT_ID, "card": _AUDIT_ID, "availability": re.compile(r"[1-9][0-9]{0,15}"),
    "package": _AUDIT_HASH, "release": _AUDIT_HASH, "user": _AUDIT_LOGIN,
    "server": re.compile(r"victoria|local"), "file": _AUDIT_PATH,
}


def _matches(value, pattern, maximum=240):
    return isinstance(value, str) and len(value) <= maximum and pattern.fullmatch(value) is not None


def audit_outcome(status, code=None):
    if isinstance(code, str) and code in {"installation_rolled_back", "interrupted_rolled_back"}:
        return "rolled_back"
    if not isinstance(status, str):
        return None
    if status in {"applied", "success", "succeeded", "ok"}:
        return "applied"
    if status in {"failed", "error", "conflict"}:
        return "failed"
    return status if status in AUDIT_OUTCOMES - {"queued"} else None


class JournalError(ValueError):
    """Ошибка журнала, безопасная для передачи в Викторию."""


class AuditFilterError(JournalError):
    """Недопустимые параметры выборки аудита."""


def _integer_in_range(value, maximum, minimum=1):
    return type(value) is int and minimum <= value <= maximum


class AdminAudit:
    """Отдельный журнал изменений, который переживает перезапуск приложения."""

    def __init__(self, db_file):
        self.db_file = db_file
        try:
            try:
                os.close(os.open(db_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            except FileExistsError:
                pass
            with closing(self._connect()) as db, db:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS admin_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                        actor TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT NOT NULL, target TEXT NOT NULL,
                        outcome TEXT NOT NULL, job_id TEXT, code TEXT, from_version TEXT, to_version TEXT
                    )
                """)
                db.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS admin_audit_job_phase
                    ON admin_audit (job_id, (outcome = 'queued')) WHERE job_id IS NOT NULL
                """)
                db.execute("CREATE INDEX IF NOT EXISTS admin_audit_ts ON admin_audit (ts)")
                db.execute("DELETE FROM admin_audit WHERE ts < ?", (int(time.time()) - AUDIT_RETENTION_SECONDS,))
        except (OSError, sqlite3.Error):
            raise JournalError("Хранилище аудита недоступно.") from None

    def _connect(self):
        db = sqlite3.connect(self.db_file, timeout=0.25)
        try:
            db.row_factory = sqlite3.Row
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            db.execute(f"PRAGMA max_page_count = {_AUDIT_DB_BYTES // page_size}")
        except sqlite3.Error:
            db.close()
            raise
        return db

    def record(self, action, *, actor, target_type, target, outcome, job_id=None, code=None,
               from_version=None, to_version=None, when=None):
        pattern = _AUDIT_TARGETS.get(target_type) if isinstance(target_type, str) else None
        if (not isinstance(action, str) or action not in AUDIT_ACTIONS
                or not isinstance(outcome, str) or outcome not in AUDIT_OUTCOMES
                or not _matches(actor, _AUDIT_LOGIN) or pattern is None or not _matches(target, pattern)
                or (job_id is not None and not _matches(job_id, _AUDIT_ID))):
            return False
        now = int(time.time())
        if type(when) not in (int, float) or not 0 <= when <= _MAX_TIMESTAMP:
            when = now
        code = code if isinstance(code, str) and code in AUDIT_CODES else None
        from_version = from_version if _matches(from_version, _AUDIT_VERSION) else None
        to_version = to_version if _matches(to_version, _AUDIT_VERSION) else None
        try:
            with closing(self._connect()) as db, db:
                db.execute("DELETE FROM admin_audit WHERE ts < ?", (now - AUDIT_RETENTION_SECONDS,))
                insert = db.execute("""
                    INSERT OR IGNORE INTO admin_audit
                        (ts, actor, action, target_type, target, outcome, job_id, code, from_version, to_version)
                    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    WHERE NOT EXISTS (
                        SELECT 1 FROM admin_audit WHERE job_id = ? AND (outcome = 'queued') = ?
                    )
                """, (int(when), actor, action, target_type, target, outcome, job_id, code,
                      from_version, to_version, job_id, outcome == "queued"))
                if insert.rowcount:
                    db.execute("DELETE FROM admin_audit WHERE id <= ?", (insert.lastrowid - AUDIT_MAX_ENTRIES,))
        except sqlite3.Error:
            return False
        return True

    def finish(self, entry, outcome, *, code=None, when=None):
        return self.record(
            entry["action"], actor=entry["actor"], target_type=entry["target_type"], target=entry["target"],
            outcome=outcome, job_id=entry["job_id"], code=code, when=when,
            from_version=entry.get("from_version"), to_version=entry.get("to_version"),
        )

    def read(self, limit=MAX_PAGE_SIZE, before=None, *, action=None, outcome=None, target_type=None,
             target=None, job_id=None):
        validate_journal_request({"limit": limit, "before": before})
        for value, choices in ((action, AUDIT_ACTIONS), (outcome, AUDIT_OUTCOMES), (target_type, _AUDIT_TARGETS)):
            if value is not None and (not isinstance(value, str) or value not in choices):
                raise AuditFilterError("Недопустимый фильтр аудита.")
        if (target is not None and (target_type is None or not _matches(target, _AUDIT_TARGETS[target_type]))
                or job_id is not None and not _matches(job_id, _AUDIT_ID)):
            raise AuditFilterError("Недопустимый фильтр аудита.")
        conditions = ["ts >= ?", "id < ?"]
        values = [int(time.time()) - AUDIT_RETENTION_SECONDS, before or _MAX_ID + 1]
        for field, value in (("action", action), ("outcome", outcome), ("target_type", target_type),
                             ("target", target), ("job_id", job_id)):
            if value is not None:
                conditions.append(field + " = ?")
                values.append(value)
        try:
            with closing(self._connect()) as db:
                rows = db.execute(f"""
                    SELECT * FROM admin_audit WHERE {' AND '.join(conditions)} ORDER BY id DESC LIMIT ?
                """, (*values, limit + 1)).fetchall()
        except sqlite3.Error:
            raise JournalError("Не удалось прочитать аудит.") from None
        return {"entries": [dict(row) for row in rows[:limit]],
                "next_before": rows[limit - 1]["id"] if len(rows) > limit else None}

    def jobs(self, actions, limit=30):
        if not actions or not actions <= AUDIT_ACTIONS or not _integer_in_range(limit, MAX_PAGE_SIZE):
            raise JournalError("Недопустимые параметры операций.")
        placeholders = ",".join("?" for _ in actions)
        try:
            with closing(self._connect()) as db:
                rows = db.execute(f"""
                    SELECT event.*, (
                        SELECT ts FROM admin_audit WHERE job_id = event.job_id AND outcome = 'queued'
                    ) AS queued_at
                    FROM admin_audit AS event JOIN (
                        SELECT MAX(id) AS newest FROM admin_audit
                        WHERE ts >= ? AND job_id IS NOT NULL AND action IN ({placeholders})
                        GROUP BY job_id ORDER BY newest DESC LIMIT ?
                    ) AS jobs ON event.id = jobs.newest
                    ORDER BY event.id DESC
                """, (int(time.time()) - AUDIT_RETENTION_SECONDS, *sorted(actions), limit)).fetchall()
        except sqlite3.Error:
            raise JournalError("Не удалось прочитать операции.") from None
        return [dict(row) for row in rows]

    def job(self, job_id):
        if not _matches(job_id, _AUDIT_ID):
            return None
        try:
            with closing(self._connect()) as db:
                row = db.execute("""
                    SELECT * FROM admin_audit WHERE job_id = ? AND ts >= ? ORDER BY id DESC LIMIT 1
                """, (job_id, int(time.time()) - AUDIT_RETENTION_SECONDS)).fetchone()
        except sqlite3.Error:
            raise JournalError("Не удалось прочитать операцию.") from None
        return dict(row) if row is not None else None

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
    """Проверить схему ответа перед сохранением в базе Виктории."""
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
