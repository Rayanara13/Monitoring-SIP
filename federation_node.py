"""Persistent outbound synchronization for a Monitoring SIP node."""

import hashlib
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path
from uuid import uuid4
from federation_updates import _local_target
from ping_trust import MAX_TRUSTED_IPS, endpoint_ip, read_trust_snapshot

API = "/api/federation/v1"
HISTORY_BATCH = 100
RESULT_BATCH = 32
MAX_REPLY = 4 * 1024 * 1024
TOKEN = re.compile(r"[A-Za-z0-9_-]{24,256}")
ID = re.compile(r"[A-Za-z0-9_-]{1,96}")
ACTION = re.compile(r"[a-z_.]{1,40}")
PACKAGE_ID = re.compile(r"[a-f0-9]{64}")
LOG = logging.getLogger(__name__)


class FederationError(Exception):
    """An error safe to display in the local node administration UI."""


def connect(db_file):
    db = sqlite3.connect(db_file, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def init_node_tables(db, now=None):
    """Create the outbox in the same database and transaction as call history."""
    db.execute("CREATE TABLE IF NOT EXISTS federation_node_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS federation_outbox (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
            ts_start REAL NOT NULL, ts_end REAL NOT NULL, duration INTEGER NOT NULL,
            direction TEXT NOT NULL, phone_number TEXT NOT NULL, phone_name TEXT NOT NULL,
            peer_number TEXT NOT NULL, username TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS federation_node_commands (
            id TEXT PRIMARY KEY, action TEXT NOT NULL, status TEXT NOT NULL,
            result TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
        )
    """)
    marker = db.execute("INSERT OR IGNORE INTO federation_node_meta VALUES ('history_seeded', '1')")
    if marker.rowcount:
        cutoff = (time.time() if now is None else now) - 86400
        db.execute("""
            INSERT INTO federation_outbox
                (id, ts_start, ts_end, duration, direction, phone_number, phone_name, peer_number, username)
            SELECT lower(hex(randomblob(16))), ts_start, ts_end, duration, direction, local, local, remote, username
            FROM call_log WHERE ts_start >= ? ORDER BY id
        """, (cutoff,))
    db.execute("""
        UPDATE federation_node_commands
        SET status = 'failed', result = ?, acknowledged = 0
        WHERE status = 'processing' AND action != 'update.install'
    """, (json.dumps({"error": "Сервер перезапущен во время команды. Сверьте состояние узла."},
                     ensure_ascii=False),))
    db.execute("""
        UPDATE federation_node_commands SET status = 'running', acknowledged = 0
        WHERE status = 'processing' AND action = 'update.install'
    """)


def queue_call(db, ts_start, ts_end, duration, number, name, peer, direction, owner):
    db.execute("""
        INSERT INTO federation_outbox
            (id, ts_start, ts_end, duration, direction, phone_number, phone_name, peer_number, username)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (uuid4().hex, ts_start, ts_end, duration, direction, number, name, peer, owner))


def validate_endpoint(url, tls_ca):
    if not isinstance(url, str) or not isinstance(tls_ca, str) or len(url) > 512 or len(tls_ca) > 65536:
        raise FederationError("Нужны HTTPS-адрес сервера и доверенный сертификат PEM.")
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                or any(char.isspace() or char == "\\" for char in url)):
            raise ValueError
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
        tls_context(tls_ca)
    except (ValueError, ssl.SSLError):
        raise FederationError("Неверный HTTPS-адрес или сертификат сервера.") from None
    return {"url": url.rstrip("/"), "tls_ca": tls_ca}


def tls_context(tls_ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=tls_ca)
    return context


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(tls_ca):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=tls_context(tls_ca)),
    )


def valid(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def read_json_response(opener, req):
    with opener.open(req, timeout=8) as response:
        raw = response.read(MAX_REPLY + 1)
    if len(raw) > MAX_REPLY:
        raise FederationError("Слишком большой ответ сервера.")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise FederationError("Некорректный ответ сервера.") from None
    if not isinstance(data, dict):
        raise FederationError("Некорректный ответ сервера.")
    return data


class NodeSync:
    def __init__(self, db_file, version, snapshot, run_command, *, interval=5, master_url=None,
                 on_connection=None, availability_probe=None, ping_trust=None):
        self.db_file = db_file
        self.version = version
        self.installed_package = os.environ.get("INEI_RUNNING_PACKAGE") or None
        self.snapshot = snapshot
        self.run_command = run_command
        self.interval = interval
        self.master_url = master_url
        self.on_connection = on_connection
        self._availability_probe = availability_probe
        self._availability_revision = None
        self._ping_trust = ping_trust
        self._published_ping_trust = None
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._update_worker = None
        self._update_retry_after = 0.0
        self.last_error = None
        self.last_error_code = None

    def _load_link(self):
        with closing(connect(self.db_file)) as db:
            row = db.execute("SELECT value FROM federation_node_meta WHERE key = 'link'").fetchone()
        return json.loads(row["value"]) if row else None

    def _save_link(self, link):
        with closing(connect(self.db_file)) as db, db:
            db.execute("INSERT OR REPLACE INTO federation_node_meta VALUES ('link', ?)",
                       (json.dumps(link),))

    def status(self):
        link = self._load_link()
        with closing(connect(self.db_file)) as db:
            queued = db.execute("SELECT count(*) FROM federation_outbox").fetchone()[0]
            last_seen = db.execute("SELECT value FROM federation_node_meta WHERE key = 'last_sync'").fetchone()
        return {
            "configured": link is not None,
            "enrolled": bool(link and link["enrolled"]),
            "node_id": link["node_id"] if link else None,
            "url": link["url"] if link else self.master_url,
            "fallback_url": (link.get("fallback") or {}).get("url") if link else None,
            "history_queued": queued,
            "last_sync": float(last_seen["value"]) if last_seen else None,
            "error": self.last_error,
        }

    def diagnostic_identity(self):
        link = self._load_link()
        if link is None:
            return None
        return {"schema": 1, "url": link["url"], "tls_ca": link["tls_ca"], "center_id": link["center_id"]}

    @staticmethod
    def _meta(db, key):
        row = db.execute("SELECT value FROM federation_node_meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    def update_status(self):
        with closing(connect(self.db_file)) as db:
            offer = self._meta(db, "update_offer")
            waiting = self._meta(db, "update_request")
            latest = db.execute("""
                SELECT status, result FROM federation_node_commands WHERE action = 'update.install'
                ORDER BY rowid DESC LIMIT 1
            """).fetchone()
        return {
            "offer": offer if offer and offer["package_id"] != self.installed_package else None,
            "waiting": waiting is not None or bool(latest and latest["status"] in {"accepted", "running"}),
            "last_status": latest["status"] if latest else None,
        }

    def request_update(self, package_id):
        with self._lock, closing(connect(self.db_file)) as db, db:
            offer = self._meta(db, "update_offer")
            if (not valid(package_id, PACKAGE_ID) or not offer or package_id != offer["package_id"]
                    or package_id == self.installed_package):
                raise FederationError("Предложение обновления изменилось. Обновите страницу.")
            if self.update_status()["waiting"]:
                return
            request = {"id": uuid4().hex, "package_id": package_id}
            db.execute("INSERT OR REPLACE INTO federation_node_meta VALUES ('update_request', ?)",
                       (json.dumps(request),))
        self._wake.set()

    def import_invitation(self, invitation):
        if not isinstance(invitation, dict) or invitation.get("version") != 1:
            raise FederationError("Ожидается файл подключения версии 1.")
        node_id, center_id = invitation.get("node_id"), invitation.get("center_id")
        invite_token = invitation.get("invite_token")
        if not valid(node_id, ID) or not valid(center_id, ID) or not valid(invite_token, TOKEN):
            raise FederationError("Некорректный файл подключения.")
        endpoint = validate_endpoint(invitation.get("url"), invitation.get("tls_ca"))
        invite_digest = hashlib.sha256(invite_token.encode("ascii")).hexdigest()
        with self._lock:
            current = self._load_link()
            if self.master_url and not current:
                configured = urllib.parse.urlsplit(self.master_url)
                offered = urllib.parse.urlsplit(endpoint["url"])
                if (configured.hostname, configured.port or 443) != (offered.hostname, offered.port or 443):
                    raise FederationError("Адрес в приглашении не совпадает с IP и портом сервера из настроек.")
            if current and (current["node_id"], current["center_id"]) != (node_id, center_id):
                raise FederationError("Узел уже привязан к другому реестру. Используйте прежнюю запись узла.")
            if current:
                pending = current.get("pending_invitation") or {}
                if any(item.get("invite_sha256") == invite_digest or item.get("invite_token") == invite_token
                       for item in (current, pending)):
                    return
                self._trusted_address(current, endpoint["url"], endpoint["tls_ca"])
            candidate = {
                **endpoint, "node_id": node_id, "center_id": center_id,
                "invite_token": invite_token, "invite_sha256": invite_digest,
                "node_token": secrets.token_urlsafe(32),
                "enrolled": False,
            }
            link = {**current, "pending_invitation": candidate} if current and current["enrolled"] else candidate
            self._save_link(link)
            self._publish_ping_trust(link)
            self.last_error = None
            self.last_error_code = None
            self._wake.set()

    def import_at_startup(self, filename):
        if not filename or self._load_link():
            return
        try:
            path = Path(filename)
            if path.stat().st_size > 150000:
                raise FederationError("Файл подключения слишком большой.")
            self.import_invitation(json.loads(path.read_text(encoding="utf-8-sig")))
        except FederationError as error:
            self.last_error = str(error)
        except (OSError, ValueError):
            self.last_error = "Не удалось прочитать файл подключения из конфига."

    @staticmethod
    def _trusted_address(link, url, tls_ca):
        endpoint = validate_endpoint(url, tls_ca if tls_ca is not None else link["tls_ca"])
        fallback = link.get("fallback") or {}
        if tls_ca is None and endpoint["url"] == fallback.get("url"):
            return fallback.copy()
        if endpoint["tls_ca"] != link["tls_ca"] and endpoint != fallback:
            raise FederationError("Новый сертификат должен быть заранее передан сервером.")
        return endpoint

    def change_address(self, url, tls_ca=None):
        with self._lock:
            link = self._load_link()
            if not link:
                raise FederationError("Сначала импортируйте файл подключения.")
            endpoint = self._trusted_address(link, url, tls_ca)
            try:
                self._verify_identity({**link, **endpoint})
            except (OSError, urllib.error.URLError, FederationError):
                raise FederationError("Не удалось подтвердить сервер по новому адресу.") from None
            link.update(endpoint)
            link.pop("fallback", None)
            self._save_link(link)
            self._publish_ping_trust(link)
            self._wake.set()

    def _request(self, link, path, payload=None, *, authenticated=False):
        headers = {"Accept": "application/json"}
        raw = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if authenticated:
            headers["Authorization"] = f"Bearer {link['node_token']}"
        request = urllib.request.Request(link["url"] + API + path, data=raw, headers=headers)
        return read_json_response(make_opener(link["tls_ca"]), request)

    def _verify_identity(self, link):
        if self._request(link, "/identity").get("center_id") != link["center_id"]:
            raise FederationError("Идентификатор сервера не совпал.")

    def _publish_ping_trust(self, link):
        if self._ping_trust is None:
            return None
        snapshot = None
        if link and link.get("enrolled") and "ping_trust" in link:
            try:
                snapshot = read_trust_snapshot(link["ping_trust"])
            except ValueError:
                LOG.warning("Ignoring an invalid saved ping trust snapshot")
        address = endpoint_ip(link["url"] if link else self.master_url)
        revision = snapshot["revision"] if snapshot else None
        policy = (address, revision)
        addresses = snapshot["addresses"] if snapshot else []
        if address and address not in addresses:
            addresses = [address, *addresses[:MAX_TRUSTED_IPS - 1]]
        if (addresses or link) and self._published_ping_trust != policy:
            if self._ping_trust.publish(addresses):
                self._published_ping_trust = policy
        return revision

    def _receive_ping_trust(self, link, reply):
        if self._ping_trust is None:
            return False
        if "ping_trust" not in reply:
            if "ping_trust_revision" not in reply and "ping_trust" in link:
                del link["ping_trust"]
                return True
            return False
        try:
            snapshot = read_trust_snapshot(reply["ping_trust"])
            if reply.get("ping_trust_revision", snapshot["revision"]) != snapshot["revision"]:
                raise ValueError
        except ValueError:
            LOG.warning("Ignoring an invalid ping trust snapshot from Victoria")
            return False
        if link.get("ping_trust") == snapshot:
            return False
        link["ping_trust"] = snapshot
        return True

    def _enroll(self, link):
        self._verify_identity(link)
        payload = {
            "node_id": link["node_id"], "invite_token": link["invite_token"], "node_token": link["node_token"],
        }
        if self._ping_trust is not None:
            payload["ping_trust_revision"] = None
        try:
            reply = self._request(link, "/enroll", payload)
        except urllib.error.HTTPError as error:
            if error.code == 401:
                try:
                    details = json.loads(error.read(4097))
                    if isinstance(details, dict) and details.get("error") == "invitation_expired":
                        error.inei_code = "invitation_expired"
                except (AttributeError, OSError, ValueError):
                    pass
                finally:
                    error.close()
            raise
        if reply.get("center_id") != link["center_id"] or reply.get("node_id") != link["node_id"]:
            raise FederationError("Некорректное подтверждение регистрации.")
        self._receive_ping_trust(link, reply)
        link["enrolled"] = True
        link.setdefault("invite_sha256", hashlib.sha256(link["invite_token"].encode("ascii")).hexdigest())
        del link["invite_token"]
        self._save_link(link)

    def _outgoing(self):
        with closing(connect(self.db_file)) as db:
            history = [dict(row) for row in db.execute("""
                SELECT id, ts_start, ts_end, duration, direction, phone_number, phone_name, peer_number, username
                FROM federation_outbox ORDER BY seq LIMIT ?
            """, (HISTORY_BATCH,))]
            results = [
                {"id": row["id"], "status": row["status"], "result": json.loads(row["result"])}
                for row in db.execute("""
                    SELECT id, status, result FROM federation_node_commands
                    WHERE acknowledged = 0 AND status != 'processing' ORDER BY rowid LIMIT ?
                """, (RESULT_BATCH,))
            ]
        return history, results

    def _exchange(self, link, payload):
        try:
            return self._request(link, "/sync", payload, authenticated=True), None
        except OSError as error:
            if isinstance(error, urllib.error.HTTPError) and 400 <= error.code < 500:
                raise
            if not link.get("fallback"):
                raise
        candidate = {**link, **link["fallback"]}
        del candidate["fallback"]
        self._verify_identity(candidate)
        return self._request(candidate, "/sync", payload, authenticated=True), candidate

    def _acknowledge(self, reply, history, results, link_update, update_request):
        history_ack, result_ack = reply.get("history_ack"), reply.get("result_ack")
        discarded = reply.get("result_discarded", [])
        if (not isinstance(history_ack, list) or not isinstance(result_ack, list) or not isinstance(discarded, list)
                or any(not isinstance(item, str) for item in history_ack + result_ack + discarded)
                or not set(history_ack) <= {row["id"] for row in history}
                or not set(result_ack + discarded) <= {row["id"] for row in results}):
            raise FederationError("Некорректное подтверждение доставки.")
        offer = reply.get("update_offer")
        target = _local_target()
        if offer is not None and (not isinstance(offer, dict) or not valid(offer.get("package_id"), PACKAGE_ID)
                                  or not isinstance(offer.get("version"), str) or len(offer["version"]) > 64
                                  or (offer.get("platform"), offer.get("arch")) != target):
            raise FederationError("Некорректное предложение обновления.")
        ack = reply.get("update_request_ack")
        if ack is not None and (not update_request or ack != update_request["id"]):
            raise FederationError("Некорректное подтверждение запроса обновления.")
        with closing(connect(self.db_file)) as db, db:
            db.executemany("DELETE FROM federation_outbox WHERE id = ?", [(key,) for key in history_ack])
            db.executemany("UPDATE federation_node_commands SET acknowledged = 1 WHERE id = ?",
                           [(key,) for key in result_ack + discarded])
            db.execute("DELETE FROM federation_node_commands WHERE action = 'logs.read' AND acknowledged = 1")
            db.execute("INSERT OR REPLACE INTO federation_node_meta VALUES ('last_sync', ?)", (str(time.time()),))
            if link_update is not None:
                db.execute("UPDATE federation_node_meta SET value = ? WHERE key = 'link'", (json.dumps(link_update),))
            if "update_offer" in reply:
                if offer is None:
                    db.execute("DELETE FROM federation_node_meta WHERE key = 'update_offer'")
                else:
                    safe = {key: offer[key] for key in ("package_id", "version", "platform", "arch")}
                    db.execute("INSERT OR REPLACE INTO federation_node_meta VALUES ('update_offer', ?)",
                               (json.dumps(safe),))
            if ack is not None or ("update_offer" in reply and update_request is not None
                                   and (offer is None or offer["package_id"] != update_request["package_id"])):
                db.execute("DELETE FROM federation_node_meta WHERE key = 'update_request'")

    @staticmethod
    def _valid_command(command):
        return (isinstance(command, dict) and valid(command.get("id"), ID)
                and valid(command.get("action"), ACTION) and isinstance(command.get("payload"), dict))

    def _execute(self, link, command):
        key, action = command["id"], command["action"]
        is_update = action == "update.install"
        if is_update and ((self._update_worker and self._update_worker.is_alive())
                          or time.monotonic() < self._update_retry_after):
            return
        with closing(connect(self.db_file)) as db, db:
            previous = db.execute("SELECT * FROM federation_node_commands WHERE id = ?", (key,)).fetchone()
            if previous and (previous["action"] != action or not is_update
                             or previous["status"] not in {"accepted", "running"}):
                return
            db.execute("INSERT OR IGNORE INTO federation_node_commands VALUES (?, ?, ?, '{}', 0)",
                       (key, action, "running" if is_update else "processing"))
        if is_update:
            self._update_worker = threading.Thread(target=self._run_and_record, args=(link.copy(), command),
                                                   daemon=True, name="federation-update")
            self._update_worker.start()
        else:
            self._run_and_record(link, command)

    def _run_and_record(self, link, command):
        key, action, payload = command["id"], command["action"], command["payload"]
        try:
            if action == "endpoint.stage":
                link["fallback"] = validate_endpoint(payload.get("url"), payload.get("tls_ca"))
                self._save_link(link)
                status, result = "applied", {"url": link["fallback"]["url"]}
            else:
                status, result = self.run_command(command, link)
            result = json.dumps(result, ensure_ascii=False, allow_nan=False)
            if len(result.encode("utf-8")) > 65536:
                raise FederationError("Результат команды слишком большой.")
        except FederationError as error:
            status, result = "failed", json.dumps({"error": str(error)}, ensure_ascii=False)
        except Exception as error:
            LOG.warning("Federation command failed: %s (%s)", action, type(error).__name__)
            status, result = "failed", json.dumps({"error": "Команда завершилась ошибкой."}, ensure_ascii=False)
        if action == "update.install" and status == "running":
            self._update_retry_after = time.monotonic() + 15
        with closing(connect(self.db_file)) as db, db:
            db.execute("""
                UPDATE federation_node_commands SET status = ?, result = ?, acknowledged = 0
                WHERE id = ? AND (status != ? OR result != ?)
            """, (status, result, key, status, result))

    def _availability_payload(self, link, db):
        from availability_protocol import read_config

        if self._availability_revision is None:
            revision, targets = -1, {}
            try:
                revision, targets = read_config(self._meta(db, "availability_config"))
                if targets is None:
                    revision, targets = -1, {}
            except ValueError:
                pass
            self._availability_probe.set_targets(targets, observer_id=link["node_id"])
            self._availability_revision = revision
        return {
            "revision": self._availability_revision,
            "results": [[key, *result] for key, result in self._availability_probe.results().items()],
        }

    def _apply_availability_config(self, link, revision, targets):
        with closing(connect(self.db_file)) as db, db:
            if revision == -1:
                db.execute("DELETE FROM federation_node_meta WHERE key = 'availability_config'")
            else:
                config = {"revision": revision, "targets": list(targets.items())}
                db.execute("INSERT OR REPLACE INTO federation_node_meta VALUES ('availability_config', ?)",
                           (json.dumps(config),))
        self._availability_probe.set_targets(targets, observer_id=link["node_id"])
        self._availability_revision = revision

    def _receive_availability(self, link, reply):
        from availability_protocol import read_config

        if "availability" not in reply:
            if self._availability_revision != -1:
                self._apply_availability_config(link, -1, {})
            return
        try:
            revision, targets = read_config(reply["availability"])
        except ValueError:
            LOG.warning("Invalid availability configuration from Victoria")
            return
        if targets is not None:
            self._apply_availability_config(link, revision, targets)
        elif revision != self._availability_revision:
            # Ask for the full target list on the next sync.
            self._apply_availability_config(link, -1, {})

    def sync_once(self):
        with self._lock:
            link = self._load_link()
            trust_revision = self._publish_ping_trust(link)
            if link is None:
                return False
            if pending := link.get("pending_invitation"):
                try:
                    self._enroll(pending)
                except urllib.error.HTTPError as error:
                    if not 400 <= error.code < 500:
                        raise
                    del link["pending_invitation"]
                    self._save_link(link)
                else:
                    link = pending
                    trust_revision = self._publish_ping_trust(link)
            if not link["enrolled"]:
                self._enroll(link)
                trust_revision = self._publish_ping_trust(link)
            history, results = self._outgoing()
            with closing(connect(self.db_file)) as db:
                update_request = self._meta(db, "update_request")
                availability = self._availability_payload(link, db) if self._availability_probe is not None else None
            system, arch = _local_target()
            payload = {
                "node_id": link["node_id"], "version": self.version, "snapshot": self.snapshot(),
                "history": history, "results": results,
                "target": {"platform": system, "arch": arch}, "installed_package": self.installed_package,
                "update_request": update_request,
            }
            if availability is not None:
                payload["availability"] = availability
            if self._ping_trust is not None:
                payload["ping_trust_revision"] = trust_revision
            try:
                reply, candidate = self._exchange(link, payload)
            except urllib.error.HTTPError as error:
                if availability is not None and error.code == 401 and self._availability_revision != -1:
                    self._apply_availability_config(link, -1, {})
                if self._ping_trust is not None and error.code == 401 and "ping_trust" in link:
                    del link["ping_trust"]
                    self._save_link(link)
                    self._publish_ping_trust(link)
                raise
            commands = reply.get("commands")
            if (reply.get("center_id") != link["center_id"] or not isinstance(commands, list)
                    or len(commands) > 100 or any(not self._valid_command(command) for command in commands)):
                raise FederationError("Некорректный ответ синхронизации.")
            active_link = candidate or link
            trust_changed = self._receive_ping_trust(active_link, reply)
            self._acknowledge(reply, history, results, active_link if trust_changed else candidate, update_request)
            if trust_changed or candidate is not None:
                self._publish_ping_trust(active_link)
            if availability is not None:
                self._receive_availability(link, reply)
            for command in commands:
                self._execute(active_link, command)
            self.last_error = None
            self.last_error_code = None
            return True

    def start(self):
        if self._thread is None:
            if self._availability_probe is not None:
                self._availability_probe.start()
            self._thread = threading.Thread(target=self._loop, daemon=True, name="federation-sync")
            self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._availability_probe is not None:
            self._availability_probe.stop()

    def _loop(self):
        delay = self.interval
        connection = None
        while not self._stop.is_set():
            try:
                outcome = "connected" if self.sync_once() else None
                delay = self.interval
            except FederationError as error:
                outcome = "disconnected"
                self.last_error = str(error)
                self.last_error_code = "disconnected"
                delay = min(delay * 2, 60)
            except urllib.error.HTTPError as error:
                outcome = "disconnected"
                self.last_error = f"Сервер отклонил запрос ({error.code})."
                self.last_error_code = getattr(error, "inei_code", None) or (
                    "auth_failed" if error.code in {401, 403} else "disconnected"
                )
                delay = min(delay * 2, 60)
            except Exception as error:
                outcome = "disconnected"
                self.last_error = "Связь с сервером недоступна."
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                self.last_error_code = "tls_failed" if isinstance(reason, ssl.SSLError) else "disconnected"
                LOG.debug("Federation sync unavailable: %s", type(error).__name__)
                delay = min(delay * 2, 60)
            if outcome != connection:
                connection = outcome
                if outcome is not None and self.on_connection is not None:
                    self.on_connection(outcome)
            self._wake.wait(delay + random.uniform(0, min(delay / 4, 3)))
            self._wake.clear()
