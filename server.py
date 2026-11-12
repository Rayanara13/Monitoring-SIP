from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_socketio import SocketIO, join_room
from flask import has_request_context
import json
import time
import subprocess
import threading
import re
import secrets
import socket
import sqlite3
import os
import logging
import tempfile
import traceback
import urllib.request
import urllib.parse
import ipaddress
from collections import deque
from pathlib import Path
from functools import wraps
from datetime import timedelta, datetime
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from uuid import uuid4
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from federation_logs import FederationJournal, JournalError
from federation_node import FederationError, NodeSync, init_node_tables, make_opener, queue_call, validate_endpoint

app = Flask(__name__)


def redact_access_log(record):
    message = record.getMessage()
    redacted = re.sub(r"(?i)([?&](?:token|event_token)=)[^&\s\"]*", r"\1[скрыто]", message)
    if redacted != message:
        record.msg = redacted
        record.args = ()
    return True


access_logger = logging.getLogger("werkzeug")
if not any(getattr(item, "__name__", "") == "redact_access_log" for item in access_logger.filters):
    access_logger.addFilter(redact_access_log)

def socket_origin_allowed(origin, environ):
    host = environ.get("HTTP_HOST")
    return host and origin == f"{environ['wsgi.url_scheme']}://{host}"


# allow_upgrades=True — используем WebSocket если доступен, иначе polling
# ping_timeout/ping_interval — агрессивное обнаружение потери соединения
socketio = SocketIO(
    app,
    cors_allowed_origins=socket_origin_allowed,
    async_mode='threading',
    ping_timeout=25,
    ping_interval=10,
)

# Меняется с каждым выпуском: открытые панели сравнивают её с запомненной
# при первом подключении и предлагают перезагрузить страницу
VERSION = "Rel 1.4.1"

PHONES_DIR = Path("users_data")
AUTH_FILE = Path("auth.json")
ENV_FILE = Path(".env")
BLOCKS_FILE = Path("users_data/login_blocks.json")
DB_FILE = Path("users_data/call_history.db")
LOG_FILE = Path("users_data/app.log")

PHONES_DIR.mkdir(mode=0o700, exist_ok=True)

# ─── Логгер ─────────────────────────────────────────────────────────────────

class _JSONLFormatter(logging.Formatter):
    """Форматирует каждую запись как одну строку JSON."""
    def format(self, record: logging.LogRecord) -> str:
        data: dict = {
            "ts":    record.created,
            "dt":    self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
        }
        if hasattr(record, "fields"):
            data.update(record.fields)
        if record.exc_info:
            data["traceback"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False, default=str)


_raw_logger = logging.getLogger("monitoring_sip")
_raw_logger.setLevel(logging.DEBUG)
_raw_logger.propagate = False
_log_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=24, encoding="utf-8"
)
_log_handler.setFormatter(_JSONLFormatter())
_raw_logger.addHandler(_log_handler)

# Счётчик для связывания SIP-событий с broadcast и poll по event_id
_event_seq = 0
_event_seq_lock = threading.Lock()


def _next_event_id() -> int:
    global _event_seq
    with _event_seq_lock:
        _event_seq += 1
        return _event_seq


def alog(cat: str, level: str = "INFO", **fields) -> None:
    """Записывает структурированную JSONL-строку в лог."""
    lvl = getattr(logging, level, logging.INFO)
    record = _raw_logger.makeRecord(
        _raw_logger.name, lvl,
        fn="", lno=0, msg="", args=(), exc_info=None,
    )
    record.fields = {"cat": cat, **fields}
    _raw_logger.handle(record)

# ─── Активные WebSocket-клиенты ─────────────────────────────────────────────

connected_sids: set[str] = set()
_sids_lock = threading.Lock()
_emit_lock = threading.Lock()
_library_room = "shared-sets"
_ping_update_lock = threading.Lock()
_ping_update_users: set[str] = set()

# Rate-limit для /client_log: не более 120 записей в минуту с одного IP
_client_rate: dict = {}
CLIENT_LOG_RATE_LIMIT  = 120
CLIENT_LOG_RATE_WINDOW = 60

# ────────────────────────────────────────────────────────────────────────────

users_phones = {} # {username: {number: phone_data}}
pending_calls = {} # {local: {ts_start, direction, remote, username}}
closed_call_ids: dict[tuple[str, str], dict[str, float]] = {}
phone_flags = {}   # {number: {dnd, fwd_*, mute, audio, reg, missed, ...}} — функции из Action URL
mac_numbers = {}   # {(username, mac): {number}} — выучено из событий с номером и $mac
recent_events = deque(maxlen=300)  # последние /event — журнал на вкладке «Тесты»
lock = threading.RLock()

LOGIN_MAX_ATTEMPTS = 7
LOGIN_BLOCK_SECONDS = 900  # 15 минут


def load_login_attempts() -> dict:
    if BLOCKS_FILE.exists():
        try:
            data = json.loads(BLOCKS_FILE.read_text(encoding="utf-8"))
            now = time.time()
            # Удаляем просроченные блокировки при загрузке
            return {ip: rec for ip, rec in data.items() if rec.get("blocked_until", 0) > now}
        except Exception:
            pass
    return {}


def save_login_attempts() -> None:
    try:
        BLOCKS_FILE.write_text(
            json.dumps(login_attempts, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception:
        pass


login_attempts = load_login_attempts()

# Rate-limit для /event: не более 600 событий в минуту с одного IP.
# Со всеми полями Action URL один звонок даёт ~8 событий (трубка, занят/свободен,
# вызов, разговор, отбой…), а сервер-дубликатор шлёт события всех своих телефонов
# с одного IP — прежние 120 он бы выбирал за пару десятков звонков.
event_rate: dict = {}  # {ip: {"count": int, "window_start": float}}
EVENT_RATE_LIMIT = 600
EVENT_RATE_WINDOW = 60


def is_event_rate_limited(ip: str) -> bool:
    now = time.time()
    rec = event_rate.setdefault(ip, {"count": 0, "window_start": now})
    if now - rec["window_start"] >= EVENT_RATE_WINDOW:
        rec["count"] = 0
        rec["window_start"] = now
    rec["count"] += 1
    return rec["count"] > EVENT_RATE_LIMIT

API_AUTH_ROUTES = {"/phones", "/add_phone", "/update_phone", "/delete_phone", "/resize_phone",
                   "/reorder", "/yealink/inspect"}


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # не обязательно, чтобы хост существовал
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()


def get_env_value(key: str, default: str = "") -> str:
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return default


def setting(key: str, default: str = "") -> str:
    return os.environ.get(key, get_env_value(key, default))


local_role = setting("MONITORING_SIP_ROLE", "standalone").strip().lower()
if local_role not in {"standalone", "node", "slave"}:
    raise ValueError("Недопустимая роль узла.")
ROLE = "node" if local_role in {"node", "slave"} else "standalone"
LISTEN_HOST = setting("MONITORING_SIP_HOST", "0.0.0.0")
LISTEN_PORT = int(setting("MONITORING_SIP_PORT", "8000"))

journal = None
if ROLE != "standalone":
    try:
        journal = FederationJournal(PHONES_DIR / "federation_journal.db")
    except JournalError:
        alog("FEDERATION_JOURNAL_UNAVAILABLE", "ERROR")


def journal_record(kind, **fields):
    if journal is not None:
        journal.record(kind, **fields)


# Куда дублировать GET-запросы (центральный сервер). Только из .env, без адреса
# по умолчанию: не задан — дублирования нет
TARGET_IP = get_env_value("TARGET_IP", "") if ROLE == "standalone" else ""
TARGET_PORT = int(get_env_value("TARGET_PORT", "8000")) if TARGET_IP else 8000


def duplicate_get_request(url_path, query_params):
    if not TARGET_IP or LOCAL_IP == TARGET_IP:
        return

    # Строим URL для дублирования
    target_url = f"http://{TARGET_IP}:{TARGET_PORT}{url_path}"
    if query_params:
        target_url += "?" + urllib.parse.urlencode(query_params)
    
    def send_request():
        try:
            with urllib.request.urlopen(target_url, timeout=5) as response:
                response.read()
        except Exception as e:
            # Игнорируем ошибки при дублировании, чтобы не мешать основной работе
            pass

    threading.Thread(target=send_request, daemon=True).start()


@app.before_request
def before_request_func():
    if ROLE == "standalone" and request.method == "GET" and TARGET_IP and LOCAL_IP != TARGET_IP:
        duplicate_get_request(request.path, request.args.to_dict())

    origin = request.headers.get("Origin")
    if (request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and origin is not None and origin != request.host_url.rstrip("/")):
        return jsonify(ok=False, error="Запрос с другого сайта."), 403

    query = {key: value for key, value in request.args.items()
             if key.lower() not in {"token", "event_token", "password"}}
    alog("HTTP_REQ",
         method=request.method,
         path=request.path,
         ip=get_client_ip(),
         user=session.get("username"),
         query=query or None)


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    journal_record("service_exception")
    alog("UNHANDLED_EXCEPTION", "ERROR",
         error=str(e),
         traceback=traceback.format_exc(),
         path=request.path,
         method=request.method,
         ip=get_client_ip())
    return jsonify({"ok": False, "error": "Внутренняя ошибка сервера"}), 500


@socketio.on("connect")
def on_ws_connect():
    username = authenticated_user()
    if not username:
        return False
    join_room(f"phones:{username}")
    join_room(_library_room)
    with _sids_lock:
        connected_sids.add(request.sid)
        total = len(connected_sids)
    alog("WS_CONNECT",
         sid=request.sid[:10],
         total_clients=total,
         ip=get_client_ip(),
         user=username)
    socketio.emit("server_version", {"version": VERSION}, to=request.sid)


@socketio.on("disconnect")
def on_ws_disconnect():
    with _sids_lock:
        connected_sids.discard(request.sid)
        total = len(connected_sids)
    alog("WS_DISCONNECT",
         sid=request.sid[:10],
         total_clients=total)


def load_or_create_auth() -> dict:
    if AUTH_FILE.exists():
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        # Преобразуем старый формат в новый, если нужно
        if isinstance(data, dict) and "username" in data:
            data = {data["username"]: data}
            AUTH_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data

    username = "admin"
    password = secrets.token_urlsafe(12)
    event_token = secrets.token_hex(16)

    user_data = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_token": event_token
    }
    
    auth_data = {username: user_data}

    with os.fdopen(os.open(AUTH_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                   "w", encoding="utf-8") as stream:
        json.dump(auth_data, stream, indent=2, ensure_ascii=False)

    print("=" * 70)
    print("Создан файл auth.json")
    print(f"Логин: {username}")
    print(f"Пароль: {password}")
    print(f"Токен для /event: {event_token}")
    print("Сохрани эти данные. В auth.json хранится только хэш пароля.")
    print("=" * 70)

    return auth_data


AUTH = load_or_create_auth()


def get_app_secret():
    if ENV_FILE.exists():
        lines = ENV_FILE.read_text().splitlines()
        for line in lines:
            if line.startswith("APP_SECRET_KEY="):
                return line.split("=", 1)[1]
    
    key = secrets.token_hex(32)
    with os.fdopen(os.open(ENV_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a") as f:
        f.write(f"APP_SECRET_KEY={key}\n")
    return key


app.secret_key = get_app_secret()
app.permanent_session_lifetime = timedelta(hours=12)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def is_api_route(path: str) -> bool:
    return path in API_AUTH_ROUTES


def authenticated_user():
    username = session.get("username")
    if session.get("logged_in") is True and isinstance(username, str) and username in AUTH:
        return username
    return None


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if authenticated_user():
            return view_func(*args, **kwargs)

        if is_api_route(request.path):
            return jsonify({"ok": False, "error": "Требуется авторизация"}), 401

        return redirect(url_for("login_page"))
    return wrapper


def get_client_ip() -> str:
    return request.remote_addr or "unknown"


def is_login_blocked(ip: str) -> tuple[bool, int]:
    now = time.time()
    record = login_attempts.get(ip)

    if not record:
        return False, 0

    if record["blocked_until"] > now:
        return True, int(record["blocked_until"] - now)

    return False, 0


def register_login_fail(ip: str) -> None:
    now = time.time()
    record = login_attempts.setdefault(ip, {
        "fails": 0,
        "blocked_until": 0
    })

    if record["blocked_until"] > now:
        return

    record["fails"] += 1

    if record["fails"] >= LOGIN_MAX_ATTEMPTS:
        record["blocked_until"] = now + LOGIN_BLOCK_SECONDS
        record["fails"] = 0
        save_login_attempts()
        alog("AUTH_IP_BLOCKED", "WARNING",
             ip=ip, block_seconds=LOGIN_BLOCK_SECONDS)


def register_login_success(ip: str) -> None:
    if ip in login_attempts:
        del login_attempts[ip]
        save_login_attempts()


def init_db() -> None:
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS call_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_start  REAL    NOT NULL,
            ts_end    REAL    NOT NULL,
            duration  INTEGER NOT NULL,
            local     TEXT    NOT NULL,
            remote    TEXT    NOT NULL,
            direction TEXT    NOT NULL,
            username  TEXT    NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts    ON call_log(ts_start)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_local ON call_log(local)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user  ON call_log(username)")
    if ROLE == "node":
        init_node_tables(conn)
    conn.commit()
    conn.close()
    os.chmod(DB_FILE, 0o600)


def insert_call(ts_start: float, ts_end: float, duration: int,
                local: str, remote: str, direction: str, username: str) -> None:
    try:
        with closing(sqlite3.connect(DB_FILE)) as conn, conn:
            conn.execute(
                "INSERT INTO call_log (ts_start,ts_end,duration,local,remote,direction,username)"
                " VALUES (?,?,?,?,?,?,?)",
                (ts_start, ts_end, duration, local, remote, direction, username),
            )
            if ROLE == "node":
                phone = users_phones.get(username, {}).get(local, {})
                queue_call(conn, ts_start, ts_end, duration, local, phone.get("name", local),
                           remote, direction, username)
    except Exception as e:
        alog("DB_ERROR", "ERROR",
             operation="insert_call",
             error=str(e),
             local=local, remote=remote)


def cleanup_old_calls() -> None:
    try:
        cutoff = time.time() - 86400  # 24 часа
        conn = sqlite3.connect(DB_FILE)
        conn.execute("DELETE FROM call_log WHERE ts_start < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def cleanup_loop() -> None:
    cleanup_old_calls()
    while True:
        time.sleep(6 * 3600)
        cleanup_old_calls()


def complete_call(user_phone: str, event_id: int | None = None,
                  quiet: bool = False) -> None:
    """Завершает pending-звонок и записывает его в БД если длительность >= 3 сек.

    quiet — для вспомогательных событий конца звонка (Busy To Idle, Transfer
    Finished…): они приходят пачкой вслед за Terminated/On Hook, и отсутствие
    pending для них норма, а не CALL_MISS.
    """
    with lock:
        now = time.time()
        call = _pending_call(user_phone, now)
        if call:
            pending_calls.pop(user_phone)
            _remember_closed_call(user_phone, call, now)
    if call:
        ts_end = time.time()
        duration = int(ts_end - call["ts_start"])
        if duration >= 3:
            insert_call(
                call["ts_start"], ts_end, duration,
                user_phone,
                call["remote"] or "Не определен",
                call["direction"],
                call["username"],
            )
            alog("CALL_LOGGED",
                 event_id=event_id,
                 number=user_phone,
                 duration=duration,
                 remote=call.get("remote"),
                 direction=call["direction"],
                 user=call["username"])
        else:
            alog("CALL_SKIPPED",
                 event_id=event_id,
                 number=user_phone,
                 duration=duration,
                 msg=f"Длительность {duration}с < 3с, в историю не записан")
    elif quiet:
        alog("CALL_ALREADY_CLOSED", "DEBUG",
             event_id=event_id,
             number=user_phone)
    else:
        alog("CALL_MISS", "WARNING",
             event_id=event_id,
             number=user_phone,
             msg="complete_call: нет pending_call для номера")


CARD_LAYOUT_LIMITS = {"columns": (1, 8), "min_height": (0, 800)}


def valid_layout_value(key, value):
    default, maximum = CARD_LAYOUT_LIMITS[key]
    return type(value) is int and default <= value <= maximum


def load_phones() -> None:
    global users_phones
    seen_ids = set()

    # Загружаем телефоны для каждого пользователя из auth.json
    for username in AUTH.keys():
        user_file = PHONES_DIR / f"phones_{username}.json"
        
        # Миграция старого файла для админа
        if username == "admin" and Path("phones.json").exists() and not user_file.exists():
            try:
                Path("phones.json").rename(user_file)
            except Exception:
                pass

        if not user_file.exists():
            user_file.write_text("[]", encoding="utf-8")

        try:
            data = json.loads(user_file.read_text(encoding="utf-8"))
        except Exception:
            data = []

        loaded = {}
        migrated = False
        for item in data:
            number = str(item["number"]).strip()
            loaded[number] = {
                "name": item.get("name", number),
                "ip": item.get("ip", ""),
                "state": "В_покое",
                "time": "-",
                "peer": "",
                "duration": "00:00",
                "call_start": None,
                "ping": "?",
                "position": int(item.get("position", 0)),
            }
            for key, (default, _) in CARD_LAYOUT_LIMITS.items():
                value = item.get(key)
                if valid_layout_value(key, value) and value != default:
                    loaded[number][key] = value
            card_id, revision = item.get("card_id"), item.get("revision", 0)
            if ROLE == "node" and (
                not isinstance(card_id, str) or not re.fullmatch(r"[0-9a-f]{32}", card_id)
                or card_id in seen_ids or type(revision) is not int or revision < 0
            ):
                card_id, revision = uuid4().hex, 0
                migrated = True
            if isinstance(card_id, str):
                loaded[number].update(card_id=card_id, revision=revision)
                seen_ids.add(card_id)
        users_phones[username] = loaded
        if migrated:
            save_phones(username)
        alog("PHONES_LOADED", user=username, count=len(loaded),
             numbers=list(loaded.keys()))


def write_local_json(path, data):
    if path.resolve().parent != PHONES_DIR.resolve():
        raise ValueError("Неверный путь файла пользователя.")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            handle.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_cards(username, phones):
    rows = []
    for number, phone in phones.items():
        row = {"number": number, "name": phone["name"], "ip": phone["ip"],
               "position": int(phone.get("position", 0))}
        row.update({key: phone[key] for key in CARD_LAYOUT_LIMITS if key in phone})
        if "card_id" in phone:
            row.update(card_id=phone["card_id"], revision=phone["revision"])
        rows.append(row)
    rows.sort(key=lambda row: row["position"])
    write_local_json(PHONES_DIR / f"phones_{username}.json", rows)


def save_phones(username: str) -> None:
    with lock:
        if username in users_phones:
            write_cards(username, users_phones[username])


def new_card(number, name, ip, position):
    card = {"name": name or number, "ip": ip, "state": "В_покое", "time": "-", "peer": "",
            "duration": "00:00", "call_start": None, "ping": "?", "position": position}
    if ROLE == "node":
        card.update(card_id=uuid4().hex, revision=0)
    return card


def next_card_position(cards):
    return max((card["position"] for card in cards.values()), default=-1) + 1


def touch_card(card):
    if "card_id" in card:
        card["revision"] += 1


def change_cards(username, apply):
    with lock:
        before = users_phones.get(username, {})
        cards = {number: phone.copy() for number, phone in before.items()}
        result = apply(cards)
        if cards == before:
            return result
        numbers = before.keys() | cards.keys()
        changed_ips = {number for number in numbers
                       if before.get(number, {}).get("ip") != cards.get(number, {}).get("ip")}
        previous_conflicts = {number for number in changed_ips if conflicting_number(number)}
        write_cards(username, cards)
        users_phones[username] = cards
        current_conflicts = {number for number in changed_ips if conflicting_number(number)}
        owners = {username} | owners_of_numbers(previous_conflicts ^ current_conflicts)
        shared_changed = (
            any(before.get(number, {}).get("name") != cards.get(number, {}).get("name")
                for number in numbers) or bool(changed_ips)
        ) and get_user_meta(username).get("shared", False)
    broadcast_update(owners)
    if shared_changed:
        emit_updates("shared_sets_update", {}, {_library_room})
    return result


def normalize_number(value: str | None) -> str:
    if value is None:
        return ""
    return str(value).strip()


def clean_remote(value: str | None) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if value.startswith("$") or value.lower() in {"sip:", "sip:@", "sips:", "sips:@"}:
        return ""
    
    # Регулярное выражение: ищем sip: (без учета регистра), захватываем все до @ или :
    match = re.search(r'(?i)sip:([^@:]+)', value)
    if match:
        return match.group(1)
    
    # Если есть @, берем все до него
    if '@' in value:
        return value.split('@')[0]
    
    # Если нет sip: и нет @, но есть :, может это номер:порт?
    if ':' in value and not value.startswith(':'):
         return value.split(':')[0]

    return value


def normalize_call_id(value: str | None) -> str:
    call_id = (value or "").strip()[:100]
    return "" if call_id == "-1" or call_id.startswith("$") else call_id


def owners_of_numbers(numbers):
    if not numbers:
        return set()
    with lock:
        return {username for username, phones in users_phones.items() if not numbers.isdisjoint(phones)}


def emit_updates(event, payload, rooms):
    if not rooms:
        return
    try:
        with _emit_lock:
            for room in rooms:
                socketio.emit(event, payload, to=room)
        if event == "phones_update":
            with _sids_lock:
                ws_clients = len(connected_sids)
            alog("BROADCAST_EMIT", event_id=payload["event_id"], ws_clients=ws_clients)
    except Exception as error:
        alog("BROADCAST_ERROR", "ERROR", event=event, event_id=payload.get("event_id"), error=str(error))


def broadcast_update(usernames, event_id: int | None = None):
    emit_updates("phones_update", {"data": "updated", "event_id": event_id},
                 {f"phones:{username}" for username in usernames})


# ─── Состояния карточки ──────────────────────────────────────────────────────
# Идёт разговор (одна из линий занята собеседником)
TALK_STATES = {"Разговор", "Удержание", "Перевод_вызова", "Конференция"}
# Телефон занят: идёт таймер, ставится время события
ACTIVE_STATES = TALK_STATES | {"Исходящий_вызов", "Входящий_вызов", "Снята_трубка",
                               "Абонент_занят", "Занят"}
# Если в событии нет собеседника — оставляем прежнего
PEER_KEEP_STATES = TALK_STATES | {"Абонент_занят"}
# Покой: таймер и собеседник сбрасываются
REST_STATES = {"В_покое", "OFFLINE", "DND", "Нет_регистрации"}
# Зависшие дольше 60 с сбрасывает watchdog в ping_loop
STUCK_STATES = {"Снята_трубка", "Входящий_вызов", "Исходящий_вызов", "Абонент_занят"}
STUCK_TIMEOUT = 60
LATE_ANSWER_GRACE = 60
MAX_CLOSED_IDS = 16


def set_state(number: str, state: str, peer: str | None = None,
              event_id: int | None = None) -> None:
    found = False
    with lock:
        if conflicting_number(number):
            return
        # Ищем номер у всех пользователей
        for username, phones in users_phones.items():
            if number in phones:
                found = True
                phone = phones[number]
                old_state = phone["state"]
                old_peer  = phone.get("peer", "")
                phone["state"] = state

                if state in ACTIVE_STATES:
                    phone["time"] = time.strftime("%H:%M:%S")
                    if phone["call_start"] is None:
                        phone["call_start"] = time.time()

                # Миграция номера собеседника: если в новом событии peer не указан,
                # но он был определен ранее в рамках этого же вызова, сохраняем старый.
                if peer is not None and peer != "":
                    phone["peer"] = peer
                elif state in PEER_KEEP_STATES and phone.get("peer") and phone["peer"] != "Не определен":
                    # Сохраняем существующий peer для этих состояний, если новый не пришел
                    pass
                elif state in ACTIVE_STATES:
                    # Если peer вообще не был задан ранее
                    if not phone.get("peer"):
                        phone["peer"] = "Не определен"
                else:
                    phone["peer"] = ""

                if state in REST_STATES:
                    phone["call_start"] = None
                    phone["duration"] = "00:00"
                    if state == "В_покое":
                        phone["peer"] = ""

                alog("STATE_CHANGE",
                     event_id=event_id,
                     number=number,
                     from_state=old_state,
                     to_state=state,
                     peer_before=old_peer,
                     peer_after=phone.get("peer", ""),
                     user=username)

    if not found:
        alog("STATE_MISS", "WARNING",
             event_id=event_id,
             number=number,
             state=state,
             msg="Номер не найден ни у одного пользователя — карточка не обновится")


def get_sorted_phones(username: str) -> list[dict]:
    with lock:
        if username not in users_phones:
            return []
            
        phones = users_phones[username]
        result = []

        now = time.time()
        for number, phone in phones.items():
            entry = {"number": number, **{k: v for k, v in phone.items() if k not in {"card_id", "revision"}}}
            if phone.get("call_start") is not None:
                entry["duration_sec"] = int(now - phone["call_start"])
            flags = {} if conflicting_number(number) else phone_flags.get(number, {})
            entry["flags"] = {k: flags[k] for k in PUBLIC_FLAGS if k in flags}
            result.append(entry)

    result.sort(key=lambda x: int(x["position"]))
    return result


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if authenticated_user():
            return redirect(url_for("panel"))
        return send_file("login.html")

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    ip = get_client_ip()
    blocked, seconds_left = is_login_blocked(ip)
    if blocked:
        journal_record("auth_result", outcome="blocked")
        return jsonify({
            "ok": False,
            "error": f"Слишком много попыток. Повтори через {seconds_left} сек."
        }), 429

    if username in AUTH and check_password_hash(AUTH[username]["password_hash"], password):
        session.permanent = True
        session["logged_in"] = True
        session["username"] = username
        register_login_success(ip)
        journal_record("auth_result", outcome="success")
        alog("AUTH_LOGIN_OK", user=username, ip=ip)
        return jsonify({"ok": True})

    register_login_fail(ip)
    journal_record("auth_result", outcome="failed")
    fails = login_attempts.get(ip, {}).get("fails", 1)
    alog("AUTH_LOGIN_FAIL", "WARNING",
         username=username, ip=ip, fails_so_far=fails)
    return jsonify({"ok": False, "error": "Неверный логин или пароль"}), 401


@app.route("/register", methods=["POST"])
@login_required
def register():
    # Регистрация доступна только админу
    if session.get("username") != "admin":
        return jsonify({"ok": False, "error": "Доступ запрещен"}), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()

    if not username:
        return jsonify({"ok": False, "error": "Введите логин"}), 400

    if len(username) < 3:
        return jsonify({"ok": False, "error": "Логин слишком короткий"}), 400

    if username in AUTH:
        return jsonify({"ok": False, "error": "Пользователь уже существует"}), 400

    # Генерируем пароль автоматически
    password = secrets.token_urlsafe(10)
    event_token = secrets.token_hex(16)
    
    AUTH[username] = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_token": event_token
    }

    AUTH_FILE.write_text(json.dumps(AUTH, indent=2, ensure_ascii=False), encoding="utf-8")
    
    # Создаем пустой файл телефонов для нового пользователя
    user_file = PHONES_DIR / f"phones_{username}.json"
    if not user_file.exists():
        user_file.write_text("[]", encoding="utf-8")
    
    with lock:
        users_phones[username] = {}

    return jsonify({
        "ok": True, 
        "password": password, 
        "event_token": event_token
    })


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"ok": True})


# ─── Action URL: события Yealink ─────────────────────────────────────────────
# key — значение state в Action URL: имя параметра action_url.* из админ-гайда
# Yealink (у последних шести полей гайд имён не даёт — назвали сами).
# ru — подпись поля на странице «Функции → Action URL» русской прошивки. Перевод
# там местами мимо («Отклонено» = Terminated, «Ошибка» = Missed Call, «режим
# ожидания» = Call Waiting), поэтому рядом en. Порядок = порядок полей на странице.
ACTION_URL_EVENTS = [
    ("setup_completed",          "Настройка завершена",                  "Setup Completed"),
    ("registered",               "Зарегистрирован",                      "Registered"),
    ("unregistered",             "Не зарегистрировано",                  "Unregistered"),
    ("register_failed",          "Ошибка регистрации",                   "Register Failed"),
    ("off_hook",                 "Трубка снята",                         "Off Hook"),
    ("on_hook",                  "Трубка положена",                      "On Hook"),
    ("incoming_call",            "Входящий вызов",                       "Incoming Call"),
    ("outgoing_call",            "Исходящий вызов",                      "Outgoing Call"),
    ("call_established",         "Связь установлена",                    "Established"),
    ("call_terminated",          "Отклонено",                            "Terminated"),
    ("dnd_on",                   "Включение DND",                        "Open DND"),
    ("dnd_off",                  "Отключение DND",                       "Close DND"),
    ("always_fwd_on",            "Включена переадресация 'Всегда'",      "Open Always Forward"),
    ("always_fwd_off",           "Выключена переадресация 'Всегда'",     "Close Always Forward"),
    ("busy_fwd_on",              "Включена переадресация 'Занято'",      "Open Busy Forward"),
    ("busy_fwd_off",             "Выключена переадресация 'Занято'",     "Close Busy Forward"),
    ("no_answer_fwd_on",         "Включена переадресация 'Нет ответа'",  "Open NoAnswer Forward"),
    ("no_answer_fwd_off",        "Выключена переадресация 'Нет ответа'", "Close NoAnswer Forward"),
    ("transfer_call",            "Перевод звонка",                       "Transfer Call"),
    ("blind_transfer_call",      "Слепой трансфер",                      "Blind Transfer"),
    ("attended_transfer_call",   "Сопроводительный трансфер",            "Attended Transfer"),
    ("hold",                     "Удержание",                            "Hold"),
    ("unhold",                   "Возврат",                              "UnHold"),
    ("mute",                     "Тишина",                               "Mute"),
    ("unmute",                   "Вкл.микро",                            "UnMute"),
    ("missed_call",              "Ошибка",                               "Missed Call"),
    ("ip_change",                "Смена IP-адреса",                      "IP Changed"),
    ("idle_to_busy",             "Занятость абонента",                   "Idle To Busy"),
    ("busy_to_idle",             "Занято",                               "Busy To Idle"),
    ("reject_incoming_call",     "Отбой входящего вызова",               "Reject Incoming Call"),
    ("answer_new_incoming_call", "Ответил на вызов",                     "Answer New-In Call"),
    ("transfer_failed",          "Ошибка трансфера",                     "Transfer Failed"),
    ("transfer_finished",        "Завершение перевода",                  "Transfer Finished"),
    ("forward_incoming_call",    "Переадресация входящих вызовов",       "Forward Incoming Call"),
    ("setup_autop_finish",       "Завершение настройки",                 "Autop Finish"),
    ("call_waiting_on",          "Включение режима ожидания",            "Open Call Waiting"),
    ("call_waiting_off",         "Отключение режима ожидания",           "Close Call Waiting"),
    ("headset",                  "Гарнитура",                            "Headset"),
    ("handfree",                 "Громкая связь",                        "Handfree"),
    ("cancel_callout",           "Отмена вызова",                        "Cancel Call Out"),
    ("remote_busy",              "Вызываемый абонент занят",             "Remote Busy"),
    ("call_remote_canceled",     "Вызов отклонен",                       "Call Remote Canceled"),
    ("view_missed_call",         "View Missed Call",                     "View Missed Call"),
    ("view_forwarded_call",      "View Forwarded Call",                  "View Forwarded Call"),
    ("peripheral_information",   "Периферийная информация",              "Peripheral Information"),
    ("vpn_ip",                   "VPN IP",                               "VPN IP"),
    ("sip_info_display_update",  "SIP INFO Display Update",              "SIP INFO Display Update"),
    ("conference",               "Конференция с",                        "Conference"),
]
EVENT_LABELS = {k: ru for k, ru, _ in ACTION_URL_EVENTS}
# Verified against the Yealink T53 Remote Control provisioning table:
# https://support.yealink.com/docs/sip-t53/remote-control/93527fc627104ded93cf7f11a1c2dbe2
# The last two custom names cannot be inferred from our event keys.
ACTION_URL_PARAMETERS = {k: f"action_url.{k}" for k, _, _ in ACTION_URL_EVENTS}
ACTION_URL_PARAMETERS.update({
    "view_missed_call": "custom.action_url.view_misscall",
    "view_forwarded_call": "custom.action_url.view_forward",
})

# Старые значения state — уже прописаны в телефонах, принимаем как синонимы
LEGACY_STATES = {
    "Setup":     "outgoing_call",
    "Ringing":   "incoming_call",
    "Connected": "call_established",
    "Idle":      "call_terminated",
    "Hold":      "hold",
    "DND":       "dnd_on",
    "OffHook":   "off_hook",
    "OnHook":    "on_hook",
}

# Что из phone_flags отдаём в /phones (служебные dnd_sticky / line2 / … — нет)
PUBLIC_FLAGS = ("dnd", "fwd_always", "fwd_busy", "fwd_noanswer", "call_waiting",
                "mute", "audio", "reg", "missed", "forwarded", "vpn_ip", "lines",
                "last_event", "last_event_time")

# Звонок есть (своя линия занята): новый вызов поверх — вторая линия
CALL_STATES = TALK_STATES | {"Исходящий_вызов", "Входящий_вызов", "Абонент_занят"}


def normalize_mac(value: str | None) -> str:
    mac = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    return mac if len(mac) == 12 else ""


def normalize_ip(value: str | None) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def resolve_number(local: str, mac: str, phone_ip: str, user: str) -> tuple[str, str]:
    """Номер телефона для события и откуда он взят.

    По гайду Yealink $active_user заполнен только в звонке; для DND,
    переадресаций, регистрации, смены IP он может прийти пустым. Тогда ищем по
    $mac (выучен на прошлых событиях с номером), потом по IP карточки — только в
    наборе владельца токена и только однозначные совпадения: у DECT-базы один IP
    и MAC на несколько трубок, такой адрес номер не определяет. IP отправителя не
    используем: при дублировании это IP сервера-дубликатора, а X-Forwarded-For
    подделывается.
    """
    if local:
        return local, "local"
    with lock:
        ip_numbers = {num for num, phone in users_phones.get(user, {}).items()
                      if phone_ip and normalize_ip(phone.get("ip")) == phone_ip}
        # A known shared base stays ambiguous even after just ONE handset has
        # taught us its MAC. Otherwise all blank events look like that handset.
        if len(ip_numbers) > 1:
            return "", ""
        if mac:
            numbers = mac_numbers.get((user, mac), set())
            if len(numbers) == 1:
                return next(iter(numbers)), "mac"
        if len(ip_numbers) == 1:
            return ip_numbers.pop(), "ip"
    return "", ""


_number_locks: dict[str, threading.Lock] = {}


def number_lock(number: str) -> threading.Lock:
    """Одно событие номера за раз: переход (start_call → set_state и т.п.) не
    перемежается с соседним событием того же телефона. Берётся ДО lock."""
    with lock:
        return _number_locks.setdefault(number, threading.Lock())


def find_phone(number: str) -> dict | None:
    """Карточка номера (состояние одинаково во всех наборах). Вызывать под lock."""
    for phones in users_phones.values():
        if number in phones:
            return phones[number]
    return None


def conflicting_number(number: str) -> bool:
    """Общий номер допустим только для копий одной карточки с одним IP. Под lock."""
    addresses = [normalize_ip(phones[number].get("ip"))
                 for phones in users_phones.values() if number in phones]
    return len(addresses) > 1 and (not all(addresses) or len(set(addresses)) > 1)


def current_state(number: str) -> str | None:
    """Вызывать под lock."""
    phone = find_phone(number)
    return phone["state"] if phone else None


def rest_state(number: str) -> str:
    """Состояние покоя с учётом функций телефона. Вызывать под lock."""
    flags = phone_flags.get(number, {})
    if flags.get("reg") in ("off", "fail"):
        return "Нет_регистрации"
    # «Включение DND» держит DND до «Отключение DND»; старый state=DND гаснет
    # с концом звонка, как раньше (у таких телефонов поля «Отключение» нет)
    if flags.get("dnd") and flags.get("dnd_sticky"):
        return "DND"
    return "В_покое"


def _event_call_id() -> str:
    return normalize_call_id(request.args.get("call_id")) if has_request_context() else ""


def _remember_closed_call(number: str, call: dict, now: float) -> None:
    """Вызывать под lock. Недавние закрытые ID подавляют запоздалые события."""
    call_id = call.get("call_id", "")
    timed_out = "recover_until" in call or call.get("recovered", False)
    if not call_id and not timed_out:
        return
    ids = closed_call_ids.setdefault((call["username"], number), {})
    if call_id:
        ids[call_id] = now + LATE_ANSWER_GRACE
    if timed_out:
        ids[""] = now + LATE_ANSWER_GRACE
    while len(ids) > MAX_CLOSED_IDS:
        ids.pop(next(iter(ids)))


def _closed_call(number: str, user: str, call_id: str, now: float) -> bool:
    """Вызывать под lock. Пустой ID отмечает неоднозначное событие после таймаута."""
    return closed_call_ids.get((user, number), {}).get(call_id, 0) > now


def _pending_call(number: str, now: float) -> dict | None:
    """Вызывать под lock. Сброшенная карточка хранит попытку ограниченное время."""
    call = pending_calls.get(number)
    if call and "recover_until" in call and now >= call["recover_until"]:
        pending_calls.pop(number)
        _remember_closed_call(number, call, now)
        return None
    return call


def _matches_pending(call: dict, call_id: str, remote: str, *, check_peer: bool) -> bool:
    previous_id = call.get("call_id", "")
    if call_id and previous_id:
        return call_id == previous_id
    return not (check_peer and remote and call["remote"] and remote != call["remote"])


def _can_answer_incoming(number: str, user: str, state: str | None, remote: str) -> bool:
    now, call_id = time.time(), _event_call_id()
    with lock:
        call = _pending_call(number, now)
        if not call or call["direction"] != "in" or (call_id and _closed_call(number, user, call_id, now)):
            return False
        if state == "Входящий_вызов":
            return _matches_pending(call, call_id, remote, check_peer=_closed_call(number, user, "", now))
        return (state in {"В_покое", "DND"} and call["username"] == user
                and call.get("recover_state") == "Входящий_вызов"
                and _matches_pending(call, call_id, remote, check_peer=True))


def _terminal_for_replaced_call(number: str, user: str) -> bool:
    call_id = _event_call_id()
    if not call_id:
        return False
    now = time.time()
    with lock:
        call = _pending_call(number, now)
        return bool(call and call_id != call.get("call_id") and _closed_call(number, user, call_id, now))


def record_event(key: str | None, number: str, local: str, resolved_by: str,
                 remote: str, phone_ip: str, call_id: str, user: str,
                 details: dict | None = None, *, update_card: bool = True) -> None:
    """Последнее событие на карточке + журнал для вкладки «Тесты»."""
    label = EVENT_LABELS.get(key)
    now = time.strftime("%H:%M:%S")
    with lock:
        recent_events.append({
            "time": now, "key": key, "label": label or "неизвестное событие",
            "known": label is not None, "number": number, "local": local,
            "resolved_by": resolved_by, "remote": remote, "ip": phone_ip,
            "call_id": call_id, "user": user,
            **(details or {}),
        })
        if update_card and number and label:
            flags = phone_flags.setdefault(number, {})
            flags["last_event"] = label
            flags["last_event_time"] = now


# ── Линии ──
# Action URL не говорит, к какой линии относится событие ($call_id по гайду —
# «активного» звонка, на живых трассах не проверен). Поэтому считаем линии:
# lines = сколько звонков идёт. Вторая линия не трогает pending первой — в
# историю звонок со второй линией ложится одной записью, от начала первого до
# конца последнего. «Одна линия кончилась, телефон ещё занят» допускаем, только
# если телефон шлёт Busy To Idle: оно поправит ошибку, когда телефон реально
# освободится. Без него (старая настройка) Terminated / On Hook, как раньше,
# завершают всё — иначе карточка могла бы навсегда застрять в «Удержании».

def start_call(number: str, direction: str, remote: str, user: str) -> bool | None:
    """Начинает звонок. True — вторая линия, None — повтор известного события."""
    now, call_id = time.time(), _event_call_id()
    with lock:
        previous = _pending_call(number, now)
        if call_id and (_closed_call(number, user, call_id, now)
                        or (previous and previous["username"] == user and previous.get("call_id") == call_id)):
            return None
        phone = find_phone(number)
        cur = phone["state"] if phone else None
        flags = phone_flags.setdefault(number, {})
        second = flags.get("lines", 0) >= 1 and cur in CALL_STATES
        if second:
            flags["lines"] += 1
            # Куда вернуть карточку, если вторая линия не состоится
            flags["line2"] = {"state": cur, "peer": phone.get("peer", "")}
        else:
            flags["lines"] = 1
            flags.pop("line2", None)
        if not second or not previous:
            if previous and "recover_until" in previous:
                _remember_closed_call(number, previous, now)
            pending_calls[number] = {
                "ts_start": now,
                "direction": direction,
                "remote": remote,
                "username": user,
                "call_id": call_id,
            }
        return second


def end_call(number: str, event_id: int, quiet: bool = False) -> None:
    """Звонок завершён (все линии): история, сброс mute/гарнитуры, карточка в покой."""
    complete_call(number, event_id=event_id, quiet=quiet)
    with lock:
        flags = phone_flags.setdefault(number, {})
        flags.pop("line2", None)
        flags["lines"] = 0
        flags["mute"] = False
        flags["audio"] = None
        if not flags.get("dnd_sticky"):
            flags["dnd"] = False  # старая логика: DND гаснет с концом звонка
        state = rest_state(number)
    set_state(number, state, event_id=event_id)


def end_line(number: str, event_id: int, quiet: bool = False,
             ignore_if_multi: bool = False) -> None:
    """Terminated / On Hook: конец одной линии или всего звонка (см. «Линии»)."""
    with lock:
        flags = phone_flags.setdefault(number, {})
        multi = flags.get("lines", 0) > 1 and flags.get("busy_to_idle_seen")
        line2 = None
        if multi and not ignore_if_multi:
            flags["lines"] -= 1
            line2 = flags.pop("line2", None)
    if not multi:
        end_call(number, event_id, quiet)
    elif ignore_if_multi:
        # Трубку положили при двух линиях: какая кончилась — не знаем; покой
        # придёт с Terminated / Busy To Idle
        alog("SIP_ONHOOK_IGNORED", event_id=event_id, number=number, reason="multi_line")
    elif line2:
        # Вторая линия так и не ответила — карточка остаётся на первой
        set_state(number, line2["state"], line2["peer"] or None, event_id=event_id)
    else:
        # Обе линии были в разговоре: оставшаяся ждёт «Возврат»
        set_state(number, "Удержание", event_id=event_id)


def end_attempt(number: str, event_id: int, expect: set[str],
                show: str | None = None, *, user: str, remote: str) -> None:
    """Неудачная попытка вызова (отбой, занято, отмена, пропущен, переадресован).

    Была вторая линия — возвращаем карточку к первой. Иначе завершаем, только
    если карточка в ожидаемом состоянии попытки: событие от линии, которой мы не
    видели, не должно ронять идущий разговор.
    """
    now, call_id = time.time(), _event_call_id()
    with lock:
        call = _pending_call(number, now)
        if call_id and _closed_call(number, user, call_id, now):
            return
        timed_out_attempt = (call and call["username"] == user and call.get("recover_state") in expect
                             and _matches_pending(call, call_id, remote, check_peer=True))
        flags = phone_flags.setdefault(number, {})
        line2 = flags.pop("line2", None)
        if line2:
            flags["lines"] = max(1, flags.get("lines", 1) - 1)
        cur = current_state(number)
    if line2:
        set_state(number, line2["state"], line2["peer"] or None, event_id=event_id)
    elif timed_out_attempt:
        end_call(number, event_id, quiet=True)
    elif cur in expect:
        if show:
            # pending живёт до отбоя трубки — иначе On Hook не найдёт звонок
            set_state(number, show, event_id=event_id)
        else:
            end_call(number, event_id, quiet=True)


# ── Обработчики: handler(number, remote, phone_ip, user, event_id) ──

def _ev_outgoing(n, remote, ip, user, eid):
    second = start_call(n, "out", remote, user)
    if second is None:
        return
    if second:
        alog("SIP_SECOND_LINE", event_id=eid, number=n, remote=remote, direction="out")
    set_state(n, "Исходящий_вызов", remote, event_id=eid)


def _ev_incoming(n, remote, ip, user, eid):
    second = start_call(n, "in", remote, user)
    if second is None:
        return
    if second:
        # Второй входящий поверх звонка: карточку не трогаем, иначе после
        # отбоя звонящего watchdog сбросил бы идущий разговор в покой
        alog("SIP_SECOND_LINE", event_id=eid, number=n, remote=remote, direction="in")
        return
    set_state(n, "Входящий_вызов", remote, event_id=eid)


def _connect(n, remote, user, eid, direction=None, *, require_pending=False):
    now, call_id = time.time(), _event_call_id()
    with lock:
        call = _pending_call(n, now)
        if require_pending and not call:
            return
        if (call_id or not call) and _closed_call(n, user, call_id, now):
            return
        flags = phone_flags.setdefault(n, {})
        recovering = call and "recover_until" in call
        if call and flags.get("lines", 0) <= 1 and not _matches_pending(
                call, call_id, remote, check_peer=bool(recovering or _closed_call(n, user, "", now))):
            return
        if recovering:
            expected_state = "Входящий_вызов" if call["direction"] == "in" else "Исходящий_вызов"
            if call["username"] != user or call.get("recover_state") != expected_state:
                return
            call.pop("recover_until")
            call.pop("recover_state")
            call["recovered"] = True
            flags["lines"] = 1
            for phones in users_phones.values():
                if n in phones:
                    phones[n]["call_start"] = call["ts_start"]
        if not remote:
            # После таймаута видимый peer сброшен, но исходный номер есть в попытке.
            phone = find_phone(n)
            remote = (phone.get("peer") or "") if phone else ""
            if call and (not remote or remote == "Не определен"):
                remote = call["remote"]
            if remote:
                alog("SIP_PEER_PRESERVED", event_id=eid, number=n, peer=remote)
        flags.pop("line2", None)  # вторая линия ответила — возвращать некуда
        if call:
            # При нескольких линиях pending принадлежит первой — собеседника не меняем
            if flags.get("lines", 0) <= 1:
                if remote:
                    call["remote"] = remote
                if call_id and not call.get("call_id"):
                    call["call_id"] = call_id
        elif direction:
            flags["lines"] = 1
            pending_calls[n] = {
                "ts_start": now,
                "direction": direction,
                "remote": remote,
                "username": user,
                "call_id": call_id,
            }
    set_state(n, "Разговор", remote, event_id=eid)


def _ev_established(n, remote, ip, user, eid):
    _connect(n, remote, user, eid)


def _ev_answer_new(n, remote, ip, user, eid):
    _connect(n, remote, user, eid, direction="in")


def _ev_terminated(n, remote, ip, user, eid):
    if not _terminal_for_replaced_call(n, user):
        end_line(n, eid)


def _ev_on_hook(n, remote, ip, user, eid):
    if not _terminal_for_replaced_call(n, user):
        end_line(n, eid, ignore_if_multi=True)


def _ev_busy_to_idle(n, remote, ip, user, eid):
    # Телефон целиком свободен — все линии кончились
    with lock:
        phone_flags.setdefault(n, {})["busy_to_idle_seen"] = True
    if not _terminal_for_replaced_call(n, user):
        end_call(n, eid, quiet=True)


def _ev_call_end_quiet(n, remote, ip, user, eid):
    end_call(n, eid, quiet=True)


def _ev_off_hook(n, remote, ip, user, eid):
    now, call_id = time.time(), _event_call_id()
    with lock:
        in_call = _pending_call(n, now) is not None
        if call_id and _closed_call(n, user, call_id, now):
            return
        cur = current_state(n)
        flags = phone_flags.get(n, {})
        audio_cleared = cur in TALK_STATES and flags.get("audio") is not None
        if audio_cleared:
            flags["audio"] = None
    if _can_answer_incoming(n, user, cur, remote):
        # Трубку сняли, пока звонит, — это ответ (Established может не прийти)
        _connect(n, remote, user, eid, require_pending=True)
    elif in_call or cur in TALK_STATES:
        # Off Hook во время разговора делает старый аудиозначок недостоверным.
        # По этому событию нельзя определить текущий аудиоканал или ход звонка.
        alog("SIP_OFFHOOK_IGNORED", event_id=eid, number=n, reason="active_call",
             audio_cleared=audio_cleared)
    else:
        set_state(n, "Снята_трубка", event_id=eid)


def _ev_idle_to_busy(n, remote, ip, user, eid):
    # Подробности (трубка, вызов) приносят другие события; «Занят» — только если
    # кроме этого события ничего не пришло
    with lock:
        cur = current_state(n)
    if cur in ("В_покое", "DND"):
        set_state(n, "Занят", event_id=eid)


def _set_state_ev(state, keep_peer=False):
    def handler(n, remote, ip, user, eid):
        set_state(n, state, None if keep_peer else remote, event_id=eid)
    return handler


def _attempt_ev(expect, show=None, counter=None):
    def handler(n, remote, ip, user, eid):
        if counter:
            with lock:
                flags = phone_flags.setdefault(n, {})
                flags[counter] = flags.get(counter, 0) + 1
        end_attempt(n, eid, expect, show, user=user, remote=remote)
    return handler


def _flag_ev(name, value):
    def handler(n, remote, ip, user, eid):
        with lock:
            phone_flags.setdefault(n, {})[name] = value
    return handler


def _audio_ev(value):
    def handler(n, remote, ip, user, eid):
        now, call_id = time.time(), _event_call_id()
        with lock:
            _pending_call(n, now)
            if call_id and _closed_call(n, user, call_id, now):
                return
            phone_flags.setdefault(n, {})["audio"] = value
            cur = current_state(n)
        if _can_answer_incoming(n, user, cur, remote):
            # Ответили кнопкой громкой связи / гарнитуры, не снимая трубку:
            # Established на части телефонов при этом не приходит
            _connect(n, remote, user, eid, require_pending=True)
    return handler


def _info_ev(n, remote, ip, user, eid):
    """Информационное событие отражается в журнале и отметке последнего события."""


def _dnd_on(n, eid, sticky):
    with lock:
        flags = phone_flags.setdefault(n, {})
        flags["dnd"] = True
        flags["dnd_sticky"] = sticky
        cur = current_state(n)
    if cur not in ACTIVE_STATES:  # во время звонка — только значок
        set_state(n, "DND", event_id=eid)


def _ev_dnd_on(n, remote, ip, user, eid):
    _dnd_on(n, eid, sticky=True)


def _ev_dnd_legacy(n, remote, ip, user, eid):
    _dnd_on(n, eid, sticky=False)


def _ev_dnd_off(n, remote, ip, user, eid):
    with lock:
        flags = phone_flags.setdefault(n, {})
        flags["dnd"] = False
        cur = current_state(n)
        rest = rest_state(n)
    if cur == "DND":
        set_state(n, rest, event_id=eid)


def _reg_ev(value):
    def handler(n, remote, ip, user, eid):
        with lock:
            phone_flags.setdefault(n, {})["reg"] = value
            cur = current_state(n)
            rest = rest_state(n)
        if value == "ok" and cur == "Нет_регистрации":
            set_state(n, rest, event_id=eid)
        elif value != "ok" and cur in ("В_покое", "DND"):
            set_state(n, "Нет_регистрации", event_id=eid)
    return handler


def _ev_ip_change(n, remote, ip, user, eid):
    """Новый IP телефона — в карточку владельца токена, иначе пинг уведёт её в OFFLINE.
    Чужие наборы не трогаем: токен одного набора не даёт права писать в другой."""
    if not ip:
        alog("SIP_IP_CHANGE_NO_IP", "WARNING", event_id=eid, number=n,
             msg="Нет параметра ip=$ip — карточка не обновлена")
        return
    with lock:
        cards = users_phones.get(user, {})
        phone = cards.get(n)
        old_ip = phone.get("ip") if phone else None
        changed = phone is not None and old_ip != ip
        if changed:
            updated = {**phone, "ip": ip}
            touch_card(updated)
            write_cards(user, {**cards, n: updated})
            cards[n] = updated
    if changed:
        alog("PHONE_IP_CHANGED", event_id=eid, number=n, user=user,
             old_ip=old_ip, new_ip=ip)
        if get_user_meta(user).get("shared", False):
            emit_updates("shared_sets_update", {}, {_library_room})
    elif phone is None:
        alog("SIP_IP_CHANGE_NOT_OWNED", "WARNING", event_id=eid, number=n, user=user,
             msg="Номера нет в наборе владельца токена — IP не обновлён")


def _ev_vpn_ip(n, remote, ip, user, eid):
    with lock:
        phone_flags.setdefault(n, {})["vpn_ip"] = ip


INCOMING_ATTEMPT = {"Входящий_вызов"}
OUTGOING_ATTEMPT = {"Исходящий_вызов"}

EVENT_HANDLERS = {
    "setup_completed":          _ev_call_end_quiet,  # перезагрузился — звонков нет
    "registered":               _reg_ev("ok"),
    "unregistered":             _reg_ev("off"),
    "register_failed":          _reg_ev("fail"),
    "off_hook":                 _ev_off_hook,
    "on_hook":                  _ev_on_hook,
    "incoming_call":            _ev_incoming,
    "outgoing_call":            _ev_outgoing,
    "call_established":         _ev_established,
    "call_terminated":          _ev_terminated,
    "dnd_on":                   _ev_dnd_on,
    "dnd_off":                  _ev_dnd_off,
    "always_fwd_on":            _flag_ev("fwd_always", True),
    "always_fwd_off":           _flag_ev("fwd_always", False),
    "busy_fwd_on":              _flag_ev("fwd_busy", True),
    "busy_fwd_off":             _flag_ev("fwd_busy", False),
    "no_answer_fwd_on":         _flag_ev("fwd_noanswer", True),
    "no_answer_fwd_off":        _flag_ev("fwd_noanswer", False),
    "transfer_call":            _set_state_ev("Перевод_вызова", keep_peer=True),
    "blind_transfer_call":      _set_state_ev("Перевод_вызова", keep_peer=True),
    "attended_transfer_call":   _set_state_ev("Перевод_вызова", keep_peer=True),
    "hold":                     _set_state_ev("Удержание"),
    "unhold":                   _set_state_ev("Разговор"),
    "mute":                     _flag_ev("mute", True),
    "unmute":                   _flag_ev("mute", False),
    "missed_call":              _attempt_ev(INCOMING_ATTEMPT, counter="missed"),
    "ip_change":                _ev_ip_change,
    "idle_to_busy":             _ev_idle_to_busy,
    "busy_to_idle":             _ev_busy_to_idle,
    "reject_incoming_call":     _attempt_ev(INCOMING_ATTEMPT),
    "answer_new_incoming_call": _ev_answer_new,
    "transfer_failed":          _set_state_ev("Разговор", keep_peer=True),
    "transfer_finished":        _ev_call_end_quiet,  # звонок передан целиком
    "forward_incoming_call":    _attempt_ev(INCOMING_ATTEMPT, counter="forwarded"),
    "setup_autop_finish":       _info_ev,
    "call_waiting_on":          _flag_ev("call_waiting", True),
    "call_waiting_off":         _flag_ev("call_waiting", False),
    "headset":                  _audio_ev("headset"),
    "handfree":                 _audio_ev("handsfree"),
    "cancel_callout":           _attempt_ev(OUTGOING_ATTEMPT),
    "remote_busy":              _attempt_ev(OUTGOING_ATTEMPT, show="Абонент_занят"),
    "call_remote_canceled":     _attempt_ev(INCOMING_ATTEMPT),
    "view_missed_call":         _flag_ev("missed", 0),
    "view_forwarded_call":      _flag_ev("forwarded", 0),
    "peripheral_information":   _info_ev,
    "vpn_ip":                   _ev_vpn_ip,
    "sip_info_display_update":  _info_ev,
    "conference":               _set_state_ev("Конференция", keep_peer=True),
}
assert set(EVENT_HANDLERS) == {k for k, _, _ in ACTION_URL_EVENTS}

# Старый state=DND: DND гаснет с концом звонка (поля «Отключение DND» у таких
# телефонов не настроено) — отдельный обработчик, а не вывод из истории событий
LEGACY_HANDLERS = {"DND": _ev_dnd_legacy}


@app.route("/event")
def event():
    client_ip = get_client_ip()

    if is_event_rate_limited(client_ip):
        journal_record("sip_rejected", reason="rate_limited")
        alog("SIP_RATE_LIMITED", "WARNING", ip=client_ip)
        return "Too Many Requests", 429

    token = request.args.get("token")
    # Проверяем токен у любого пользователя
    target_user = None
    for user_info in AUTH.values():
        if token and user_info.get("event_token") == token:
            target_user = user_info["username"]
            break

    if not target_user:
        journal_record("sip_rejected", reason="bad_token")
        alog("SIP_BAD_TOKEN", "WARNING", ip=client_ip)
        return "Unauthorized", 401

    state  = request.args.get("state")
    # Keep the actual macro expansion for diagnostics. Never retain the token
    # or the full query string in the browser's event journal.
    raw_local = str(request.args.get("local") or "").strip()[:200]
    raw_remote = str(request.args.get("remote") or "").strip()[:200]
    raw_called_number = str(request.args.get("called_number") or "").strip()[:200]
    local  = normalize_number(request.args.get("local"))
    if local.startswith("$"):  # переменная не подставилась
        local = ""
    remote = clean_remote(request.args.get("remote"))
    mac    = normalize_mac(request.args.get("mac"))
    phone_ip = normalize_ip(request.args.get("ip"))
    call_id = normalize_call_id(request.args.get("call_id"))
    key = LEGACY_STATES.get(state, state)

    evt_id = _next_event_id()
    user_phone, resolved_by = resolve_number(local, mac, phone_ip, target_user)
    with number_lock(user_phone):
        remote_source = "remote" if remote else ""
        called_number = clean_remote(request.args.get("called_number"))
        # $calledNumber is the OUTGOING callee. Only the outgoing event proves
        # this direction: pending_calls may belong to a different, held line.
        if not remote and called_number and key == "outgoing_call":
            remote, remote_source = called_number, "called_number"
        details = {
            "raw_local": raw_local, "raw_remote": raw_remote,
            "raw_called_number": raw_called_number, "remote_source": remote_source,
            "model": str(request.args.get("model") or "").strip()[:100],
            "firmware": str(request.args.get("firmware") or "").strip()[:100],
        }

        alog("SIP_RECV",
             event_id=evt_id,
             state=state,
             local=local,
             number=user_phone,
             resolved_by=resolved_by,
             remote=remote,
             user=target_user,
             ip=client_ip,
             phone_ip=phone_ip or None,
             mac=mac or None,
             call_id=call_id or None,
             **details)

        with lock:
            owned = user_phone in users_phones.get(target_user, {})
            ambiguous = owned and conflicting_number(user_phone)
            accepted = owned and (not ambiguous or key == "ip_change")
            if accepted and resolved_by == "local" and mac:
                mac_numbers.setdefault((target_user, mac), set()).add(user_phone)

        if not user_phone:
            journal_record("sip_rejected", reason="unknown_phone")
            rejection = "unresolved"
        elif not owned:
            rejection = "not_owned"
        elif not accepted:
            rejection = "ambiguous_number"
        else:
            rejection = ""
        record_event(key, user_phone, local, resolved_by, remote, phone_ip, call_id,
                     target_user, {**details, "rejection": rejection},
                     update_card=accepted and not ambiguous)
        owners = set()

        if not user_phone:
            alog("SIP_NO_LOCAL", "WARNING", event_id=evt_id, state=state, user=target_user)
        elif not owned:
            journal_record("sip_rejected", reason="unknown_phone")
            alog("SIP_PHONE_NOT_IN_CARDS", "WARNING",
                 event_id=evt_id,
                 number=user_phone,
                 user=target_user,
                 msg="Событие пришло для номера, которого нет в карточках пользователя")
        elif not accepted:
            journal_record("sip_rejected", reason="unknown_phone")
            alog("SIP_AMBIGUOUS_NUMBER", "WARNING", event_id=evt_id,
                 number=user_phone, user=target_user)
        else:
            handler = LEGACY_HANDLERS.get(state) or EVENT_HANDLERS.get(key)
            if handler is None:
                journal_record("sip_rejected", reason="unsupported_event")
                alog("SIP_UNKNOWN_STATE", "WARNING",
                     event_id=evt_id, state=state, number=user_phone, user=target_user)
            else:
                handler(user_phone, remote, phone_ip, target_user, evt_id)
                journal_record("sip_event", event=key, phone_number=user_phone)
                owners.add(target_user)
                with lock:
                    if not ambiguous or not conflicting_number(user_phone):
                        owners.update(owners_of_numbers({user_phone}))

    broadcast_update(owners, event_id=evt_id)
    emit_updates("recent_events_update", {"event_id": evt_id}, {"phones:admin"})
    return "OK"


@app.route("/action_url_events")
@login_required
def action_url_events():
    """Каталог событий — панель строит по нему таблицу URL и список тест-событий."""
    current_user = session.get("username")
    username = request.args.get("username", current_user)
    if username != current_user and current_user != "admin":
        return jsonify({"ok": False, "error": "Доступ запрещен"}), 403
    if username not in AUTH:
        return jsonify({"ok": False, "error": "Пользователь не найден"}), 404
    return jsonify(action_url_catalog(username))


def action_url_catalog(username):
    with lock:
        phones = [
            {"number": number, "name": phone.get("name", number),
             "ip": phone.get("ip", "")}
            for number, phone in sorted(users_phones.get(username, {}).items(),
                                        key=lambda item: item[1].get("position", 0))
        ]
    aliases: dict[str, list[str]] = {}
    for old, new in LEGACY_STATES.items():
        aliases.setdefault(new, []).append(old)
    return {
        "server_ip": LOCAL_IP,  # если панель открыта как localhost — телефонам нужен LAN-IP
        "phones": phones,
        "events": [
            {"key": k, "ru": ru, "en": en, "aliases": aliases.get(k, []),
             "parameter": ACTION_URL_PARAMETERS[k]}
            for k, ru, en in ACTION_URL_EVENTS
        ],
    }


_yealink_inspect_lock = threading.Lock()


@app.route("/yealink/inspect", methods=["POST"])
@login_required
def inspect_yealink():
    """Сверяем профиль телефона по HTTPS, сохраняя устройство в исходном состоянии."""
    if session.get("username") != "admin":
        return jsonify(ok=False, code="forbidden", error="Проверка доступна администратору."), 403
    if request.content_length is None or request.content_length > 40_000:
        return jsonify(ok=False, code="payload_size", error="Слишком большой запрос проверки."), 413
    return inspect_yealink_data(request.get_json(silent=True))


def inspect_yealink_data(data):
    from yealink_setup import YealinkSetupError, inspect_phone

    if not isinstance(data, dict):
        return jsonify(ok=False, code="invalid_request", error="Неверные параметры проверки."), 400
    ip = normalize_ip(data.get("ip")) if isinstance(data.get("ip"), str) else ""
    owner, number = data.get("username"), data.get("number")
    if not ip or not isinstance(owner, str) or not isinstance(number, str):
        return jsonify(ok=False, code="invalid_target", error="Укажите IP телефона и выберите его карточку."), 400
    with lock:
        matches = [n for n, phone in users_phones.get(owner, {}).items()
                   if normalize_ip(phone.get("ip")) == ip]
    if owner not in AUTH or matches != [number]:
        return jsonify(ok=False, code="card_mismatch",
                       error="IP должен совпадать с адресом одной карточки выбранного пользователя."), 400
    expected = data.get("expected_urls", {})
    if not isinstance(expected, dict) or any(
        key not in ACTION_URL_PARAMETERS or not isinstance(value, str) or len(value) > 511
        for key, value in expected.items()
    ):
        return jsonify(ok=False, code="invalid_profile", error="Неверный профиль Action URL."), 400

    cidrs = [item.strip() for item in setting("YEALINK_ALLOWED_CIDRS").split(",") if item.strip()]
    username = setting("YEALINK_ADMIN_USER")
    password = setting("YEALINK_ADMIN_PASSWORD")
    if not cidrs or not username or not password:
        return jsonify(ok=False, code="not_configured",
                       error="На сервере нужно настроить доступ к сети телефонов и учётную запись Yealink."), 503
    if not _yealink_inspect_lock.acquire(blocking=False):
        return jsonify(ok=False, code="busy", error="Другая проверка телефона ещё идёт."), 409
    try:
        result = inspect_phone(ip, allowed_cidrs=cidrs, username=username, password=password,
                               expected_urls=expected, certificate_sha256=setting("YEALINK_CERT_SHA256") or None)
    except YealinkSetupError as error:
        alog("YEALINK_INSPECT_FAILED", "WARNING", ip=ip, code=error.code, user=owner)
        return jsonify(ok=False, code=error.code, error=str(error)), 422
    finally:
        _yealink_inspect_lock.release()
    return jsonify(ok=True, **result)


@app.route("/recent_events")
@login_required
def get_recent_events():
    if session.get("username") != "admin":
        return jsonify({"ok": False, "error": "Доступ запрещен"}), 403
    with lock:
        items = list(recent_events)[-100:]
    items.reverse()
    return jsonify({"ok": True, "events": items})


@app.route("/client_log", methods=["POST"])
def client_log():
    """
    Принимает лог-записи от браузера и пишет их в app.log.
    Не требует авторизации — нужно фиксировать ошибки даже при протухшей сессии.
    Rate-limited по IP.
    """
    ip = get_client_ip()
    now = time.time()
    rec = _client_rate.setdefault(ip, {"count": 0, "window_start": now})
    if now - rec["window_start"] >= CLIENT_LOG_RATE_WINDOW:
        rec["count"] = 0
        rec["window_start"] = now
    rec["count"] += 1
    if rec["count"] > CLIENT_LOG_RATE_LIMIT:
        return "", 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return "", 400

    # Санируем: только строки и числа, обрезаем длинные значения
    def _sanitize(v):
        if isinstance(v, (int, float, bool)):
            return v
        return str(v)[:500]

    fields = {k: _sanitize(v) for k, v in data.items()
              if isinstance(k, str) and not k.startswith("_")}

    cat   = str(fields.pop("cat",   "CLIENT")).upper()[:40]
    level = str(fields.pop("level", "INFO")).upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        level = "INFO"

    alog(f"CLIENT_{cat}", level,
         source="browser",
         client_ip=ip,
         user=session.get("username"),
         **fields)
    return "", 204


@app.route("/phones")
@login_required
def get_phones():
    username = session.get("username")
    phones = get_sorted_phones(username)
    with _sids_lock:
        ws_clients = len(connected_sids)
    alog("PHONES_POLL",
         user=username,
         ip=get_client_ip(),
         count=len(phones),
         ws_clients=ws_clients)
    response = jsonify({"phones": phones})
    response.headers["Cache-Control"] = "no-store"
    return response


class CardError(FederationError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def card_group(state):
    if state == "В_покое":
        return "idle"
    if not state or state in {"OFFLINE", "DND", "Нет_регистрации"}:
        return "offline"
    return "active"


def move_card_in_group(cards, data):
    source = data.get("from_number")
    target = data.get("to_number")
    group = data.get("group")
    if not isinstance(source, str) or not isinstance(target, str) or (
        group is not None and group not in ("active", "idle", "offline")
    ):
        raise CardError("Неверный формат перемещения.")
    if source not in cards or target not in cards:
        raise CardError("Карточка была удалена. Попробуйте снова.", 409)
    source_group = card_group(cards[source].get("state"))
    target_group = card_group(cards[target].get("state"))
    if source_group != target_group or (group is not None and source_group != group):
        raise CardError("Статус карточки изменился. Попробуйте снова.", 409)

    order = sorted(cards, key=lambda number: cards[number]["position"])
    positions = [cards[number]["position"] for number in order]
    if len(set(positions)) != len(positions):
        # Старые наборы могли сохранить одинаковые позиции. Порядок при равенстве
        # уже определён текущей выдачей, поэтому сначала закрепляем эти места.
        positions = list(range(len(order)))
    slots = [index for index, number in enumerate(order)
             if card_group(cards[number].get("state")) == source_group]
    group_order = [order[index] for index in slots]
    target_index = group_order.index(target)
    group_order.remove(source)
    group_order.insert(target_index, source)
    for index, number in zip(slots, group_order):
        order[index] = number
    for number, position in zip(order, positions):
        if cards[number]["position"] != position:
            cards[number]["position"] = position
            touch_card(cards[number])
    return {}


def apply_card_change(action, username, data, *, remote=False):
    def apply(cards):
        if action == "phone.reorder":
            if remote:
                refs = data.get("cards")
                if not isinstance(refs, list) or len(refs) != len(cards):
                    raise CardError("Набор карточек изменился.", 409)
                order = [resolve_card(cards, ref)[0] for ref in refs]
                if len(set(order)) != len(cards):
                    raise CardError("Список карточек содержит повторы.")
            elif isinstance(data, dict):
                return move_card_in_group(cards, data)
            elif isinstance(data, list):
                order = list(map(str, data))
            else:
                raise CardError("Неверный формат")
            for position, number in enumerate(order):
                if number in cards and cards[number]["position"] != position:
                    cards[number]["position"] = position
                    touch_card(cards[number])
            return {}

        if action == "phone.add":
            old_number = None
        elif remote:
            old_number, _ = resolve_card(cards, data)
        else:
            old_number = normalize_number(data.get("old_number") or data.get("number"))

        if action == "phone.delete":
            if old_number in cards:
                del cards[old_number]
                for position, phone in enumerate(sorted(cards.values(), key=lambda p: p["position"])):
                    if phone["position"] != position:
                        phone["position"] = position
                        touch_card(phone)
            return {}

        number = normalize_number(data.get("number"))
        name = normalize_number(data.get("name"))
        ip = normalize_number(data.get("ip"))
        if not number:
            raise CardError("Не указан номер" if action == "phone.add" else "Номер не может быть пустым")
        if remote and (len(number) > 64 or len(name) > 256 or (ip and not normalize_ip(ip))):
            raise CardError("Некорректные данные карточки.")
        if number in cards and number != old_number:
            raise CardError("Такой номер уже существует")
        if action == "phone.add":
            card = new_card(number, name, ip, next_card_position(cards))
        else:
            if old_number not in cards:
                raise CardError("Номер не найден", 404)
            card = cards.pop(old_number)
            if (old_number, card["name"], card["ip"]) != (number, name or number, ip):
                touch_card(card)
            card.update(name=name or number, ip=ip)
        cards[number] = card
        return {"id": card.get("card_id"), "revision": card.get("revision")}

    if action != "phone.reorder" and not isinstance(data, dict):
        raise CardError("Неверный формат")
    if action == "phone.reorder" and username not in users_phones:
        raise CardError("Пользователь не найден", 404)
    return change_cards(username, apply)


def resolve_card(cards, ref):
    if not isinstance(ref, dict) or not isinstance(ref.get("id"), str) or type(ref.get("revision")) is not int:
        raise CardError("Укажите идентификатор и версию карточки.")
    for number, card in cards.items():
        if card.get("card_id") == ref["id"]:
            if card["revision"] != ref["revision"]:
                raise CardError("Карточка изменилась на узле. Обновите снимок.", 409)
            return number, card
    raise CardError("Карточка удалена на узле.", 409)


def edit_local_cards(action):
    try:
        apply_card_change(action, session["username"], request.get_json(force=True))
    except CardError as error:
        return jsonify(ok=False, error=str(error)), error.status
    return jsonify(ok=True)


@app.route("/add_phone", methods=["POST"])
@login_required
def add_phone():
    return edit_local_cards("phone.add")


@app.route("/update_phone", methods=["POST"])
@login_required
def update_phone():
    return edit_local_cards("phone.update")


@app.route("/delete_phone", methods=["POST"])
@login_required
def delete_phone():
    return edit_local_cards("phone.delete")


@app.route("/resize_phone", methods=["POST"])
@login_required
def resize_phone():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("number"), str) or not all(
        valid_layout_value(key, data.get(key)) for key in CARD_LAYOUT_LIMITS
    ):
        return jsonify(ok=False, error="Неверные размеры карточки."), 400
    number = normalize_number(data["number"])

    def resize(cards):
        if number not in cards:
            raise CardError("Номер не найден", 404)
        for key, (default, _) in CARD_LAYOUT_LIMITS.items():
            if data[key] == default:
                cards[number].pop(key, None)
            else:
                cards[number][key] = data[key]

    try:
        change_cards(session["username"], resize)
    except CardError as error:
        return jsonify(ok=False, error=str(error)), error.status
    return jsonify(ok=True)


@app.route("/reorder", methods=["POST"])
@login_required
def reorder():
    return edit_local_cards("phone.reorder")


@app.route("/")
@login_required
def panel():
    response = send_file("panel.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/favicon.ico")
def favicon():
    return redirect(url_for("static", filename="monitor.svg"), code=302)


@app.route("/user_info")
@login_required
def user_info():
    username = session.get("username")
    return jsonify({
        "username": username,
        "event_token": AUTH[username].get("event_token"),
        "is_admin": username == "admin",
        "server_role": ROLE,
    })


@app.route("/admin/users")
@login_required
def admin_users():
    username = session.get("username")
    if username != "admin":
        return jsonify({"ok": False, "error": "Доступ запрещен"}), 403
    
    users = []
    for uname, info in AUTH.items():
        users.append({
            "username": info.get("username"),
            "created_at": info.get("created_at"),
            "event_token": info.get("event_token")
        })
    return jsonify({"ok": True, "users": users})


# ── Общая библиотека карточек ─────────────────────────────────────────────────

def get_user_meta(username: str) -> dict:
    meta_file = PHONES_DIR / f"meta_{username}.json"
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"shared": False}


def save_user_meta(username: str, meta: dict) -> None:
    meta_file = PHONES_DIR / f"meta_{username}.json"
    write_local_json(meta_file, meta)


@app.route("/my_shared_status")
@login_required
def my_shared_status():
    username = session.get("username")
    meta = get_user_meta(username)
    return jsonify({"ok": True, "shared": meta.get("shared", False)})


@app.route("/shared_sets")
@login_required
def shared_sets():
    result = []
    for uname in AUTH.keys():
        meta = get_user_meta(uname)
        if not meta.get("shared"):
            continue
        with lock:
            phones = users_phones.get(uname, {})
            cards = [
                {"number": num, "name": p["name"], "ip": p["ip"]}
                for num, p in phones.items()
            ]
        result.append({
            "username": uname,
            "count": len(cards),
            "phones": cards,
        })
    return jsonify({"ok": True, "sets": result})


def set_shared_status(username, shared=None):
    with lock:
        meta = get_user_meta(username)
        previous = meta.get("shared", False)
        meta["shared"] = not previous if shared is None else shared
        if meta["shared"] == previous:
            return previous
        save_user_meta(username, meta)
    emit_updates("shared_sets_update", {}, {_library_room})
    return meta["shared"]


@app.route("/toggle_shared", methods=["POST"])
@login_required
def toggle_shared():
    return jsonify(ok=True, shared=set_shared_status(session["username"]))


def import_shared_cards(current_user, source):
    if not source or source not in AUTH:
        raise CardError("Пользователь не найден", 404)
    if source == current_user:
        raise CardError("Нельзя импортировать свой набор")

    def apply(target):
        if not get_user_meta(source).get("shared"):
            raise CardError("Набор не является общим", 403)
        imported = skipped = 0
        position = next_card_position(target)
        for number, phone in users_phones.get(source, {}).items():
            if number in target:
                skipped += 1
                continue
            target[number] = new_card(number, phone["name"], phone["ip"], position + imported)
            imported += 1
        return {"imported": imported, "skipped": skipped}

    return change_cards(current_user, apply)


@app.route("/import_set", methods=["POST"])
@login_required
def import_set():
    data = request.get_json(silent=True) or {}
    source = str(data.get("username", "")).strip()
    try:
        return jsonify(ok=True, **import_shared_cards(session["username"], source))
    except CardError as error:
        return jsonify(ok=False, error=str(error)), error.status


@app.route("/history")
@login_required
def get_history():
    username = session.get("username")
    number_filter = request.args.get("number", "").strip()
    date_filter   = request.args.get("date", "").strip()
    user_filter   = request.args.get("username", "").strip()  # только для admin
    page     = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 50)), 1), 200)
    limit    = per_page
    offset   = (page - 1) * per_page

    is_admin = (username == "admin")

    with lock:
        user_numbers = list(users_phones.get(username, {}).keys())

    conditions: list[str] = []
    params: list = []

    if not is_admin:
        if not user_numbers:
            return jsonify({"ok": True, "records": [], "total": 0})
        placeholders = ",".join("?" * len(user_numbers))
        conditions.append(f"local IN ({placeholders})")
        params.extend(user_numbers)
        conditions.append("username = ?")
        params.append(username)
    else:
        if user_filter:
            conditions.append("username = ?")
            params.append(user_filter)

    if number_filter:
        conditions.append("local = ?")
        params.append(number_filter)

    if date_filter:
        try:
            day_start = datetime.strptime(date_filter, "%Y-%m-%d")
            day_end   = day_start + timedelta(days=1)
            conditions.append("ts_start >= ? AND ts_start < ?")
            params.extend([day_start.timestamp(), day_end.timestamp()])
        except ValueError:
            pass

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        total = conn.execute(
            f"SELECT COUNT(*) FROM call_log {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM call_log {where} ORDER BY ts_start DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        conn.close()
        return jsonify({"ok": True, "records": [dict(r) for r in rows], "total": total})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def ping_once(ip: str):
    if not ip:
        return None

    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            cmd = ["ping", "-n", "1", "-w", "500", "-l", "1", ip]
            # вывод ping.exe — в OEM-кодировке консоли (cp866 на русской Windows)
            kwargs = {"creationflags": 0x08000000, "encoding": "oem"}  # CREATE_NO_WINDOW
        else:
            cmd = ["ping", "-c", "1", "-W", "1", "-s", "1", ip]
            kwargs = {}

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            **kwargs
        )

        if result.returncode != 0:
            return None

        # Windows отдаёт код 0 и на «Заданный узел недоступен» (ответ от своего IP).
        # Настоящий эхо-ответ всегда содержит TTL (TTL=64 / ttl=64).
        if not re.search(r"ttl[=:]", result.stdout, re.IGNORECASE):
            return None

        # Поиск времени ответа (RU/EN, Linux/Windows)
        match = re.search(r"(?:time|время)[=<]\s*(\d+)", result.stdout, re.IGNORECASE)
        if match:
            return int(match.group(1))

        return 1
    except Exception:
        return None


def expire_stuck_calls(now: float | None = None) -> bool:
    """Один проход watchdog. Блокировка номера совпадает с обработчиком /event."""
    now = time.time() if now is None else now

    def is_stuck(phone: dict) -> bool:
        started = phone.get("call_start")
        return phone.get("state") in STUCK_STATES and started is not None and now - started > STUCK_TIMEOUT

    with lock:
        candidates = {number for phones in users_phones.values() for number, phone in phones.items()
                      if is_stuck(phone)}
        candidates.update(number for number, call in pending_calls.items()
                          if "recover_until" in call and call["recover_until"] <= now)
        for key, ids in list(closed_call_ids.items()):
            remaining = {call_id: expires for call_id, expires in ids.items() if expires > now}
            if remaining:
                closed_call_ids[key] = remaining
            else:
                del closed_call_ids[key]

    owners = set()
    shared_numbers = set()
    for number in candidates:
        with number_lock(number), lock:
            call = _pending_call(number, now)
            for username, phones in users_phones.items():
                phone = phones.get(number)
                if phone is None or not is_stuck(phone):
                    continue
                rest = rest_state(number)
                state = phone["state"]
                alog("STATE_TIMEOUT", "WARNING", number=number, user=username, state=state,
                     stuck_seconds=int(now - phone["call_start"]),
                     msg=f"Состояние зависло >{STUCK_TIMEOUT}с, сброс в {rest}")
                if call and call["username"] == username and "recover_until" not in call:
                    call["recover_until"] = now + LATE_ANSWER_GRACE
                    call["recover_state"] = state
                flags = phone_flags.get(number, {})
                flags.pop("line2", None)
                flags["lines"] = 0
                phone.update(state=rest, call_start=None, peer="", duration="00:00")
                owners.add(username)
                if not conflicting_number(number):
                    shared_numbers.add(number)
    broadcast_update(owners | owners_of_numbers(shared_numbers))
    return bool(owners)


def apply_ping_result(username, number, ip_addr, latency):
    with lock:
        phone = users_phones.get(username, {}).get(number)
        if phone is None or phone.get("ip", "").strip() != ip_addr:
            return False

        old_ping = phone.get("ping")
        old_state = phone.get("state")
        if latency is None:
            phone["ping_fail_count"] = phone.get("ping_fail_count", 0) + 1
            phone["ping_ok_count"] = 0
            # Порог для индикации ping и для перехода в OFFLINE различается.
            if phone["ping_fail_count"] >= 2:
                phone["ping"] = "Недоступен"
            if phone["ping_fail_count"] >= 3 and old_state != "OFFLINE":
                journal_record("phone_reachability", phone_number=number, status="offline")
                alog("PING_OFFLINE", number=number, user=username, ip=ip_addr,
                     fail_count=phone["ping_fail_count"], prev_state=old_state)
                phone.update(state="OFFLINE", call_start=None, duration="00:00")
        else:
            phone["ping_fail_count"] = 0
            phone["ping_ok_count"] = phone.get("ping_ok_count", 0) + 1
            phone["ping"] = f"{latency} ms"
            if old_state == "OFFLINE" and phone["ping_ok_count"] >= 2:
                journal_record("phone_reachability", phone_number=number, status="online")
                alog("PING_RECOVERED", number=number, user=username, ip=ip_addr, latency_ms=latency)
                phone["state"] = "В_покое"

        ping_changed = phone.get("ping") != old_ping
        if ping_changed:
            alog("PING_CHANGE", number=number, user=username, old_ping=old_ping, new_ping=phone["ping"])
        return ping_changed or phone.get("state") != old_state


def flush_ping_updates():
    # Объединяем ответы пингов, пришедшие почти одновременно, без ожидания полного обхода.
    socketio.sleep(0.25)
    with _ping_update_lock:
        owners = _ping_update_users.copy()
        _ping_update_users.clear()
    broadcast_update(owners)


def ping_card(username, number, ip_addr):
    if not apply_ping_result(username, number, ip_addr, ping_once(ip_addr)):
        return
    with _ping_update_lock:
        start_flush = not _ping_update_users
        _ping_update_users.add(username)
    if start_flush:
        socketio.start_background_task(flush_ping_updates)


def ping_loop() -> None:
    # Увеличиваем число воркеров до 100 для масштабируемости.
    # Это позволяет обрабатывать сотни пингов одновременно, не блокируя мониторинг.
    executor = ThreadPoolExecutor(max_workers=100)
    
    while True:
        snapshot = []
        expire_stuck_calls()
        
        with lock:
            for username, phones in users_phones.items():
                for number, phone in phones.items():
                    ip_addr = phone.get("ip", "").strip()
                    if ip_addr:
                        snapshot.append((username, number, ip_addr))

        if snapshot:
            # Распределяем запуск процессов во времени (shaping), чтобы избежать пиков CPU.
            # Для 2000 телефонов размазываем запуск пачки на ~10 секунд.
            futures = []
            delay = 10.0 / len(snapshot) if len(snapshot) > 50 else 0
            
            for p in snapshot:
                futures.append(executor.submit(ping_card, *p))
                if delay > 0:
                    time.sleep(delay)
            
            for f in futures:
                try:
                    f.result()
                except Exception:
                    pass

        # Пауза перед следующим полным циклом мониторинга
        time.sleep(10)



def federation_admin():
    return authenticated_user() == "admin"


def federation_snapshot():
    with lock:
        phones = []
        for owner, cards in users_phones.items():
            for number, card in cards.items():
                flags = {} if conflicting_number(number) else phone_flags.get(number, {})
                phones.append({
                    "id": card["card_id"], "revision": card["revision"], "owner": owner, "number": number,
                    **{key: card.get(key) for key in ("name", "ip", "state", "peer", "call_start",
                                                     "position", "ping")},
                    "flags": {key: flags[key] for key in PUBLIC_FLAGS if key in flags},
                })
        return {
            "phones": phones,
            "users": [{"username": owner, "shared": get_user_meta(owner).get("shared", False)} for owner in AUTH],
            "recent_events": [
                {field: entry[field] for field in ("time", "label", "number", "user", "rejection") if field in entry}
                for entry in reversed(list(recent_events)[-100:]) if entry["known"]
            ],
        }


def find_federation_card(ref):
    card_id = ref.get("id")
    if not isinstance(card_id, str):
        raise CardError("Укажите идентификатор карточки.")
    with lock:
        for owner, cards in users_phones.items():
            if any(card.get("card_id") == card_id for card in cards.values()):
                number, card = resolve_card(cards, ref)
                return owner, number, card.copy()
    raise CardError("Карточка удалена на узле.", 409)


def execute_federation_command(command, link):
    action, data = command["action"], command["payload"]
    if action == "logs.read":
        if journal is None:
            return "failed", {"error": "Журнал на узле недоступен."}
        try:
            return "applied", journal.read(limit=data.get("limit", 100), before=data.get("before"))
        except JournalError as error:
            return "failed", {"error": str(error)}
    if action == "update.install":
        from federation_updates import UpdateDownloadError, UpdateError, execute_update
        from release_install import managed, update_public_key

        public_key = update_public_key(Path(__file__).resolve().parent, Path.cwd())
        if not public_key:
            raise FederationError("На узле не настроен ключ проверки обновлений.")
        try:
            result = execute_update(
                command, {**link, "token": link["node_token"]}, PHONES_DIR,
                public_key=public_key, executable=setting("FEDERATION_UPDATE_EXECUTOR") or None,
                opener=make_opener(link["tls_ca"]).open,
                managed_role=ROLE if managed() else None,
            )
        except UpdateDownloadError:
            return "running", {"error": "Загрузка прервана. Узел повторит запрос."}
        except UpdateError as error:
            return "failed", {"code": error.code, "error": str(error)}
        return result.pop("status"), result

    try:
        if action in {"phone.update", "phone.delete", "yealink.inspect"}:
            owner, number, card = find_federation_card(data)
        else:
            owner = data.get("owner")
            if not isinstance(owner, str) or owner not in AUTH:
                raise CardError("Пользователь не найден", 404)
        if action in {"phone.add", "phone.update", "phone.delete", "phone.reorder"}:
            return "applied", apply_card_change(action, owner, data, remote=True)
        if action == "set.toggle_shared":
            shared = data.get("shared")
            if type(shared) is not bool:
                raise CardError("Укажите состояние доступа к набору.")
            return "applied", {"shared": set_shared_status(owner, shared)}
        if action == "set.import":
            if not isinstance(data.get("source"), str):
                raise CardError("Укажите источник набора.")
            return "applied", import_shared_cards(owner, data["source"])
        if action == "action_url.events":
            return "applied", action_url_catalog(owner)
        if action == "yealink.inspect":
            with app.app_context():
                response = app.make_response(inspect_yealink_data({
                    "username": owner, "number": number, "ip": card["ip"],
                }))
                return ("applied" if response.status_code < 400 else "failed"), response.get_json()
        raise CardError("Неизвестная команда сервера.")
    except CardError as error:
        return ("conflict" if error.status == 409 else "failed"), {"error": str(error)}


node_sync = None
if ROLE == "node":
    from availability_probe import AvailabilityProbe
    from ping_trust import PingTrustFile

    poll_seconds = int(setting("FEDERATION_POLL_SECONDS", "5"))
    if not 1 <= poll_seconds <= 30:
        raise ValueError("FEDERATION_POLL_SECONDS должен быть от 1 до 30.")
    master_ip = setting("FEDERATION_MASTER_IP").strip()
    master_url = None
    if master_ip:
        address = ipaddress.ip_address(master_ip)
        host = str(address) if address.version == 4 else f"[{address}]"
        port = int(setting("FEDERATION_MASTER_PORT", "443"))
        if not 1 <= port <= 65535:
            raise ValueError("Неверный FEDERATION_MASTER_PORT.")
        master_url = f"https://{host}:{port}" if port != 443 else f"https://{host}"
    node_sync = NodeSync(DB_FILE, VERSION, federation_snapshot, execute_federation_command,
                         interval=poll_seconds, master_url=master_url,
                         availability_probe=AvailabilityProbe(ROLE),
                         ping_trust=PingTrustFile(Path("ping-trust.json")),
                         on_connection=lambda outcome: journal_record("federation_status", outcome=outcome))


@app.route("/federation")
@app.route("/node-link")
@login_required
def federation_panel():
    if ROLE == "standalone":
        return jsonify(ok=False, error="Подключение доступно на узле."), 404
    if not federation_admin():
        return jsonify(ok=False, error="Доступ запрещён."), 403
    response = send_file("node_link.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/federation/v1/node/link", methods=["GET", "POST"])
@app.route("/api/federation/v1/node/address", methods=["POST"])
def federation_node_settings():
    if node_sync is None:
        return jsonify(ok=False, error="Доступно на узле."), 404
    if not federation_admin():
        return jsonify(ok=False, error="Доступ запрещён."), 403
    if request.method == "GET":
        return jsonify(node_sync.status())
    if request.headers.get("Origin", request.host_url.rstrip("/")) != request.host_url.rstrip("/"):
        return jsonify(ok=False, error="Запрос с другого сайта."), 403
    if request.content_length is None or request.content_length > 150000:
        return jsonify(ok=False, error="Слишком большой запрос."), 413
    data = request.get_json(silent=True)
    try:
        if request.path.endswith("/address"):
            if not isinstance(data, dict):
                raise FederationError("Неверный формат адреса.")
            node_sync.change_address(data.get("url"), data.get("tls_ca"))
        else:
            node_sync.import_invitation(data)
    except FederationError as error:
        return jsonify(ok=False, error=str(error)), 400
    return jsonify(node_sync.status())


@app.route("/api/federation/v1/node/update", methods=["GET", "POST"])
def federation_node_update():
    if node_sync is None:
        return jsonify(ok=False, error="Доступно на узле."), 404
    if not federation_admin():
        return jsonify(ok=False, error="Доступ запрещён."), 403
    from release_install import managed, update_public_key

    enabled = managed() and bool(update_public_key(Path(__file__).resolve().parent, Path.cwd()))
    if request.method == "POST":
        if not enabled:
            return jsonify(ok=False, error="Автоматическая установка не настроена."), 409
        if request.content_length is None or request.content_length > 1024:
            return jsonify(ok=False, error="Неверный запрос."), 400
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(ok=False, error="Неверный запрос."), 400
        try:
            node_sync.request_update(data.get("package_id"))
        except FederationError as error:
            return jsonify(ok=False, error=str(error)), 409
    response = jsonify(ok=True, enabled=enabled, **node_sync.update_status())
    response.headers["Cache-Control"] = "no-store"
    return response


def main():
    alog("APP_START", version=VERSION, role=ROLE, log_file=str(LOG_FILE), db_file=str(DB_FILE),
         target_ip=(TARGET_IP or None) if ROLE == "standalone" else None)
    load_phones()
    init_db()
    threading.Thread(target=ping_loop, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    if node_sync:
        node_sync.import_at_startup(setting("FEDERATION_INVITATION"))
        node_sync.start()
    journal_record("service_started")
    alog("APP_READY", host=LISTEN_HOST, port=LISTEN_PORT, role=ROLE)
    try:
        if os.environ.get("INEI_UPDATE_READY"):
            from release_install import mark_ready
            from werkzeug.serving import make_server

            with make_server(LISTEN_HOST, LISTEN_PORT, app, threaded=True) as listener:
                mark_ready(VERSION, ROLE)
                listener.serve_forever()
            return
        socketio.run(app, host=LISTEN_HOST, port=LISTEN_PORT, debug=False, allow_unsafe_werkzeug=True)
    finally:
        if node_sync:
            node_sync.stop()


if __name__ == "__main__":
    main()
