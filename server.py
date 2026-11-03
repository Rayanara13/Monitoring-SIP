from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_socketio import SocketIO
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
import traceback
import urllib.request
import urllib.parse
import ipaddress
from collections import deque
from pathlib import Path
from functools import wraps
from datetime import timedelta, datetime
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# allow_upgrades=True — используем WebSocket если доступен, иначе polling
# ping_timeout/ping_interval — агрессивное обнаружение потери соединения
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=25,
    ping_interval=10,
)

# Меняется с каждым выпуском: открытые панели сравнивают её с запомненной
# при первом подключении и предлагают перезагрузить страницу
VERSION = "Rel 1.1.1"

PHONES_DIR = Path("users_data")
AUTH_FILE = Path("auth.json")
ENV_FILE = Path(".env")
BLOCKS_FILE = Path("users_data/login_blocks.json")
DB_FILE = Path("users_data/call_history.db")
LOG_FILE = Path("users_data/app.log")

if not PHONES_DIR.exists():
    PHONES_DIR.mkdir()

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

# Rate-limit для /client_log: не более 120 записей в минуту с одного IP
_client_rate: dict = {}
CLIENT_LOG_RATE_LIMIT  = 120
CLIENT_LOG_RATE_WINDOW = 60

# ────────────────────────────────────────────────────────────────────────────

users_phones = {} # {username: {number: phone_data}}
pending_calls = {} # {local: {ts_start, direction, remote, username}}
phone_flags = {}   # {number: {dnd, fwd_*, mute, audio, reg, missed, ...}} — функции из Action URL
mac_numbers = {}   # {(username, mac): {number}} — выучено из событий с номером и $mac
recent_events = deque(maxlen=300)  # последние /event — журнал на вкладке «Тесты»
lock = threading.Lock()

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

API_AUTH_ROUTES = {"/phones", "/add_phone", "/update_phone", "/delete_phone", "/reorder"}


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


# Куда дублировать GET-запросы (центральный сервер). Только из .env, без адреса
# по умолчанию: не задан — дублирования нет
TARGET_IP = get_env_value("TARGET_IP", "")
TARGET_PORT = int(get_env_value("TARGET_PORT", "8000"))


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
    if request.method == "GET" and TARGET_IP and LOCAL_IP != TARGET_IP:
        duplicate_get_request(request.path, request.args.to_dict())

    # Логируем все входящие HTTP-запросы
    alog("HTTP_REQ",
         method=request.method,
         path=request.path,
         ip=get_client_ip(),
         user=session.get("username"),
         query=dict(request.args) or None)


@app.errorhandler(Exception)
def handle_exception(e):
    alog("UNHANDLED_EXCEPTION", "ERROR",
         error=str(e),
         traceback=traceback.format_exc(),
         path=request.path,
         method=request.method,
         ip=get_client_ip())
    return jsonify({"ok": False, "error": "Внутренняя ошибка сервера"}), 500


@socketio.on("connect")
def on_ws_connect():
    with _sids_lock:
        connected_sids.add(request.sid)
        total = len(connected_sids)
    alog("WS_CONNECT",
         sid=request.sid[:10],
         total_clients=total,
         ip=get_client_ip(),
         user=session.get("username"))
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

    AUTH_FILE.write_text(
        json.dumps(auth_data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

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
    with open(ENV_FILE, "a") as f:
        f.write(f"APP_SECRET_KEY={key}\n")
    return key


app.secret_key = get_app_secret()
app.permanent_session_lifetime = timedelta(hours=12)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # для локального HTTP оставляем False


def is_api_route(path: str) -> bool:
    return path in API_AUTH_ROUTES


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get("logged_in") is True:
            return view_func(*args, **kwargs)

        if is_api_route(request.path):
            return jsonify({"ok": False, "error": "Требуется авторизация"}), 401

        return redirect(url_for("login_page"))
    return wrapper


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
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
    conn.commit()
    conn.close()
    os.chmod(DB_FILE, 0o600)


def insert_call(ts_start: float, ts_end: float, duration: int,
                local: str, remote: str, direction: str, username: str) -> None:
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO call_log (ts_start,ts_end,duration,local,remote,direction,username)"
            " VALUES (?,?,?,?,?,?,?)",
            (ts_start, ts_end, duration, local, remote, direction, username)
        )
        conn.commit()
        conn.close()
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
        call = pending_calls.pop(user_phone, None)
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


def load_phones() -> None:
    global users_phones

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
        users_phones[username] = loaded
        alog("PHONES_LOADED", user=username, count=len(loaded),
             numbers=list(loaded.keys()))


def save_phones(username: str) -> None:
    with lock:
        if username not in users_phones:
            return
            
        phones = users_phones[username]
        arr = []
        for number, phone in phones.items():
            arr.append({
                "number": number,
                "name": phone["name"],
                "ip": phone["ip"],
                "position": int(phone.get("position", 0)),
            })

        arr.sort(key=lambda x: x["position"])
        user_file = PHONES_DIR / f"phones_{username}.json"
        user_file.write_text(
            json.dumps(arr, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )


def normalize_number(value: str | None) -> str:
    if value is None:
        return ""
    return str(value).strip()


def clean_remote(value: str | None) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if value.startswith("$"):
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


def broadcast_update(event_id: int | None = None):
    # Вызывается как из request-треда, так и из фонового ping_loop.
    # start_background_task гарантирует выполнение в eventlet green-thread контексте,
    # что надёжнее прямого emit из обычного threading.Thread.
    with _sids_lock:
        ws_clients = len(connected_sids)
    alog("BROADCAST_QUEUED", event_id=event_id, ws_clients=ws_clients)

    def _emit():
        try:
            # event_id в payload позволяет клиенту залогировать его на приём
            socketio.emit('phones_update',
                          {'data': 'updated', 'event_id': event_id},
                          namespace='/')
            alog("BROADCAST_EMIT", event_id=event_id, ws_clients=ws_clients)
        except Exception as e:
            alog("BROADCAST_ERROR", "ERROR", event_id=event_id, error=str(e))

    socketio.start_background_task(_emit)


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


def set_state(number: str, state: str, peer: str | None = None,
              event_id: int | None = None) -> None:
    found = False
    with lock:
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

    broadcast_update(event_id=event_id)


def get_sorted_phones(username: str) -> list[dict]:
    with lock:
        if username not in users_phones:
            return []
            
        phones = users_phones[username]
        result = []

        now = time.time()
        for number, phone in phones.items():
            entry = {"number": number, **phone}
            if phone.get("call_start") is not None:
                entry["duration_sec"] = int(now - phone["call_start"])
            flags = phone_flags.get(number, {})
            entry["flags"] = {k: flags[k] for k in PUBLIC_FLAGS if k in flags}
            result.append(entry)

    result.sort(key=lambda x: int(x["position"]))
    return result


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("logged_in") is True:
            return redirect(url_for("panel"))
        return send_file("login.html")

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    ip = get_client_ip()
    blocked, seconds_left = is_login_blocked(ip)
    if blocked:
        return jsonify({
            "ok": False,
            "error": f"Слишком много попыток. Повтори через {seconds_left} сек."
        }), 429

    if username in AUTH and check_password_hash(AUTH[username]["password_hash"], password):
        session.permanent = True
        session["logged_in"] = True
        session["username"] = username
        register_login_success(ip)
        alog("AUTH_LOGIN_OK", user=username, ip=ip)
        return jsonify({"ok": True})

    register_login_fail(ip)
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
        if mac:
            with lock:
                mac_numbers.setdefault((user, mac), set()).add(local)
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


def record_event(key: str | None, number: str, local: str, resolved_by: str,
                 remote: str, phone_ip: str, call_id: str, user: str,
                 details: dict | None = None) -> None:
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
        if number and label:
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

def start_call(number: str, direction: str, remote: str, user: str) -> bool:
    """Начинает учёт звонка. True — вторая линия поверх идущего звонка."""
    with lock:
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
        if not second or number not in pending_calls:
            pending_calls[number] = {
                "ts_start": time.time(),
                "direction": direction,
                "remote": remote,
                "username": user,
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
        broadcast_update(event_id=event_id)
    elif line2:
        # Вторая линия так и не ответила — карточка остаётся на первой
        set_state(number, line2["state"], line2["peer"] or None, event_id=event_id)
    else:
        # Обе линии были в разговоре: оставшаяся ждёт «Возврат»
        set_state(number, "Удержание", event_id=event_id)


def end_attempt(number: str, event_id: int, expect: set[str],
                show: str | None = None) -> None:
    """Неудачная попытка вызова (отбой, занято, отмена, пропущен, переадресован).

    Была вторая линия — возвращаем карточку к первой. Иначе завершаем, только
    если карточка в ожидаемом состоянии попытки: событие от линии, которой мы не
    видели, не должно ронять идущий разговор.
    """
    with lock:
        flags = phone_flags.setdefault(number, {})
        line2 = flags.pop("line2", None)
        if line2:
            flags["lines"] = max(1, flags.get("lines", 1) - 1)
        cur = current_state(number)
    if line2:
        set_state(number, line2["state"], line2["peer"] or None, event_id=event_id)
    elif cur in expect:
        if show:
            # pending живёт до отбоя трубки — иначе On Hook не найдёт звонок
            set_state(number, show, event_id=event_id)
        else:
            end_call(number, event_id, quiet=True)
    else:
        broadcast_update(event_id=event_id)


# ── Обработчики: handler(number, remote, phone_ip, user, event_id) ──

def _ev_outgoing(n, remote, ip, user, eid):
    if start_call(n, "out", remote, user):
        alog("SIP_SECOND_LINE", event_id=eid, number=n, remote=remote, direction="out")
    set_state(n, "Исходящий_вызов", remote, event_id=eid)


def _ev_incoming(n, remote, ip, user, eid):
    if start_call(n, "in", remote, user):
        # Второй входящий поверх звонка: карточку не трогаем, иначе после
        # отбоя звонящего watchdog сбросил бы идущий разговор в покой
        alog("SIP_SECOND_LINE", event_id=eid, number=n, remote=remote, direction="in")
        broadcast_update(event_id=eid)
        return
    set_state(n, "Входящий_вызов", remote, event_id=eid)


def _connect(n, remote, user, eid, direction=None):
    # Если remote пустой — сохраняем peer из предыдущего состояния (Ringing/Setup)
    if not remote:
        with lock:
            phone = find_phone(n)
            remote = (phone.get("peer") or "") if phone else ""
        if remote:
            alog("SIP_PEER_PRESERVED", event_id=eid, number=n, peer=remote)
    with lock:
        flags = phone_flags.setdefault(n, {})
        flags.pop("line2", None)  # вторая линия ответила — возвращать некуда
        if n in pending_calls:
            # При нескольких линиях pending принадлежит первой — собеседника не меняем
            if remote and flags.get("lines", 0) <= 1:
                pending_calls[n]["remote"] = remote
        elif direction:
            flags["lines"] = 1
            pending_calls[n] = {
                "ts_start": time.time(),
                "direction": direction,
                "remote": remote,
                "username": user,
            }
    set_state(n, "Разговор", remote, event_id=eid)


def _ev_established(n, remote, ip, user, eid):
    _connect(n, remote, user, eid)


def _ev_answer_new(n, remote, ip, user, eid):
    _connect(n, remote, user, eid, direction="in")


def _ev_terminated(n, remote, ip, user, eid):
    end_line(n, eid)


def _ev_on_hook(n, remote, ip, user, eid):
    end_line(n, eid, ignore_if_multi=True)


def _ev_busy_to_idle(n, remote, ip, user, eid):
    # Телефон целиком свободен — все линии кончились
    with lock:
        phone_flags.setdefault(n, {})["busy_to_idle_seen"] = True
    end_call(n, eid, quiet=True)


def _ev_call_end_quiet(n, remote, ip, user, eid):
    end_call(n, eid, quiet=True)


def _ev_off_hook(n, remote, ip, user, eid):
    with lock:
        in_call = n in pending_calls
        cur = current_state(n)
    if cur == "Входящий_вызов":
        # Трубку сняли, пока звонит, — это ответ (Established может не прийти)
        _connect(n, remote, user, eid)
    elif in_call:
        # Если звонок уже идёт (громкая → трубка) — игнорируем OffHook,
        # чтобы не сбить состояние "Разговор" / "Удержание"
        alog("SIP_OFFHOOK_IGNORED", event_id=eid, number=n, reason="active_call")
        broadcast_update(event_id=eid)
    else:
        set_state(n, "Снята_трубка", event_id=eid)


def _ev_idle_to_busy(n, remote, ip, user, eid):
    # Подробности (трубка, вызов) приносят другие события; «Занят» — только если
    # кроме этого события ничего не пришло
    with lock:
        cur = current_state(n)
    if cur in ("В_покое", "DND"):
        set_state(n, "Занят", event_id=eid)
    else:
        broadcast_update(event_id=eid)


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
        end_attempt(n, eid, expect, show)
    return handler


def _flag_ev(name, value):
    def handler(n, remote, ip, user, eid):
        with lock:
            phone_flags.setdefault(n, {})[name] = value
        broadcast_update(event_id=eid)
    return handler


def _audio_ev(value):
    def handler(n, remote, ip, user, eid):
        with lock:
            phone_flags.setdefault(n, {})["audio"] = value
            cur = current_state(n)
        if cur == "Входящий_вызов":
            # Ответили кнопкой громкой связи / гарнитуры, не снимая трубку:
            # Established на части телефонов при этом не приходит
            _connect(n, remote, user, eid)
        else:
            broadcast_update(event_id=eid)
    return handler


def _info_ev(n, remote, ip, user, eid):
    broadcast_update(event_id=eid)


def _dnd_on(n, eid, sticky):
    with lock:
        flags = phone_flags.setdefault(n, {})
        flags["dnd"] = True
        flags["dnd_sticky"] = sticky
        cur = current_state(n)
    if cur in ACTIVE_STATES:
        broadcast_update(event_id=eid)  # во время звонка — только значок
    else:
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
    else:
        broadcast_update(event_id=eid)


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
        else:
            broadcast_update(event_id=eid)
    return handler


def _ev_ip_change(n, remote, ip, user, eid):
    """Новый IP телефона — в карточку владельца токена, иначе пинг уведёт её в OFFLINE.
    Чужие наборы не трогаем: токен одного набора не даёт права писать в другой."""
    if not ip:
        alog("SIP_IP_CHANGE_NO_IP", "WARNING", event_id=eid, number=n,
             msg="Нет параметра ip=$ip — карточка не обновлена")
        broadcast_update(event_id=eid)
        return
    with lock:
        phone = users_phones.get(user, {}).get(n)
        old_ip = phone.get("ip") if phone else None
        changed = phone is not None and old_ip != ip
        if changed:
            phone["ip"] = ip
    if changed:
        save_phones(user)
        alog("PHONE_IP_CHANGED", event_id=eid, number=n, user=user,
             old_ip=old_ip, new_ip=ip)
    elif phone is None:
        alog("SIP_IP_CHANGE_NOT_OWNED", "WARNING", event_id=eid, number=n, user=user,
             msg="Номера нет в наборе владельца токена — IP не обновлён")
    broadcast_update(event_id=eid)


def _ev_vpn_ip(n, remote, ip, user, eid):
    with lock:
        phone_flags.setdefault(n, {})["vpn_ip"] = ip
    broadcast_update(event_id=eid)


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
        alog("SIP_RATE_LIMITED", "WARNING", ip=client_ip)
        return "Too Many Requests", 429

    token = request.args.get("token")
    # Проверяем токен у любого пользователя
    target_user = None
    for user_info in AUTH.values():
        if user_info.get("event_token") == token:
            target_user = user_info["username"]
            break

    if not target_user:
        alog("SIP_BAD_TOKEN", "WARNING",
             ip=client_ip,
             token_prefix=token[:6] if token else None)
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
    # $call_id пока только в журнал/лог: по живым трассам решим, различает ли он линии
    call_id = str(request.args.get("call_id") or "").strip()[:100]
    if call_id.startswith("$"):
        call_id = ""
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

        record_event(key, user_phone, local, resolved_by, remote, phone_ip, call_id,
                     target_user, details)

        if not user_phone:
            alog("SIP_NO_LOCAL", "WARNING", event_id=evt_id, state=state, user=target_user)
            return "OK"

        # Проверяем наличие номера в карточках
        with lock:
            phone_registered = (
                target_user in users_phones and
                user_phone in users_phones[target_user]
            )
        if not phone_registered:
            alog("SIP_PHONE_NOT_IN_CARDS", "WARNING",
                 event_id=evt_id,
                 number=user_phone,
                 user=target_user,
                 msg="Событие пришло для номера, которого нет в карточках пользователя")

        handler = LEGACY_HANDLERS.get(state) or EVENT_HANDLERS.get(key)
        if handler is None:
            alog("SIP_UNKNOWN_STATE", "WARNING",
                 event_id=evt_id, state=state, number=user_phone, user=target_user)
            return "OK"

        handler(user_phone, remote, phone_ip, target_user, evt_id)
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
    return jsonify({
        "server_ip": LOCAL_IP,  # если панель открыта как localhost — телефонам нужен LAN-IP
        "phones": phones,
        "events": [
            {"key": k, "ru": ru, "en": en, "aliases": aliases.get(k, []),
             "parameter": ACTION_URL_PARAMETERS[k]}
            for k, ru, en in ACTION_URL_EVENTS
        ],
    })


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
    return jsonify({"phones": phones})


@app.route("/add_phone", methods=["POST"])
@login_required
def add_phone():
    username = session.get("username")
    data = request.get_json(force=True)

    number = normalize_number(data.get("number"))
    name = normalize_number(data.get("name"))
    ip = normalize_number(data.get("ip"))

    if not number:
        return jsonify({"ok": False, "error": "Не указан номер"}), 400

    with lock:
        if username not in users_phones:
            users_phones[username] = {}
            
        if number in users_phones[username]:
            return jsonify({"ok": False, "error": "Такой номер уже существует"}), 400

        next_position = len(users_phones[username])
        users_phones[username][number] = {
            "name": name or number,
            "ip": ip,
            "state": "В_покое",
            "time": "-",
            "peer": "",
            "duration": "00:00",
            "call_start": None,
            "ping": "?",
            "position": next_position,
        }

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/update_phone", methods=["POST"])
@login_required
def update_phone():
    username = session.get("username")
    data = request.get_json(force=True)

    old_number = normalize_number(data.get("old_number") or data.get("number"))
    new_number = normalize_number(data.get("number"))
    name = normalize_number(data.get("name"))
    ip = normalize_number(data.get("ip"))

    if not new_number:
        return jsonify({"ok": False, "error": "Номер не может быть пустым"}), 400

    with lock:
        if username not in users_phones or old_number not in users_phones[username]:
            return jsonify({"ok": False, "error": "Номер не найден"}), 404

        if new_number != old_number and new_number in users_phones[username]:
            return jsonify({"ok": False, "error": "Такой номер уже существует"}), 400

        phone = users_phones[username].pop(old_number)
        phone["name"] = name or new_number
        phone["ip"] = ip
        users_phones[username][new_number] = phone

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/delete_phone", methods=["POST"])
@login_required
def delete_phone():
    username = session.get("username")
    data = request.get_json(force=True)
    number = normalize_number(data.get("number"))

    with lock:
        if username in users_phones and number in users_phones[username]:
            del users_phones[username][number]

            ordered_numbers = sorted(
                users_phones[username].keys(),
                key=lambda n: int(users_phones[username][n]["position"])
            )
            for idx, num in enumerate(ordered_numbers):
                users_phones[username][num]["position"] = idx

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/reorder", methods=["POST"])
@login_required
def reorder():
    username = session.get("username")
    order = request.get_json(force=True)

    if not isinstance(order, list):
        return jsonify({"ok": False, "error": "Неверный формат"}), 400

    with lock:
        if username not in users_phones:
            return jsonify({"ok": False, "error": "Пользователь не найден"}), 404
            
        for idx, number in enumerate(order):
            number = str(number)
            if number in users_phones[username]:
                users_phones[username][number]["position"] = idx

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/")
@login_required
def panel():
    response = send_file("panel.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/favicon.ico")
def favicon():
    return "OK", 200, {"Content-Type": "image/x-icon"}


@app.route("/user_info")
@login_required
def user_info():
    username = session.get("username")
    return jsonify({
        "username": username,
        "event_token": AUTH[username].get("event_token"),
        "is_admin": username == "admin"
    })


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_file(Path("static") / filename)


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
    meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


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


@app.route("/toggle_shared", methods=["POST"])
@login_required
def toggle_shared():
    username = session.get("username")
    meta = get_user_meta(username)
    meta["shared"] = not meta.get("shared", False)
    save_user_meta(username, meta)
    return jsonify({"ok": True, "shared": meta["shared"]})


@app.route("/import_set", methods=["POST"])
@login_required
def import_set():
    current_user = session.get("username")
    data = request.get_json(silent=True) or {}
    source = str(data.get("username", "")).strip()

    if not source or source not in AUTH:
        return jsonify({"ok": False, "error": "Пользователь не найден"}), 404

    if source == current_user:
        return jsonify({"ok": False, "error": "Нельзя импортировать свой набор"}), 400

    meta = get_user_meta(source)
    if not meta.get("shared"):
        return jsonify({"ok": False, "error": "Набор не является общим"}), 403

    imported = 0
    skipped = 0

    with lock:
        source_phones = users_phones.get(source, {})
        if current_user not in users_phones:
            users_phones[current_user] = {}
        target = users_phones[current_user]
        next_pos = len(target)

        for number, phone in source_phones.items():
            if number in target:
                skipped += 1
                continue
            target[number] = {
                "name": phone["name"],
                "ip": phone["ip"],
                "state": "В_покое",
                "time": "-",
                "peer": "",
                "duration": "00:00",
                "call_start": None,
                "ping": "?",
                "position": next_pos,
            }
            next_pos += 1
            imported += 1

    if imported:
        save_phones(current_user)
        broadcast_update()

    return jsonify({"ok": True, "imported": imported, "skipped": skipped})


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


def ping_loop() -> None:
    # Увеличиваем число воркеров до 100 для масштабируемости.
    # Это позволяет обрабатывать сотни пингов одновременно, не блокируя мониторинг.
    executor = ThreadPoolExecutor(max_workers=100)
    
    while True:
        snapshot = []
        now = time.time()
        any_changed = False
        
        with lock:
            for username, phones in users_phones.items():
                for number, phone in phones.items():
                    # Очистка зависших состояний STUCK_STATES (таймаут 60 сек)
                    if phone.get("state") in STUCK_STATES and phone.get("call_start"):
                        if now - phone["call_start"] > 60:
                            rest = rest_state(number)
                            alog("STATE_TIMEOUT", "WARNING",
                                 number=number, user=username,
                                 state=phone["state"],
                                 stuck_seconds=int(now - phone["call_start"]),
                                 msg=f"Состояние зависло >60с, сброс в {rest}")
                            flags = phone_flags.get(number, {})
                            flags.pop("line2", None)
                            flags["lines"] = 0
                            phone["state"] = rest
                            phone["call_start"] = None
                            phone["peer"] = ""
                            phone["duration"] = "00:00"
                            any_changed = True
                    
                    ip_addr = phone.get("ip", "").strip()
                    if ip_addr:
                        snapshot.append((username, number, ip_addr))

        def task(uname, num, ip_addr):
            latency = ping_once(ip_addr)
            with lock:
                if uname not in users_phones or num not in users_phones[uname]:
                    return False
                
                phone = users_phones[uname][num]
                old_ping = phone.get("ping")
                old_state = phone.get("state")

                if latency is None:
                    phone["ping_fail_count"] = phone.get("ping_fail_count", 0) + 1
                    phone["ping_ok_count"] = 0
                    # Показываем "Недоступен" только после 2 подряд неудач (~20с),
                    # чтобы убрать мигания при кратковременных потерях пакетов
                    if phone["ping_fail_count"] >= 2:
                        phone["ping"] = "Недоступен"
                    if phone["ping_fail_count"] >= 3 and old_state != "OFFLINE":
                        alog("PING_OFFLINE",
                             number=num, user=uname, ip=ip_addr,
                             fail_count=phone["ping_fail_count"],
                             prev_state=old_state)
                        phone["state"] = "OFFLINE"
                        phone["call_start"] = None
                        phone["duration"] = "00:00"
                else:
                    phone["ping_fail_count"] = 0
                    phone["ping_ok_count"] = phone.get("ping_ok_count", 0) + 1
                    phone["ping"] = f"{latency} ms"
                    # Восстанавливаем из OFFLINE только после 2 подряд успехов (~20с),
                    # чтобы не прыгать обратно при случайном единичном пакете
                    if phone["state"] == "OFFLINE" and phone["ping_ok_count"] >= 2:
                        alog("PING_RECOVERED",
                             number=num, user=uname, ip=ip_addr, latency_ms=latency)
                        phone["state"] = "В_покое"

                changed = phone.get("ping") != old_ping or phone.get("state") != old_state
                if changed and phone.get("ping") != old_ping:
                    alog("PING_CHANGE",
                         number=num, user=uname,
                         old_ping=old_ping, new_ping=phone["ping"])
                return changed

        if snapshot:
            # Распределяем запуск процессов во времени (shaping), чтобы избежать пиков CPU.
            # Для 2000 телефонов размазываем запуск пачки на ~10 секунд.
            futures = []
            delay = 10.0 / len(snapshot) if len(snapshot) > 50 else 0
            
            for p in snapshot:
                futures.append(executor.submit(task, *p))
                if delay > 0:
                    time.sleep(delay)
            
            # Собираем результаты и проверяем наличие изменений
            for f in futures:
                try:
                    if f.result():
                        any_changed = True
                except Exception:
                    pass

        if any_changed:
            broadcast_update()

        # Пауза перед следующим полным циклом мониторинга
        time.sleep(10)



if __name__ == "__main__":
    alog("APP_START", version=VERSION,
         log_file=str(LOG_FILE),
         db_file=str(DB_FILE),
         target_ip=TARGET_IP or None)  # None = дублирование выключено
    load_phones()
    init_db()
    threading.Thread(target=ping_loop,     daemon=True).start()
    threading.Thread(target=cleanup_loop,  daemon=True).start()
    alog("APP_READY", host="0.0.0.0", port=8000)
    socketio.run(app, host="0.0.0.0", port=8000, debug=False, allow_unsafe_werkzeug=True)