"""Изолированный стенд: обычный мониторинг и три HTTP-телефона.

Обработчик /event не подменяется: каждое действие попадает в него по TCP.
Только ICMP виртуальных IP заменён состоянием питания устройства.
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from flask import jsonify, redirect, request, send_file, session
from werkzeug.security import generate_password_hash

from .engine import PhoneLab

ROOT = Path(__file__).resolve().parent.parent
MARKER = "monitoring-sip-phone-lab"


def default_data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    return base / "MonitoringSIP" / "phone-lab"


def prepare_data(path: Path) -> str:
    """Создать только собственные тестовые данные, не затрагивая рабочие."""
    path = path.resolve()
    if path == ROOT:
        raise ValueError("Каталог стенда должен отличаться от каталога программы")
    path.mkdir(parents=True, exist_ok=True)
    marker = path / "lab.json"
    if marker.exists():
        if json.loads(marker.read_text(encoding="utf-8")).get("kind") != MARKER:
            raise ValueError("Выбранный каталог не принадлежит стенду телефонов")
    elif any(path.iterdir()):
        raise ValueError("Для первого запуска нужен пустой каталог тестовых данных")
    marker.write_text(json.dumps({"kind": MARKER, "version": 1}), encoding="utf-8")
    token = secrets.token_hex(24)
    auth = {"admin": {"username": "admin", "password_hash": generate_password_hash(secrets.token_urlsafe(24)),
                      "created_at": time.strftime("%Y-%m-%d %H:%M:%S"), "event_token": token}}
    (path / "auth.json").write_text(json.dumps(auth), encoding="utf-8")
    (path / ".env").write_text(f"APP_SECRET_KEY={secrets.token_hex(32)}\nTARGET_IP=\n", encoding="utf-8")
    users = path / "users_data"
    users.mkdir(exist_ok=True)
    cards = [{"number": str(101 + i), "name": name, "ip": f"192.0.2.{101+i}", "position": i}
             for i, name in enumerate(("Приёмная", "Кабинет", "Переговорная"))]
    (users / "phones_admin.json").write_text(json.dumps(cards, ensure_ascii=False, indent=2), encoding="utf-8")
    return token


def create_lab(data_dir: Path, port: int):
    """Создать процесс стенда; порт должен соответствовать HTTP-серверу."""
    data_dir = data_dir.resolve()
    token = prepare_data(data_dir)
    # Процесс стенда не использует роль, подключение и доступ к телефонам узла.
    for key in tuple(os.environ):
        if key.startswith(("MONITORING_SIP_", "VICTORIA_", "FEDERATION_", "YEALINK_")):
            del os.environ[key]
    os.chdir(data_dir)
    module_name = "monitoring_sip_phone_lab_server"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "server.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Не найден server.py мониторинга")
    srv = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = srv
    spec.loader.exec_module(srv)
    srv.app.config.update(SESSION_COOKIE_NAME="sip_phone_lab_session", SESSION_COOKIE_SAMESITE="Strict")
    srv.TARGET_IP = ""
    srv.load_phones()
    srv.init_db()
    base_url = f"http://127.0.0.1:{port}"
    delivery = {"ok": True, "count": 0, "last": None, "error": ""}
    delivery_lock = threading.Lock()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def send_event(phone, event, remote="", call_id=""):
        params = {"token": token, "state": event, "local": phone["number"], "remote": remote,
                  "called_number": remote if event == "outgoing_call" else "",
                  "ip": phone["ip"], "mac": phone["mac"], "call_id": call_id,
                  "model": phone["model"], "firmware": phone["firmware"]}
        try:
            with opener.open(base_url + "/event?" + urllib.parse.urlencode(params), timeout=5) as response:
                if response.status != 200 or response.read().strip() != b"OK":
                    raise RuntimeError("Мониторинг не подтвердил событие")
            with delivery_lock:
                delivery.update(ok=True, count=delivery["count"] + 1,
                                last={"phone": phone["number"], "state": event}, error="")
        except (OSError, urllib.error.URLError, RuntimeError) as exc:
            with delivery_lock:
                delivery.update(ok=False, error="Не удалось передать событие мониторингу")
            raise RuntimeError("Не удалось передать событие мониторингу") from exc

    lab = PhoneLab(send_event)
    def lab_ping(ip):
        phone = next((p for p in lab.state()["phones"] if p["ip"] == ip), None)
        return 1 if phone and phone["power"] else None

    srv.ping_once = lab_ping

    @srv.app.before_request
    def lab_local_session():
        # Этот вход без пароля существует только в отдельном loopback-процессе.
        try:
            allowed = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            allowed = False
        hostname = urllib.parse.urlsplit(request.host_url).hostname
        if not allowed or hostname not in {"127.0.0.1", "localhost", "::1"}:
            return jsonify(ok=False, error="Стенд доступен только на этом компьютере"), 403
        if request.path == "/yealink/inspect":
            return jsonify(ok=False, error="Стенд работает только с виртуальными телефонами"), 403
        if request.path.startswith("/lab/api/") and request.method == "POST":
            origin = request.headers.get("Origin")
            if (origin and origin != request.host_url.rstrip("/")) or request.headers.get("Sec-Fetch-Site") == "cross-site":
                return jsonify(ok=False, error="Запрос должен исходить со страницы стенда"), 403
            if not request.is_json:
                return jsonify(ok=False, error="Ожидается JSON"), 400
        session["logged_in"] = True
        session["username"] = "admin"

    def snapshot():
        state = lab.state()
        state["lab"] = MARKER
        with delivery_lock:
            state["monitor"] = {**delivery, "version": srv.VERSION, "url": "/lab/monitor"}
        return state

    @srv.app.get("/lab")
    @srv.app.get("/lab/")
    def lab_page():
        return send_file(Path(__file__).with_name("index.html"))

    @srv.app.get("/lab/monitor")
    def lab_monitor():
        return redirect("/")

    @srv.app.get("/lab/api/state")
    def lab_state():
        return jsonify(snapshot())

    @srv.app.post("/lab/api/action")
    def lab_action():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(ok=False, error="Ожидается объект действия"), 400
        number, action = data.get("phone"), data.get("action")
        if not isinstance(number, str) or not isinstance(action, str):
            return jsonify(ok=False, error="Укажите телефон и действие"), 400
        try:
            lab.action(number, action, data.get("value"))
            return jsonify(snapshot())
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        except RuntimeError as exc:
            return jsonify(ok=False, error=str(exc)), 502

    action_url_events = {key: {"key": key, "ru": ru, "en": en} for key, ru, en in srv.ACTION_URL_EVENTS}

    @srv.app.get("/lab/api/action-url-events")
    def lab_action_url_events():
        return jsonify(events=list(action_url_events.values()))

    @srv.app.post("/lab/api/action-url-event")
    def lab_action_url_event():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) - {"phone", "event", "remote"}:
            return jsonify(ok=False, error="Укажите телефон и событие Action URL"), 400
        number, event, remote = data.get("phone"), data.get("event"), data.get("remote", "")
        if not all(isinstance(value, str) for value in (number, event, remote)) or event not in action_url_events:
            return jsonify(ok=False, error="Выберите событие из каталога Action URL"), 400
        try:
            lab.send_single_event(number, event, remote)
            return jsonify(snapshot())
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        except RuntimeError as exc:
            return jsonify(ok=False, error=str(exc)), 502

    @srv.app.post("/lab/api/reset")
    def lab_reset():
        try:
            lab.reset()
            return jsonify(snapshot())
        except RuntimeError as exc:
            return jsonify(ok=False, error=str(exc)), 502

    return srv, lab, base_url, send_event


class QuietRequests(logging.Filter):
    """Событийные URL содержат тестовый токен; не печатать query в консоль."""
    def filter(self, record):
        return " /event?" not in record.getMessage()


def main():
    parser = argparse.ArgumentParser(description="Три виртуальных Yealink и настоящий Monitoring SIP")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--open", action="store_true", help="Открыть телефоны в браузере")
    args = parser.parse_args()
    args.data_dir = args.data_dir.resolve()
    if not 1 <= args.port <= 65535:
        parser.error("Порт должен быть от 1 до 65535")
    # Проверить порт до создания/перезаписи тестовых данных.
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", args.port))
        except OSError:
            if args.open:
                try:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(f"http://127.0.0.1:{args.port}/lab/api/state", timeout=2) as response:
                        existing = json.load(response)
                    if existing.get("lab") == MARKER:
                        webbrowser.open(f"http://127.0.0.1:{args.port}/lab")
                        return 0
                except (OSError, ValueError, urllib.error.URLError):
                    pass
            print(f"Порт {args.port} занят. Выберите другой через --port.", file=sys.stderr)
            return 1
    srv, lab, base_url, send_event = create_lab(args.data_dir, args.port)
    logging.getLogger("werkzeug").addFilter(QuietRequests())
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    def started():
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            try:
                with opener.open(base_url + "/lab/api/state", timeout=1):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            return
        for phone in lab.state()["phones"]:
            for event in ("setup_completed", "registered", "busy_to_idle"):
                send_event(phone, event)
        threading.Thread(target=srv.ping_loop, daemon=True).start()
        threading.Thread(target=srv.cleanup_loop, daemon=True).start()
        if args.open:
            webbrowser.open(base_url + "/lab")

    threading.Thread(target=started, daemon=True).start()
    print(f"Телефоны: {base_url}/lab", flush=True)
    print(f"Мониторинг: {base_url}/lab/monitor", flush=True)
    print(f"Данные стенда: {args.data_dir.resolve()}", flush=True)
    srv.socketio.run(srv.app, host="127.0.0.1", port=args.port,
                     debug=False, allow_unsafe_werkzeug=True, use_reloader=False, log_output=False)


if __name__ == "__main__":
    raise SystemExit(main())
