"""Фикстуры: server.py импортируется в чистом временном каталоге.

server.py при импорте создаёт auth.json, .env и users_data/ относительно
текущего каталога — поэтому перед импортом уходим в tmp_path, иначе тесты
затрут боевые данные.
"""
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def srv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(ROOT))
    sys.modules.pop("server", None)
    server = importlib.import_module("server")

    # Не дублировать GET-запросы на боевой TARGET_IP
    monkeypatch.setattr(server, "TARGET_IP", server.LOCAL_IP)

    user = "admin"
    token = server.AUTH[user]["event_token"]
    phones = [
        {"number": "101", "name": "Приёмная", "ip": "10.0.0.11", "position": 0},
        {"number": "102", "name": "Начальник", "ip": "10.0.0.12", "position": 1},
    ]
    (server.PHONES_DIR / f"phones_{user}.json").write_text(
        json.dumps(phones, ensure_ascii=False), encoding="utf-8")
    server.load_phones()
    server.init_db()

    client = server.app.test_client()

    class Ctx:
        pass

    ctx = Ctx()
    ctx.server = server
    ctx.client = client
    ctx.token = token
    ctx.user = user

    def ev(state, local="101", as_token=None, headers=None, **params):
        q = {"token": as_token or token, "state": state, **params}
        if local is not None:
            q["local"] = local
        return client.get("/event", query_string=q, headers=headers or {})

    def add_user(name, phones):
        """Второй пользователь со своим набором карточек; возвращает его токен."""
        user_token = f"token-{name}"
        server.AUTH[name] = {"username": name, "password_hash": "-",
                             "event_token": user_token}
        server.users_phones[name] = {
            p["number"]: {"name": p["number"], "ip": p["ip"], "state": "В_покое",
                          "time": "-", "peer": "", "duration": "00:00",
                          "call_start": None, "ping": "?", "position": i}
            for i, p in enumerate(phones)
        }
        return user_token

    def phone(number="101"):
        return server.users_phones[user][number]

    def history():
        conn = server.sqlite3.connect(server.DB_FILE)
        rows = conn.execute(
            "SELECT local, remote, direction, duration FROM call_log ORDER BY id"
        ).fetchall()
        conn.close()
        return rows

    def age_call(number="101", seconds=10):
        """Сдвигает начало pending-звонка в прошлое (иначе < 3 c — не пишется)."""
        server.pending_calls[number]["ts_start"] -= seconds

    ctx.ev = ev
    ctx.add_user = add_user
    ctx.phone = phone
    ctx.history = history
    ctx.age_call = age_call

    yield ctx
    # Логгер глобальный: при следующем импорте добавится ещё один хендлер
    for h in list(server._raw_logger.handlers):
        server._raw_logger.removeHandler(h)
        h.close()
    sys.modules.pop("server", None)
