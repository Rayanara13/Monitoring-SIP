"""Все поля страницы «Функции → Action URL» Yealink."""
import json


def flags(srv, number="101"):
    with srv.client.session_transaction() as s:
        s["logged_in"] = True
        s["username"] = srv.user
    phones = srv.client.get("/phones").get_json()["phones"]
    return next(p for p in phones if p["number"] == number)["flags"]


def login(srv):
    with srv.client.session_transaction() as s:
        s["logged_in"] = True
        s["username"] = srv.user


# ── каталог ──

def test_catalog_has_all_48_fields_in_page_order(srv):
    login(srv)
    events = srv.client.get("/action_url_events").get_json()["events"]
    assert len(events) == 48
    assert events[0]["ru"] == "Настройка завершена"
    assert events[-1]["ru"] == "Конференция с"
    by_key = {e["key"]: e for e in events}
    assert by_key["outgoing_call"]["aliases"] == ["Setup"]
    assert by_key["call_terminated"]["aliases"] == ["Idle"]


def test_every_event_accepted(srv):
    login(srv)
    for e in srv.client.get("/action_url_events").get_json()["events"]:
        r = srv.ev(e["key"], remote="200", ip="10.0.0.11")
        assert r.status_code == 200, e["key"]
        assert r.data == b"OK"


# ── звонки ──

def test_hold_unhold_keeps_peer(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("hold")
    srv.ev("unhold")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "300"


def test_transfer_failed_then_finished(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("blind_transfer_call", remote="555")
    assert srv.phone()["state"] == "Перевод_вызова"
    assert srv.phone()["peer"] == "300"
    srv.ev("transfer_failed")
    assert srv.phone()["state"] == "Разговор"
    srv.ev("attended_transfer_call")
    srv.age_call()
    srv.ev("transfer_finished")
    assert srv.phone()["state"] == "В_покое"
    assert srv.history() == [("101", "300", "in", 10)]
    srv.ev("call_terminated")          # пришёл следом — без дубля в истории
    assert len(srv.history()) == 1


def test_conference(srv):
    srv.ev("outgoing_call", remote="200")
    srv.ev("call_established")
    srv.ev("conference", remote="400")
    assert srv.phone()["state"] == "Конференция"
    assert srv.phone()["peer"] == "200"


def test_second_incoming_during_talk_does_not_touch_card(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.age_call(seconds=20)
    srv.ev("incoming_call", remote="777")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "300"
    srv.ev("call_remote_canceled")     # второй звонящий бросил
    assert srv.phone()["state"] == "Разговор"
    srv.ev("missed_call")              # и пропущенный — разговор не роняет
    assert srv.phone()["state"] == "Разговор"
    assert flags(srv)["missed"] == 1
    srv.ev("call_terminated")
    assert srv.history() == [("101", "300", "in", 20)]


def test_consult_call_busy_returns_to_hold(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("hold")
    srv.ev("outgoing_call", remote="555")
    assert srv.phone()["state"] == "Исходящий_вызов"
    srv.ev("remote_busy")
    assert srv.phone()["state"] == "Удержание"
    assert srv.phone()["peer"] == "300"


def test_answer_new_without_busy_to_idle_ends_all_on_terminated(srv):
    """Телефон не шлёт Busy To Idle — Terminated, как раньше, завершает всё:
    лучше рано уйти в покой, чем навсегда застрять в «Удержании»."""
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("incoming_call", remote="777")
    srv.ev("answer_new_incoming_call", remote="777")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "777"
    srv.age_call()
    srv.ev("call_terminated")
    assert srv.phone()["state"] == "В_покое"
    assert srv.history() == [("101", "300", "in", 10)]   # одна запись — сессия


def test_legacy_call_waiting_does_not_stick(srv):
    """Старая настройка: второй звонящий бросил молча — Idle всё равно в покой."""
    srv.ev("Ringing", remote="300")
    srv.ev("Connected")
    srv.ev("Ringing", remote="777")
    assert srv.phone()["state"] == "Разговор"
    srv.ev("Idle")
    assert srv.phone()["state"] == "В_покое"


# ── несколько линий (телефон шлёт Busy To Idle) ──

def test_multiline_terminated_keeps_held_call(srv):
    srv.ev("busy_to_idle")                       # телефон умеет Busy To Idle
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.age_call(seconds=20)
    srv.ev("incoming_call", remote="777")
    assert flags(srv)["lines"] == 2
    srv.ev("answer_new_incoming_call", remote="777")
    srv.ev("call_terminated")                    # кончилась одна из линий
    assert srv.phone()["state"] == "Удержание"
    assert srv.history() == []
    srv.ev("unhold", remote="300")
    assert srv.phone()["state"] == "Разговор"
    srv.ev("busy_to_idle")                       # телефон свободен целиком
    assert srv.phone()["state"] == "В_покое"
    assert srv.history() == [("101", "300", "in", 20)]


def test_multiline_unanswered_second_line_terminated(srv):
    srv.ev("busy_to_idle")
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("incoming_call", remote="777")
    srv.ev("call_terminated")                    # второй звонящий бросил
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "300"
    assert flags(srv)["lines"] == 1


def test_multiline_on_hook_ignored(srv):
    srv.ev("busy_to_idle")
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("incoming_call", remote="777")
    srv.ev("on_hook")
    assert srv.phone()["state"] == "Разговор"
    assert flags(srv)["lines"] == 2


# ── ответ без снятия трубки ──

def test_speaker_answer_without_established(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("handfree")                           # ответили кнопкой громкой связи
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "300"
    assert flags(srv)["audio"] == "handsfree"
    srv.ev("call_established")                   # если всё же пришло — без вреда
    assert srv.phone()["state"] == "Разговор"
    srv.age_call()
    srv.ev("call_terminated")
    assert srv.history() == [("101", "300", "in", 10)]


def test_headset_answer(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("headset")
    assert srv.phone()["state"] == "Разговор"


def test_offhook_during_ringing_answers(srv):
    srv.ev("Ringing", remote="300")
    srv.ev("OffHook")
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "300"
    srv.age_call()
    srv.ev("OnHook")
    assert srv.history() == [("101", "300", "in", 10)]


def test_handfree_when_idle_only_flag(srv):
    srv.ev("handfree")
    assert srv.phone()["state"] == "В_покое"
    assert flags(srv)["audio"] == "handsfree"


def test_remote_busy_keeps_pending_until_on_hook(srv):
    srv.ev("outgoing_call", remote="200")
    srv.age_call()
    srv.ev("remote_busy")
    assert srv.server.pending_calls.get("101") is not None
    srv.ev("on_hook")
    assert srv.history() == [("101", "200", "out", 10)]


def test_answer_new_without_ringing_starts_call(srv):
    srv.ev("answer_new_incoming_call", remote="777")
    assert srv.phone()["state"] == "Разговор"
    srv.age_call()
    srv.ev("busy_to_idle")
    assert srv.history() == [("101", "777", "in", 10)]


def test_remote_busy_first_line(srv):
    srv.ev("outgoing_call", remote="200")
    srv.ev("remote_busy")
    assert srv.phone()["state"] == "Абонент_занят"
    assert srv.phone()["peer"] == "200"
    srv.ev("on_hook")
    assert srv.phone()["state"] == "В_покое"


def test_cancel_and_reject(srv):
    srv.ev("outgoing_call", remote="200")
    srv.ev("cancel_callout")
    assert srv.phone()["state"] == "В_покое"
    srv.ev("incoming_call", remote="300")
    srv.ev("reject_incoming_call")
    assert srv.phone()["state"] == "В_покое"


def test_cancel_ignored_when_not_dialing(srv):
    srv.ev("off_hook")
    srv.ev("cancel_callout")
    assert srv.phone()["state"] == "Снята_трубка"


def test_missed_and_forwarded_counters(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("missed_call")
    assert srv.phone()["state"] == "В_покое"
    srv.ev("missed_call")
    srv.ev("forward_incoming_call")
    f = flags(srv)
    assert (f["missed"], f["forwarded"]) == (2, 1)
    srv.ev("view_missed_call")
    srv.ev("view_forwarded_call")
    f = flags(srv)
    assert (f["missed"], f["forwarded"]) == (0, 0)


def test_forwarded_call_does_not_drop_dialing(srv):
    srv.ev("off_hook")
    srv.ev("forward_incoming_call")
    assert srv.phone()["state"] == "Снята_трубка"


def test_idle_busy_pair(srv):
    srv.ev("idle_to_busy")
    assert srv.phone()["state"] == "Занят"
    srv.ev("off_hook")
    assert srv.phone()["state"] == "Снята_трубка"
    srv.ev("busy_to_idle")
    assert srv.phone()["state"] == "В_покое"


def test_idle_to_busy_does_not_override_details(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("idle_to_busy")
    assert srv.phone()["state"] == "Входящий_вызов"


def test_setup_completed_resets_stale_call(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("setup_completed")
    assert srv.phone()["state"] == "В_покое"


# ── функции телефона ──

def test_dnd_on_off(srv):
    srv.ev("dnd_on")
    assert srv.phone()["state"] == "DND"
    assert flags(srv)["dnd"] is True
    srv.ev("dnd_off")
    assert srv.phone()["state"] == "В_покое"
    assert flags(srv)["dnd"] is False


def test_dnd_sticky_once_off_event_seen(srv):
    srv.ev("dnd_off")                  # телефон настроен и на «Отключение DND»
    srv.ev("dnd_on")
    srv.ev("outgoing_call", remote="200")
    srv.ev("call_established")
    srv.ev("call_terminated")
    assert srv.phone()["state"] == "DND"


def test_legacy_dnd_not_sticky_even_after_dnd_off(srv):
    """Старый state=DND гаснет с концом звонка, что бы ни приходило раньше."""
    srv.ev("dnd_off")
    srv.ev("DND")
    srv.ev("Idle")
    assert srv.phone()["state"] == "В_покое"


def test_dnd_during_call_only_flag(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("dnd_on")
    assert srv.phone()["state"] == "Разговор"
    assert flags(srv)["dnd"] is True


def test_forward_flags(srv):
    srv.ev("always_fwd_on")
    srv.ev("busy_fwd_on")
    srv.ev("no_answer_fwd_on")
    srv.ev("busy_fwd_off")
    f = flags(srv)
    assert (f["fwd_always"], f["fwd_busy"], f["fwd_noanswer"]) == (True, False, True)
    assert srv.phone()["state"] == "В_покое"


def test_mute_and_audio_reset_on_call_end(srv):
    srv.ev("incoming_call", remote="300")
    srv.ev("call_established")
    srv.ev("mute")
    srv.ev("headset")
    f = flags(srv)
    assert (f["mute"], f["audio"]) == (True, "headset")
    srv.ev("handfree")
    assert flags(srv)["audio"] == "handsfree"
    srv.ev("unmute")
    assert flags(srv)["mute"] is False
    srv.ev("mute")
    srv.ev("call_terminated")
    f = flags(srv)
    assert (f["mute"], f["audio"]) == (False, None)


def test_call_waiting_flag(srv):
    srv.ev("call_waiting_off")
    assert flags(srv)["call_waiting"] is False
    srv.ev("call_waiting_on")
    assert flags(srv)["call_waiting"] is True


def test_registration(srv):
    srv.ev("register_failed")
    assert srv.phone()["state"] == "Нет_регистрации"
    assert flags(srv)["reg"] == "fail"
    srv.ev("registered")
    assert srv.phone()["state"] == "В_покое"
    srv.ev("unregistered")
    assert srv.phone()["state"] == "Нет_регистрации"
    srv.ev("outgoing_call", remote="200")   # звонок невозможен, но если пришёл —
    srv.ev("call_terminated")               # покой остаётся «Нет регистрации»
    assert srv.phone()["state"] == "Нет_регистрации"


def test_info_events_set_last_event(srv):
    srv.ev("peripheral_information")
    f = flags(srv)
    assert f["last_event"] == "Периферийная информация"
    srv.ev("vpn_ip", ip="172.16.0.5")
    assert flags(srv)["vpn_ip"] == "172.16.0.5"


# ── номер без $active_user ──

def test_resolve_by_card_ip(srv):
    srv.ev("dnd_on", local="", ip="10.0.0.12")
    assert srv.phone("102")["state"] == "DND"
    assert srv.phone("101")["state"] == "В_покое"


def test_unsubstituted_variable_falls_back(srv):
    srv.ev("dnd_on", local="$active_user", ip="10.0.0.12")
    assert srv.phone("102")["state"] == "DND"


def test_resolve_by_learned_mac(srv):
    srv.ev("off_hook", local="102", mac="00:15:65:AA:BB:CC")
    srv.ev("on_hook", local="102")
    srv.ev("dnd_on", local="", mac="001565aabbcc")
    assert srv.phone("102")["state"] == "DND"


def test_unresolved_event_is_ok(srv):
    r = srv.ev("dnd_on", local=None, ip="10.9.9.9")
    assert r.data == b"OK"
    assert srv.phone("101")["state"] == "В_покое"


def test_shared_ip_not_resolved(srv):
    """DECT-база: один IP на несколько трубок — номер по IP не определить."""
    srv.phone("102")["ip"] = "10.0.0.11"
    srv.ev("dnd_on", local="", ip="10.0.0.11")
    assert srv.phone("101")["state"] == "В_покое"
    assert srv.phone("102")["state"] == "В_покое"


def test_shared_mac_not_resolved(srv):
    srv.ev("off_hook", local="101", mac="001565aabbcc")
    srv.ev("on_hook", local="101")
    srv.ev("off_hook", local="102", mac="001565aabbcc")
    srv.ev("on_hook", local="102")
    srv.ev("dnd_on", local="", mac="001565aabbcc")
    assert srv.phone("101")["state"] == "В_покое"
    assert srv.phone("102")["state"] == "В_покое"


def test_other_users_card_not_resolved_by_ip(srv):
    srv.add_user("bob", [{"number": "201", "ip": "10.0.0.21"}])
    srv.ev("dnd_on", local="", ip="10.0.0.21")       # токен admin
    assert srv.server.users_phones["bob"]["201"]["state"] == "В_покое"


def test_x_forwarded_for_ignored(srv):
    srv.ev("dnd_on", local="", headers={"X-Forwarded-For": "10.0.0.12"})
    assert srv.phone("102")["state"] == "В_покое"


# ── смена IP ──

def test_ip_change_updates_card_and_file(srv):
    srv.ev("off_hook", local="101", mac="001565aabbcc")
    srv.ev("ip_change", local="", mac="001565aabbcc", ip="10.0.0.99")
    assert srv.phone("101")["ip"] == "10.0.0.99"
    saved = json.loads((srv.server.PHONES_DIR / "phones_admin.json").read_text(encoding="utf-8"))
    assert next(p for p in saved if p["number"] == "101")["ip"] == "10.0.0.99"


def test_ip_change_only_token_owners_cards(srv):
    bob = srv.add_user("bob", [{"number": "101", "ip": "10.0.0.31"}])
    srv.ev("ip_change", local="101", ip="10.0.0.99", as_token=bob)
    assert srv.server.users_phones["bob"]["101"]["ip"] == "10.0.0.99"
    assert srv.phone("101")["ip"] == "10.0.0.11"     # набор admin не тронут


def test_ip_change_ignores_garbage(srv):
    srv.ev("ip_change", ip="$ip")
    assert srv.phone("101")["ip"] == "10.0.0.11"


# ── журнал ──

def test_recent_events_admin_only(srv):
    srv.ev("dnd_on")
    srv.ev("Bogus")
    assert srv.client.get("/recent_events").status_code == 302   # не залогинен
    login(srv)
    events = srv.client.get("/recent_events").get_json()["events"]
    assert events[0]["key"] == "Bogus" and events[0]["known"] is False
    assert events[1]["label"] == "Включение DND" and events[1]["number"] == "101"
