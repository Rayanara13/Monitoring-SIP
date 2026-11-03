"""Три виртуальных телефона, отправляющих настоящие события Action URL.

Модель не обращается к сети: транспорт задаёт синхронный ``send_event``.
``hook=True`` означает снятую трубку. Состояние и журнал возвращаются копиями.
"""

from collections import deque
import threading
import time


class PhoneLab:
    NUMBERS = ("101", "102", "103")
    NAMES = ("Приёмная", "Кабинет", "Переговорная")
    ACTIVE = {"ringing", "calling", "connected", "held"}

    def __init__(self, send_event, clock=time.monotonic):
        self._send_event = send_event
        self._clock = clock
        self._wall_offset = time.time() - self._clock()
        self._lock = threading.RLock()
        self._events = deque(maxlen=300)
        self._sequence = 0
        self._pairs = {}
        self._phones = self._initial_phones()

    def _initial_phones(self):
        return {
            number: {
                "number": number, "name": name,
                "ip": f"192.0.2.{number}",
                "mac": f"02:00:00:00:01:{index:02d}",
                "model": "Yealink T53 (simulator)", "firmware": "simulator-1",
                "state": "idle", "peer": "", "dial": "", "hook": False,
                "speaker": False, "headset": False, "mute": False,
                "dnd": False, "registered": True, "power": True,
                "forward_to": "", "call_id": "", "started_at": None,
                "duration": 0,
            }
            for index, (number, name) in enumerate(zip(self.NUMBERS, self.NAMES), 1)
        }

    def state(self):
        with self._lock:
            now = self._clock()
            phones = []
            for number in self.NUMBERS:
                phone = dict(self._phones[number])
                started = phone["started_at"]
                phone["duration"] = max(0, int(now - started)) if started is not None else 0
                phones.append(phone)
            return {"phones": phones, "events": [dict(event) for event in self._events]}

    def _phone(self, number):
        try:
            return self._phones[str(number)]
        except KeyError:
            raise ValueError("Доступны только телефоны 101, 102 и 103.") from None

    @staticmethod
    def _toggle(value, current):
        if value is None:
            return not current
        if isinstance(value, bool):
            return value
        if value in (1, "1", "on", "true"):
            return True
        if value in (0, "0", "off", "false"):
            return False
        raise ValueError("Для переключателя нужны true/false или on/off.")

    @staticmethod
    def _require_power(phone):
        if not phone["power"]:
            raise ValueError("Телефон выключен.")

    def _emit(self, phone, key, remote=None, call_id=None):
        remote = phone["peer"] if remote is None else str(remote)
        call_id = phone["call_id"] if call_id is None else str(call_id)
        self._send_event(dict(phone), key, remote, call_id)
        self._events.append({
            "at": self._clock() + self._wall_offset, "phone": phone["number"], "state": key,
            "remote": remote, "call_id": call_id,
        })

    def _rest(self, phone):
        self._pairs.pop(phone["number"], None)
        phone.update(state="idle" if phone["power"] else "offline", peer="",
                     dial="", hook=False, speaker=False, headset=False,
                     mute=False, call_id="", started_at=None, duration=0)

    def _hangup(self, phone):
        peer_number = self._pairs.get(phone["number"])
        peer = self._phones.get(peer_number)
        participants = [phone] + ([peer] if peer is not None else [])
        # Снимки нужны до сброса: в событиях конца остаются номер и ID звонка.
        snapshots = [dict(item) for item in participants]
        for item in participants:
            self._rest(item)
        for item, previous in zip(participants, snapshots):
            remote, call_id = previous["peer"], previous["call_id"]
            if previous["state"] in ("connected", "held"):
                self._emit(item, "call_terminated", remote, call_id)
            elif previous["state"] == "ringing":
                key = "reject_incoming_call" if item is phone else "call_remote_canceled"
                self._emit(item, key, remote, call_id)
            elif previous["state"] == "calling":
                self._emit(item, "cancel_callout", remote, call_id)
            elif previous["state"] == "dialing":
                self._emit(item, "on_hook", remote, call_id)
            # Не дублируем On Hook после Terminated: оба закрывают pending.
            if item["power"]:
                self._emit(item, "busy_to_idle", remote, call_id)

    def _route(self, caller, number):
        target = self._phone(number)
        seen = {caller["number"]}
        forwarded = []
        while True:
            if target["number"] in seen:
                raise ValueError("Нельзя звонить себе или создавать петлю переадресации.")
            seen.add(target["number"])
            if not target["power"] or not target["registered"] or not target["forward_to"]:
                return forwarded, target
            forwarded.append(target)
            target = self._phone(target["forward_to"])

    def _call(self, phone, value):
        self._require_power(phone)
        if not phone["registered"]:
            raise ValueError("Телефон не зарегистрирован.")
        if phone["state"] not in ("idle", "dialing"):
            raise ValueError("Сначала завершите текущий звонок.")
        number = str(value if value is not None else phone["dial"]).strip()
        forwarded, target = self._route(phone, number)  # До любых изменений.
        self._sequence += 1
        call_id = f"sim-{self._sequence:06d}"
        if not (phone["hook"] or phone["speaker"] or phone["headset"]):
            phone["speaker"] = True
            self._emit(phone, "handfree", "", call_id)
        phone.update(state="calling", peer=target["number"], dial=number, call_id=call_id)
        self._emit(phone, "outgoing_call")
        if (not target["power"] or not target["registered"] or target["dnd"]
                or target["state"] != "idle"):
            self._emit(phone, "remote_busy")
            remote = target["number"]
            self._rest(phone)
            self._emit(phone, "cancel_callout", remote, call_id)
            self._emit(phone, "busy_to_idle", remote, call_id)
            return
        for intermediate in forwarded:
            # Уже занятая трубка не получает вторую виртуальную линию:
            # её переадресация работает до доставки вызова на аппарат.
            if intermediate["state"] != "idle":
                continue
            # Условие переадресации не создаёт соединения с исходной трубкой.
            self._emit(intermediate, "incoming_call", phone["number"], call_id)
            self._emit(intermediate, "forward_incoming_call", phone["number"], call_id)
            self._emit(intermediate, "busy_to_idle", phone["number"], call_id)
        target.update(state="ringing", peer=phone["number"], call_id=call_id)
        self._pairs[phone["number"]] = target["number"]
        self._pairs[target["number"]] = phone["number"]
        self._emit(target, "incoming_call")

    def _answer(self, phone, mode="hook"):
        self._require_power(phone)
        peer_number = self._pairs.get(phone["number"])
        peer = self._phones.get(peer_number)
        if phone["state"] != "ringing" or peer is None or peer["state"] != "calling":
            raise ValueError("У телефона нет входящего звонка.")
        if not phone["registered"]:
            raise ValueError("Телефон не зарегистрирован.")
        phone.update(hook=mode == "hook", speaker=mode == "speaker", headset=mode == "headset")
        started = self._clock()
        for item in (phone, peer):
            item.update(state="connected", started_at=started)
        # На принимающей стороне намеренно нет Established: номер должен
        # сохраниться при Off Hook / Handfree / Headset, как на живом аппарате.
        self._emit(phone, {"hook": "off_hook", "speaker": "handfree", "headset": "headset"}[mode])
        self._emit(peer, "call_established")

    def _audio(self, phone, mode, value):
        self._require_power(phone)
        enabled = self._toggle(value, phone[mode])
        if phone["state"] == "ringing" and enabled:
            self._answer(phone, mode)
            return
        if enabled == phone[mode]:
            return
        phone[mode] = enabled
        other = "headset" if mode == "speaker" else "speaker"
        if enabled:
            phone[other] = False
            if phone["state"] == "idle":
                phone["state"] = "dialing"
        # Action URL сообщает нажатие клавиши, в том числе при выключении.
        # Физическую трубку при этом не поднимали: Off Hook здесь недостоверен.
        self._emit(phone, "handfree" if mode == "speaker" else "headset")
        if not enabled and not (phone["hook"] or phone[other]):
            self._hangup(phone)

    def _hold(self, phone, value):
        enabled = self._toggle(value, phone["state"] == "held")
        if phone["state"] not in ("connected", "held"):
            raise ValueError("Удерживать можно только установленный разговор.")
        if enabled == (phone["state"] == "held"):
            return
        peer = self._phones[self._pairs[phone["number"]]]
        for item in (phone, peer):
            item["state"] = "held" if enabled else "connected"
            self._emit(item, "hold" if enabled else "unhold")

    def _forward(self, phone, value):
        self._require_power(phone)
        target = "" if value is None else str(value).strip()
        if target:
            self._route(phone, target)  # Проверяет существование и петли.
        phone["forward_to"] = target
        self._emit(phone, "always_fwd_on" if target else "always_fwd_off", target)

    def _transfer(self, phone, value):
        self._require_power(phone)
        if phone["state"] not in ("connected", "held"):
            raise ValueError("Передавать можно только установленный разговор.")
        target = self._phone(str(value).strip())
        peer = self._phones[self._pairs[phone["number"]]]
        if target["number"] in (phone["number"], peer["number"]):
            raise ValueError("Для перевода нужна третья трубка.")
        if (not target["power"] or not target["registered"] or target["dnd"]
                or target["state"] != "idle" or target["forward_to"]):
            raise ValueError("Третья трубка должна быть свободна и доступна без переадресации.")
        old_id = phone["call_id"]
        old_peer = phone["peer"]
        route = {key: peer[key] for key in ("hook", "speaker", "headset")}
        self._emit(phone, "blind_transfer_call", target["number"], old_id)
        self._emit(phone, "transfer_finished", old_peer, old_id)
        self._emit(peer, "call_terminated", phone["number"], old_id)
        self._rest(phone)
        self._rest(peer)
        self._emit(phone, "busy_to_idle", old_peer, old_id)
        self._emit(peer, "busy_to_idle", phone["number"], old_id)
        peer.update(route)
        self._call(peer, target["number"])

    def action(self, number, action, value=None):
        with self._lock:
            phone = self._phone(number)
            action = str(action).strip().lower()
            if action in ("digit", "backspace", "clear"):
                self._require_power(phone)
                if phone["state"] not in ("idle", "dialing"):
                    raise ValueError("Набор доступен только вне звонка.")
                if action == "digit":
                    digit = str(value)
                    if len(digit) != 1 or digit not in "0123456789*#":
                        raise ValueError("Допустима одна цифра, * или #.")
                    phone["dial"] += digit
                elif action == "backspace":
                    phone["dial"] = phone["dial"][:-1]
                else:
                    phone["dial"] = ""
                phone["state"] = "dialing" if phone["dial"] or phone["hook"] or phone["speaker"] or phone["headset"] else "idle"
            elif action in ("call", "dial"):
                self._call(phone, value)
            elif action == "answer":
                self._answer(phone)
            elif action == "hangup":
                self._hangup(phone)
            elif action == "hook":
                self._require_power(phone)
                enabled = self._toggle(value, phone["hook"])
                if enabled and phone["state"] == "ringing":
                    self._answer(phone)
                elif enabled != phone["hook"]:
                    if not enabled:
                        self._hangup(phone)
                    else:
                        phone["hook"] = True
                        phone["speaker"] = phone["headset"] = False
                        if phone["state"] == "idle":
                            phone["state"] = "dialing"
                        self._emit(phone, "off_hook")
            elif action in ("speaker", "headset"):
                self._audio(phone, action, value)
            elif action in ("mute", "dnd"):
                self._require_power(phone)
                enabled = self._toggle(value, phone[action])
                phone[action] = enabled
                key = ("mute" if enabled else "unmute") if action == "mute" else ("dnd_on" if enabled else "dnd_off")
                self._emit(phone, key)
            elif action == "hold":
                self._hold(phone, value)
            elif action == "forward":
                self._forward(phone, value)
            elif action == "register":
                self._require_power(phone)
                enabled = self._toggle(value, phone["registered"])
                if not enabled and phone["state"] in self.ACTIVE | {"dialing"}:
                    self._hangup(phone)
                phone["registered"] = enabled
                self._emit(phone, "registered" if enabled else "unregistered", "")
            elif action == "power":
                enabled = self._toggle(value, phone["power"])
                if enabled != phone["power"]:
                    if not enabled:
                        self._hangup(phone)
                    phone.update(power=enabled, registered=enabled, state="idle" if enabled else "offline")
                    if enabled:
                        self._emit(phone, "setup_completed", "")
                        self._emit(phone, "registered", "")
                    else:
                        self._emit(phone, "unregistered", "")
            elif action == "transfer":
                self._transfer(phone, value)
            else:
                raise ValueError("Неизвестное действие телефона.")
            return self.state()

    def reset(self):
        with self._lock:
            for number in self.NUMBERS:
                if number in self._pairs:
                    self._hangup(self._phones[number])
            self._phones = self._initial_phones()
            self._pairs.clear()
            self._events.clear()
            for phone in self._phones.values():
                for key in ("setup_completed", "registered", "dnd_off", "always_fwd_off", "unmute", "busy_to_idle"):
                    self._emit(phone, key, "", "")
            return self.state()
