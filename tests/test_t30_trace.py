"""Порядок событий из пилота SIP-T30 124.87.14.1, адреса обезличены."""


def test_t30_incoming_trace_keeps_caller_and_one_history_row(srv):
    ip = "10.0.0.11"
    assert srv.ev("off_hook", local="", ip=ip).status_code == 200
    assert srv.phone()["state"] == "Снята_трубка"
    srv.ev("on_hook", local="", ip=ip)
    params = dict(ip=ip, remote="sip:902@192.0.2.90", called_number="902", call_id="32770",
                  model="SIP-T30", firmware="124.87.14.1")
    for state in ("idle_to_busy", "incoming_call", "answer_new_incoming_call", "call_established"):
        assert srv.ev(state, **params).status_code == 200
    assert srv.phone()["state"] == "Разговор"
    assert srv.phone()["peer"] == "902"
    srv.age_call(seconds=8)
    srv.ev("call_terminated", **params)
    srv.ev("busy_to_idle", ip=ip, remote="sip:@", call_id="-1")
    assert srv.phone()["state"] == "В_покое" and srv.phone()["peer"] == ""
    assert [row[:3] for row in srv.history()] == [("101", "902", "in")]
    assert srv.server.recent_events[-1]["raw_remote"] == "sip:@"
    assert srv.server.recent_events[-1]["remote"] == ""
    assert srv.server.recent_events[-1]["call_id"] == ""
