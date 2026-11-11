from contextlib import closing
from dataclasses import dataclass
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest

import federation_node as node


PRIMARY = "https://10.0.0.10:8443"
FALLBACK = "https://10.0.0.11:8443"
OTHER = "https://10.0.0.12:8443"
PRIMARY_CA = "primary test certificate"
FALLBACK_CA = "fallback test certificate"
NODE_ID = "office_1"
CENTER_ID = "victoria_1"
INVITE = "a" * 43
RENEWED_INVITE = "b" * 43


def invitation(token=INVITE):
    return {
        "version": 1, "node_id": NODE_ID, "center_id": CENTER_ID,
        "invite_token": token, "url": PRIMARY, "tls_ca": PRIMARY_CA,
    }


def stage_command():
    return {
        "id": "stage_1", "action": "endpoint.stage",
        "payload": {"url": FALLBACK, "tls_ca": FALLBACK_CA},
    }


@dataclass
class Request:
    url: str
    path: str
    body: dict | None
    bearer: str | None


class Victoria:
    def __init__(self):
        self.calls = []
        self.identities = {url: CENTER_ID for url in (PRIMARY, FALLBACK, OTHER)}
        self.allowed_invites = {INVITE, RENEWED_INVITE}
        self.enrollments = {}
        self.active_token = None
        self.lose_enrollment_reply = False
        self.primary_error = None
        self.commands = []
        self.fallback_reply = {}
        self.partial_ack = False

    def request(self, link, path, payload=None, *, authenticated=False):
        url = link["url"]
        bearer = link["node_token"] if authenticated else None
        self.calls.append(Request(url, path, payload, bearer))
        if path == "/identity":
            assert bearer is None
            return {"center_id": self.identities[url]}
        if path == "/enroll":
            assert bearer is None and payload["node_id"] == NODE_ID
            invite_token, node_token = payload["invite_token"], payload["node_token"]
            existing = self.enrollments.get(invite_token)
            if invite_token not in self.allowed_invites or existing not in (None, node_token):
                raise HTTPError(url, 401, "Invalid invitation", {}, None)
            self.enrollments[invite_token] = self.active_token = node_token
            if self.lose_enrollment_reply:
                self.lose_enrollment_reply = False
                raise URLError("The enrollment reply was lost")
            return {"center_id": CENTER_ID, "node_id": NODE_ID}
        assert path == "/sync" and bearer == self.active_token and payload["node_id"] == NODE_ID
        if url == PRIMARY and self.primary_error is not None:
            raise self.primary_error
        history_ack = [row["id"] for row in payload["history"]]
        result_ack = [row["id"] for row in payload["results"]]
        if self.partial_ack:
            history_ack, result_ack = history_ack[:1], result_ack[:1]
        reply = {
            "center_id": CENTER_ID, "history_ack": history_ack,
            "result_ack": result_ack, "commands": self.commands,
        }
        return {**reply, **self.fallback_reply} if url == FALLBACK else reply


@pytest.fixture
def federation(tmp_path, monkeypatch):
    path = tmp_path / "calls.db"
    with closing(node.connect(path)) as db, db:
        db.execute("""
            CREATE TABLE call_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts_start REAL NOT NULL, ts_end REAL NOT NULL,
                duration INTEGER NOT NULL, local TEXT NOT NULL, remote TEXT NOT NULL,
                direction TEXT NOT NULL, username TEXT NOT NULL
            )
        """)
        node.init_node_tables(db)
    victoria = Victoria()
    monkeypatch.setattr(node, "tls_context", lambda certificate: None)
    monkeypatch.setattr(node.NodeSync, "_request", lambda self, *args, **kwargs: victoria.request(*args, **kwargs))
    executed = []

    def apply(command, _link):
        executed.append(command["id"])
        return "applied", {"saved": True}

    def new_node():
        return node.NodeSync(path, "1.3", lambda: {"phones": [], "users": [], "recent_events": []}, apply,
                             master_url=PRIMARY)

    return SimpleNamespace(new_node=new_node, path=path, victoria=victoria, executed=executed)


@pytest.fixture
def enrolled(federation):
    sync = federation.new_node()
    sync.import_invitation(invitation())
    assert sync.sync_once()
    assert sync.status()["enrolled"]
    federation.sync = sync
    federation.victoria.calls.clear()
    return federation


def queue_history(federation, *numbers):
    with closing(node.connect(federation.path)) as db, db:
        for number in numbers:
            node.queue_call(db, 100, 109, 9, number, "Desk", "0123", "out", "admin")


def stage(federation):
    federation.victoria.commands = [stage_command()]
    assert federation.sync.sync_once()
    assert federation.sync.status()["fallback_url"] == FALLBACK
    federation.victoria.commands.clear()


def test_retry_after_lost_enrollment_reply_reuses_durable_token(federation):
    original = federation.new_node()
    original.import_invitation(invitation())
    federation.victoria.lose_enrollment_reply = True
    with pytest.raises(URLError):
        original.sync_once()
    assert not original.status()["enrolled"]
    persisted_token = federation.victoria.active_token
    restarted = federation.new_node()
    assert restarted.sync_once()
    assert restarted.status()["enrolled"]
    first, second = [call for call in federation.victoria.calls if call.path == "/enroll"]
    assert first.body == second.body
    assert second.body["node_token"] == persisted_token


def test_reimporting_consumed_invitation_preserves_active_credentials(enrolled):
    active_token = enrolled.victoria.active_token
    restarted = enrolled.new_node()
    restarted.import_invitation(invitation())
    assert restarted.status()["enrolled"]
    assert restarted.sync_once()
    assert [(request.path, request.bearer) for request in enrolled.victoria.calls] == [("/sync", active_token)]


def test_rejected_renewal_preserves_active_credentials(enrolled):
    token = enrolled.victoria.active_token
    enrolled.sync.import_invitation(invitation("z" * 43))
    restarted = enrolled.new_node()
    assert restarted.status()["enrolled"]
    try:
        restarted.sync_once()
    except HTTPError as error:
        assert error.code == 401
    except node.FederationError:
        pass
    assert restarted.sync_once()
    assert restarted.status()["enrolled"]
    assert len([call for call in enrolled.victoria.calls if call.path == "/enroll"]) == 1
    assert enrolled.victoria.calls[-1].bearer == token


def test_renewal_promotes_new_token_after_center_confirmation(enrolled):
    old_token = enrolled.victoria.active_token
    enrolled.sync.import_invitation(invitation(RENEWED_INVITE))
    restarted = enrolled.new_node()
    assert restarted.status()["enrolled"]
    assert restarted.sync_once()
    assert restarted.status()["enrolled"]
    new_token = enrolled.victoria.active_token
    assert new_token and new_token != old_token
    assert enrolled.victoria.calls[-1].bearer == new_token
    after_renewal = enrolled.new_node()
    enrolled.victoria.calls.clear()
    after_renewal.import_invitation(invitation(RENEWED_INVITE))
    assert after_renewal.sync_once()
    assert [(call.path, call.bearer) for call in enrolled.victoria.calls] == [("/sync", new_token)]


def test_stage_stores_endpoint_and_reports_success_before_it_is_reachable(enrolled):
    enrolled.victoria.identities.pop(FALLBACK)
    stage(enrolled)
    restarted = enrolled.new_node()
    assert restarted.status()["fallback_url"] == FALLBACK
    assert restarted.status()["url"] == PRIMARY
    assert restarted.sync_once()
    assert all(call.url == PRIMARY for call in enrolled.victoria.calls)
    assert enrolled.victoria.calls[-1].body["results"] == [{
        "id": "stage_1", "status": "applied", "result": {"url": FALLBACK},
    }]


@pytest.mark.parametrize("code", [400, 401, 403, 429])
def test_primary_client_error_does_not_trigger_failover(enrolled, code):
    stage(enrolled)
    queue_history(enrolled, "0101")
    enrolled.victoria.calls.clear()
    enrolled.victoria.primary_error = HTTPError(PRIMARY, code, "Rejected", {}, None)
    with pytest.raises(HTTPError) as error:
        enrolled.sync.sync_once()
    assert error.value.code == code
    assert [(call.url, call.path) for call in enrolled.victoria.calls] == [(PRIMARY, "/sync")]
    assert enrolled.sync.status()["url"] == PRIMARY
    assert enrolled.sync.status()["history_queued"] == 1


def test_fallback_identity_mismatch_prevents_credential_transmission(enrolled):
    stage(enrolled)
    enrolled.victoria.calls.clear()
    enrolled.victoria.primary_error = URLError("Host unreachable")
    enrolled.victoria.identities[FALLBACK] = "different_center"
    with pytest.raises(node.FederationError):
        enrolled.sync.sync_once()
    assert [(call.url, call.path, call.bearer) for call in enrolled.victoria.calls] == [
        (PRIMARY, "/sync", enrolled.victoria.active_token), (FALLBACK, "/identity", None),
    ]
    assert enrolled.new_node().status()["url"] == PRIMARY


@pytest.mark.parametrize("bad_reply", [
    {"history_ack": ["not_submitted"]}, {"result_ack": ["not_submitted"]},
    {"commands": {}}, {"commands": [None]}, {"center_id": "different_center"},
])
def test_invalid_failover_reply_neither_promotes_nor_acknowledges(enrolled, bad_reply):
    stage(enrolled)
    queue_history(enrolled, "0101")
    previous = enrolled.sync.status()["last_sync"]
    enrolled.victoria.primary_error = URLError("Host unreachable")
    enrolled.victoria.fallback_reply = bad_reply
    with pytest.raises(node.FederationError):
        enrolled.sync.sync_once()
    persisted = enrolled.new_node().status()
    assert persisted["url"] == PRIMARY
    assert persisted["fallback_url"] == FALLBACK
    assert persisted["history_queued"] == 1
    assert persisted["last_sync"] == previous


def test_successful_failover_persists_address_and_acks_only_listed_records(enrolled):
    additional = {"id": "command_2", "action": "phone.add", "payload": {"number": "0102"}}
    enrolled.victoria.commands = [stage_command(), additional]
    assert enrolled.sync.sync_once()
    assert enrolled.sync.status()["fallback_url"] == FALLBACK
    enrolled.victoria.commands = [additional]
    enrolled.victoria.partial_ack = True
    queue_history(enrolled, "0101", "0102")
    enrolled.victoria.calls.clear()
    enrolled.victoria.primary_error = URLError("Host unreachable")
    assert enrolled.sync.sync_once()
    requests = enrolled.victoria.calls
    assert [(call.url, call.path) for call in requests] == [
        (PRIMARY, "/sync"), (FALLBACK, "/identity"), (FALLBACK, "/sync"),
    ]
    assert requests[1].bearer is None and requests[2].bearer == requests[0].bearer
    submitted = requests[2].body
    assert [row["phone_number"] for row in submitted["history"]] == ["0101", "0102"]
    assert [row["id"] for row in submitted["results"]] == ["stage_1", "command_2"]
    assert enrolled.executed == ["command_2"]
    restarted = enrolled.new_node()
    assert restarted.status()["url"] == FALLBACK
    assert restarted.status()["fallback_url"] is None
    assert restarted.status()["history_queued"] == 1
    enrolled.victoria.calls.clear()
    assert restarted.sync_once()
    [retry] = enrolled.victoria.calls
    assert retry.url == FALLBACK
    assert retry.body["history"] == [submitted["history"][1]]
    assert retry.body["results"] == [submitted["results"][1]]
    assert restarted.status()["history_queued"] == 0
    assert enrolled.executed == ["command_2"]
    assert restarted.sync_once()
    assert enrolled.victoria.calls[-1].body["results"] == []


def test_manual_change_allows_existing_trust_after_verifying_identity(enrolled):
    enrolled.sync.change_address(OTHER, PRIMARY_CA)
    assert enrolled.new_node().status()["url"] == OTHER
    assert [(call.url, call.path, call.bearer) for call in enrolled.victoria.calls] == [
        (OTHER, "/identity", None),
    ]


def test_manual_change_refuses_unstaged_trust_and_accepts_staged_pair(enrolled):
    with pytest.raises(node.FederationError):
        enrolled.sync.change_address(FALLBACK, FALLBACK_CA)
    assert not enrolled.victoria.calls
    stage(enrolled)
    enrolled.victoria.calls.clear()
    with pytest.raises(node.FederationError):
        enrolled.sync.change_address(OTHER, FALLBACK_CA)
    assert enrolled.sync.status()["url"] == PRIMARY
    assert not enrolled.victoria.calls
    enrolled.sync.change_address(FALLBACK, FALLBACK_CA)
    persisted = enrolled.new_node().status()
    assert persisted["url"] == FALLBACK and persisted["fallback_url"] is None
    assert [(call.url, call.path, call.bearer) for call in enrolled.victoria.calls] == [
        (FALLBACK, "/identity", None),
    ]
