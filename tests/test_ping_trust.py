import json

import pytest

import ping_trust
from ping_trust import PingTrustFile, endpoint_ip, normalize_ip, read_trust_snapshot, trust_snapshot


def test_trust_snapshots_require_literal_addresses_and_matching_revision():
    assert normalize_ip('::ffff:10.40.0.1') == '10.40.0.1'
    assert endpoint_ip('https://[fd00::10]:8443') == 'fd00::10'
    assert endpoint_ip('https://victoria.example') is None
    for invalid in ('10.40.0.0/24', '0.0.0.0', '255.255.255.255', 'ff02::1', 'fe80::1%en0', 'example.org'):
        assert normalize_ip(invalid) is None
    current = trust_snapshot(['fd00:0000::1', '10.40.0.2', '::ffff:10.40.0.2'])
    assert current['addresses'] == ['10.40.0.2', 'fd00::1']
    assert current == read_trust_snapshot(current)
    assert current == trust_snapshot(reversed(current['addresses']))
    with pytest.raises(ValueError):
        read_trust_snapshot({**current, 'addresses': ['10.40.0.3']})


def test_publish_avoids_rewriting_unchanged_policy_and_survives_replace_error(tmp_path, monkeypatch):
    path = tmp_path / 'ping-trust.json'
    publisher = PingTrustFile(path)
    assert publisher.publish(['fd00::1', '10.40.0.2'])
    previous = path.read_bytes()
    assert json.loads(previous) == {'addresses': ['10.40.0.2', 'fd00::1']}

    def failed_replace(*args):
        raise PermissionError('cannot replace policy')

    monkeypatch.setattr(ping_trust.os, 'replace', failed_replace)
    assert publisher.publish(['10.40.0.2', 'fd00::1'])
    assert not publisher.publish(['10.40.0.3'])
    assert path.read_bytes() == previous
    assert list(tmp_path.iterdir()) == [path]
