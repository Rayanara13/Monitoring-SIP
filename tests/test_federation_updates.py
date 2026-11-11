"""Проверки доверия, потоковой загрузки и однократного локального запуска."""

import hashlib
import io
import json
import os
import subprocess
import sys
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import federation_updates as updates


LINK = {"url": "https://victoria.example.invalid:8443", "node_id": "node-01", "token": "synthetic-node-key"}


@pytest.fixture
def signer():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def linux_target(monkeypatch):
    monkeypatch.setattr(updates, "_local_target", lambda: ("linux", "x86_64"))


def signed(signer, content=b"synthetic-offline-package", **changes):
    manifest = {"version": "Rel 1.3", "platform": "linux", "arch": "x86_64",
                "sha256": hashlib.sha256(content).hexdigest(), "size": len(content), **changes}
    canonical = updates.canonical_manifest(manifest)
    return canonical, signer.sign(canonical), content


def job(canonical, job_id="job-01", **claims):
    return {"id": job_id, "action": "update.install",
            "payload": {"package_id": hashlib.sha256(canonical).hexdigest(), **claims}}


def key(signer):
    return signer.public_key().public_bytes_raw()


class Response(io.BytesIO):
    status = 200

    def __init__(self, request, canonical, signature, content, reads):
        super().__init__(content)
        self.url = request.full_url
        self.headers = {"X-Update-Manifest": updates.encode_url64(canonical),
                        "X-Update-Signature": updates.encode_url64(signature),
                        "Content-Length": str(len(content))}
        self.reads = reads

    def geturl(self):
        return self.url

    def read1(self, size=-1):
        self.reads.append(size)
        return self.read(size)


def remote(canonical, signature, content, *, calls=None, reads=None):
    def open_request(request, *, timeout):
        if calls is not None:
            calls.append(request)
        return Response(request, canonical, signature, content, reads if reads is not None else [])
    return open_request


def no_network(*args, **kwargs):
    pytest.fail("Повтор команды не должен открывать сеть")


def test_store_verifies_upload_then_publishes_canonical_package(tmp_path, signer):
    canonical, signature, content = signed(signer)
    store = updates.PackageStore(tmp_path, updates.encode_url64(key(signer)))
    metadata = store.put(json.dumps(json.loads(canonical), indent=2), updates.encode_url64(signature), io.BytesIO(content))
    assert store.lookup(metadata.id) == metadata
    assert metadata.id == hashlib.sha256(canonical).hexdigest()
    assert metadata.manifest_path.read_bytes() == canonical
    assert metadata.path.read_bytes() == content
    assert set(metadata.public()) == {"package_id", "version", "platform", "arch", "sha256", "size"}
    assert sorted(p.name for p in tmp_path.iterdir()) == [metadata.id]
    with pytest.raises(KeyError):
        store.lookup("../package.zip")


@pytest.mark.parametrize("kind,code", [
    ("short", "size_mismatch"), ("long", "size_mismatch"),
    ("corrupt", "hash_mismatch"), ("signature", "invalid_signature"),
])
def test_invalid_upload_never_publishes_a_partial_package(tmp_path, signer, kind, code):
    canonical, signature, content = signed(signer)
    store = updates.PackageStore(tmp_path, key(signer))
    if kind == "short":
        content = content[:-1]
    elif kind == "long":
        content += b"!"
    elif kind == "corrupt":
        content = b"!" + content[1:]
    else:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    with pytest.raises(updates.UpdateError) as error:
        store.put(canonical, signature, io.BytesIO(content))
    assert error.value.code == code
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("changes", [{"size": True}, {"size": 0}, {"platform": "other"},
                                    {"arch": "../arm"}, {"extra": "value"}])
def test_manifest_schema_rejects_ambiguous_fields(signer, changes):
    canonical, _, _ = signed(signer)
    with pytest.raises(updates.UpdateError):
        updates.canonical_manifest({**json.loads(canonical), **changes})


def test_duplicate_json_keys_and_duplicate_upload_tampering(tmp_path, signer):
    canonical, signature, content = signed(signer)
    store = updates.PackageStore(tmp_path, key(signer))
    with pytest.raises(updates.UpdateError):
        store.put(canonical[:-1] + b',"size":23}', signature, io.BytesIO(content))
    original = store.put(canonical, signature, io.BytesIO(content))
    with pytest.raises(updates.UpdateError, match="SHA-256"):
        store.put(canonical, signature, io.BytesIO(b"!" + content[1:]))
    assert store.lookup(original.id).path.read_bytes() == content


def test_node_streams_authenticated_https_and_stages_when_executor_is_absent(tmp_path, signer, linux_target):
    canonical, signature, content = signed(signer, b"x" * (updates.CHUNK_BYTES * 2 + 5))
    calls, reads = [], []
    command = job(canonical, version="Rel 1.3")
    result = updates.execute_update(command, LINK, tmp_path, public_key=key(signer),
                                    opener=remote(canonical, signature, content, calls=calls, reads=reads))
    assert result == {"status": "staged", "code": "local_executor_not_configured",
                      "package_id": command["payload"]["package_id"], "version": "Rel 1.3"}
    assert len(calls) == 1
    assert calls[0].full_url == LINK["url"] + "/api/federation/v1/update-packages/" + result["package_id"]
    assert calls[0].get_header("Authorization") == "Bearer " + LINK["token"]
    assert calls[0].get_header("X-node-id") == LINK["node_id"]
    assert reads == [updates.CHUNK_BYTES, updates.CHUNK_BYTES, 5, 1]
    stage = tmp_path / "federation-updates" / "packages" / result["package_id"]
    assert (stage / "package.zip").read_bytes() == content
    assert updates.execute_update(command, LINK, tmp_path, public_key=key(signer), opener=no_network) == result
    receipt = (tmp_path / "federation-updates" / "jobs" / "job-01.json").read_text(encoding="utf-8")
    assert LINK["token"] not in receipt


@pytest.mark.parametrize("case,code", [
    ("http", "invalid_center_url"), ("wrong_arch", "target_mismatch"),
    ("wrong_version", "target_mismatch"), ("wrong_package", "package_mismatch"),
    ("foreign_signature", "invalid_signature"),
])
def test_node_rejects_ineligible_package_before_reading_body(tmp_path, signer, linux_target, case, code):
    canonical, signature, content = signed(signer, arch="aarch64" if case == "wrong_arch" else "x86_64")
    link = {**LINK, "url": "http://victoria.example.invalid"} if case == "http" else LINK
    command = job(canonical, **({"version": "Rel 9.9"} if case == "wrong_version" else {}))
    if case == "wrong_package":
        command["payload"]["package_id"] = "0" * 64
    if case == "foreign_signature":
        signature = Ed25519PrivateKey.generate().sign(canonical)
    reads = []
    with pytest.raises(updates.UpdateError) as error:
        updates.execute_update(command, link, tmp_path, public_key=key(signer),
                               opener=remote(canonical, signature, content, reads=reads))
    assert error.value.code == code
    assert reads == []


def test_installer_is_local_and_receipt_precedes_exact_argv(tmp_path, signer, linux_target, monkeypatch):
    canonical, signature, content = signed(signer)
    command = job(canonical)
    root = tmp_path / "federation-updates"
    package_id = command["payload"]["package_id"]
    stage = root / "packages" / package_id
    installer = tmp_path / "local-installer.exe"
    installer.touch()
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert argv == [str(installer), "--package", str(stage / "package.zip"),
                        "--manifest", str(stage / "manifest.json"), "--job-id", command["id"]]
        assert kwargs["shell"] is False and kwargs["cwd"] == root
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        assert (stage / "package.zip").read_bytes() == content
        receipt = json.loads((root / "jobs" / "job-01.json").read_bytes())
        assert receipt["status"] == "installing"
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(updates.subprocess, "run", run)
    result = updates.execute_update(command, LINK, tmp_path, public_key=key(signer), executable=installer,
                                    opener=remote(canonical, signature, content))
    assert result["status"] == "applied"
    assert updates.execute_update(command, LINK, tmp_path, public_key=key(signer), executable=installer,
                                  opener=no_network) == result
    assert len(calls) == 1
    with pytest.raises(updates.UpdateError) as error:
        updates.execute_update(job(canonical, version="Rel 1.4"), LINK, tmp_path,
                               public_key=key(signer), executable=installer, opener=no_network)
    assert error.value.code == "job_conflict"
    with pytest.raises(updates.UpdateError):
        updates.execute_update(job(canonical, job_id="../escaped", shell="malicious"), LINK, tmp_path,
                               public_key=key(signer), executable=installer, opener=no_network)


def test_local_executor_handoff_through_a_real_subprocess(tmp_path, signer, linux_target, monkeypatch):
    """Контрольный установщик читает пакет, манифест и запись запуска из своего процесса."""
    canonical, signature, content = signed(signer)
    command = job(canonical)
    script = tmp_path / "executor-harness.py"
    script.write_text('''#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--package", type=Path, required=True)
parser.add_argument("--manifest", type=Path, required=True)
parser.add_argument("--job-id", required=True)
args = parser.parse_args()
manifest = json.loads(args.manifest.read_bytes())
package = args.package.read_bytes()
receipt = json.loads((Path("jobs") / (args.job_id + ".json")).read_bytes())
if (not args.package.is_absolute() or not args.manifest.is_absolute()
        or hashlib.sha256(package).hexdigest() != manifest["sha256"]
        or len(package) != manifest["size"] or receipt["status"] != "installing"):
    raise SystemExit(17)
with Path("harness-receipt.json").open("x", encoding="utf-8") as stream:
    json.dump({"job_id": args.job_id, "sha256": manifest["sha256"]}, stream)
''', encoding="utf-8", newline="\n")
    installer = script
    if os.name == "nt":
        # Для теста Windows подставляем фиксированный Python harness вместо сборки .exe.
        installer = tmp_path / "harness.exe"
        installer.touch()
        run = subprocess.run

        def launch_harness(argv, **kwargs):
            assert argv[0] == str(installer)
            return run([sys.executable, str(script), *argv[1:]], **kwargs)

        monkeypatch.setattr(updates.subprocess, "run", launch_harness)
    else:
        script.chmod(0o700)
    result = updates.execute_update(command, LINK, tmp_path, public_key=key(signer), executable=installer,
                                    opener=remote(canonical, signature, content))
    assert result["status"] == "applied"
    witness = tmp_path / "federation-updates" / "harness-receipt.json"
    assert json.loads(witness.read_bytes()) == {"job_id": command["id"], "sha256": hashlib.sha256(content).hexdigest()}
    assert updates.execute_update(command, LINK, tmp_path, public_key=key(signer), executable=installer,
                                  opener=no_network) == result


@pytest.mark.parametrize("failure", ["timeout", "interrupted", "receipt_write"])
def test_uncertain_execution_is_never_launched_twice(tmp_path, signer, linux_target, monkeypatch, failure):
    canonical, signature, content = signed(signer)
    command = job(canonical)
    installer = tmp_path / "local-installer.exe"
    installer.touch()
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if failure == "interrupted":
            raise KeyboardInterrupt
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(updates.subprocess, "run", run)
    if failure == "receipt_write":
        write_receipt = updates._write_receipt

        def write_intent_only(path, content):
            if content["status"] != "installing":
                raise OSError("disk full")
            write_receipt(path, content)

        monkeypatch.setattr(updates, "_write_receipt", write_intent_only)
    args = dict(public_key=key(signer), executable=installer, opener=remote(canonical, signature, content))
    if failure == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            updates.execute_update(command, LINK, tmp_path, **args)
    else:
        result = updates.execute_update(command, LINK, tmp_path, **args)
        assert result["status"] == "uncertain"
        assert result["code"] == ("executor_timeout" if failure == "timeout" else "executor_result_not_recorded")
    args["opener"] = no_network
    assert updates.execute_update(command, LINK, tmp_path, **args)["status"] == "uncertain"
    with pytest.raises(updates.UpdateError) as error:
        updates.execute_update(job(canonical, job_id="next-job"), LINK, tmp_path, **args)
    assert error.value.code == "previous_execution_unconfirmed"
    assert len(calls) == 1


def test_transient_download_error_leaves_job_retryable(tmp_path, signer, linux_target):
    canonical, signature, content = signed(signer)
    command = job(canonical)

    def unavailable(request, *, timeout):
        raise HTTPError(request.full_url, 503, "unavailable", {}, None)

    with pytest.raises(updates.UpdateDownloadError):
        updates.execute_update(command, LINK, tmp_path, public_key=key(signer), opener=unavailable)
    result = updates.execute_update(command, LINK, tmp_path, public_key=key(signer),
                                    opener=remote(canonical, signature, content))
    assert result["status"] == "staged"


@pytest.mark.parametrize("failure", ["network_read", "disk_write"])
def test_download_distinguishes_socket_failures_from_local_disk_errors(
    tmp_path, signer, linux_target, monkeypatch, failure,
):
    canonical, signature, content = signed(signer)

    def broken_io(*args, **kwargs):
        raise OSError("synthetic IO failure")

    if failure == "network_read":
        monkeypatch.setattr(Response, "read1", broken_io)
        error_type, code = updates.UpdateDownloadError, "download_unavailable"
    else:
        monkeypatch.setattr(updates, "_write_file", broken_io)
        error_type, code = updates.UpdateError, "local_storage_unavailable"
    with pytest.raises(error_type) as error:
        updates.execute_update(job(canonical), LINK, tmp_path, public_key=key(signer),
                               opener=remote(canonical, signature, content))
    assert type(error.value) is error_type
    assert error.value.code == code
    assert list((tmp_path / "federation-updates" / "packages").iterdir()) == []
