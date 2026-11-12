"""Изоляция архива и настоящий перезапуск тестового процесса в офлайн-комплекте."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from threading import Event
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from federation_updates import PackageStore, canonical_manifest, encode_url64
import release_install as installer


ROOT = Path(__file__).resolve().parents[1]
APP_FILES = ("release_install.py", "federation_updates.py")
DATA_FILES = {
    ".env": b"MONITORING_SIP_ROLE=node\nTEST_SETTING=preserve\n",
    "auth.json": b'{"fixture":"keep existing auth"}',
    "ping-trust.json": b'{"addresses":["192.0.2.17"]}',
    "users_data/phones_admin.json": b'[{"number":"9701","name":"Keep existing card"}]',
}


@pytest.mark.skipif(os.name != "nt", reason="Windows readers can deny atomic replace")
def test_release_receipt_waits_for_a_transient_windows_reader(tmp_path):
    target = tmp_path / "active.json"
    installer._write(target, {"id": "previous"})
    starting = Event()

    def update():
        starting.set()
        installer._write(target, {"id": "candidate"})

    with ThreadPoolExecutor(max_workers=1) as executor:
        with target.open("rb"):
            pending = executor.submit(update)
            assert starting.wait(2)
            time.sleep(0.15)
            assert not pending.done()
        pending.result(timeout=2)
    assert installer._read(target) == {"id": "candidate"}


def worker_source(version, *, broken=False):
    return f"""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import time
from release_install import PACKAGE_ENV, mark_ready, wait_for_activation

if {broken!r}:
    Path(".env").write_text("broken candidate")
    Path("auth.json").write_text("broken candidate")
    Path("ping-trust.json").write_text('{{"addresses":["192.0.2.88"]}}')
    Path("users_data/phones_admin.json").write_text("broken candidate")
    Path("users_data/candidate-only.json").write_text("remove after rollback")
    with closing(sqlite3.connect("users_data/call_history.db")) as db, db:
        db.execute("DELETE FROM calls")

with Path("worker-starts.jsonl").open("a", encoding="utf-8") as witness:
    note = Path(__file__).parent / "assets" / "fixture.txt"
    witness.write(json.dumps({{
        "version": {version!r}, "pid": os.getpid(), "cwd": str(Path.cwd()),
        "package_id": os.environ[PACKAGE_ENV],
        "note": note.read_text(encoding="utf-8") if note.is_file() else None,
    }}) + "\\n")
mark_ready("Rel 0.0" if {broken!r} else {version!r}, "node")
wait_for_activation()
while not Path("stop-test-worker").exists():
    time.sleep(0.05)
"""


def signed_archive(store, signer, version, members):
    source = io.BytesIO()
    with ZipFile(source, "w", compression=ZIP_DEFLATED, compresslevel=1) as archive:
        for name, contents in members:
            archive.writestr(name, contents)
    content = source.getvalue()
    system, arch = installer._local_target()
    manifest = canonical_manifest({"version": version, "platform": system, "arch": arch,
                                   "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)})
    return store.put(manifest, signer.sign(manifest), io.BytesIO(content))


def kit_members(version, runtime, *, broken=False):
    yield "MonitoringSIP/app/server.py", worker_source(version, broken=broken)
    yield "MonitoringSIP/app/login.html", b"test login page"
    yield "MonitoringSIP/app/panel.html", b"test panel page"
    for name in APP_FILES:
        yield "MonitoringSIP/app/" + name, (ROOT / name).read_bytes()
    yield "MonitoringSIP/vendor/fixture.txt", b"test runtime"
    yield from runtime


def runtime_path():
    kit = Path("MonitoringSIP")
    return installer._python(kit).as_posix()


def real_runtime_members():
    name = runtime_path()
    if os.name == "nt":
        base_python = Path(sys._base_executable)
        yield name, base_python.read_bytes()
        for library in base_python.parent.glob("*.dll"):
            yield str(Path(name).parent / library.name).replace("\\", "/"), library.read_bytes()
    else:
        # Исполнитель архива вызывает настоящий Python с тем же PID, что и launcher.
        yield name, "#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n'


@pytest.mark.parametrize("violation", ["traversal", "symlink", "role"])
def test_signed_archive_rejects_unsafe_paths_and_role_mismatch(tmp_path, violation):
    signer = Ed25519PrivateKey.generate()
    store = PackageStore(tmp_path / "packages", signer.public_key().public_bytes_raw())
    members = list(kit_members("Rel 1.3.3", [(runtime_path(), b"unused runtime")]))
    if violation == "traversal":
        members.append(("MonitoringSIP/app/../../outside.txt", b"escaped"))
    elif violation == "symlink":
        link = ZipInfo("MonitoringSIP/app/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        members.append((link, b"../../outside.txt"))
    else:
        members.append(("MonitoringSIP/app/federation_center.py", b"unexpected center module"))
    package = signed_archive(store, signer, "Rel 1.3.3", members)
    target = tmp_path / "candidate"
    with pytest.raises(ValueError):
        installer._prepare(package, target, tmp_path / "original", "node")
    assert not target.exists()
    assert not (tmp_path / "outside.txt").exists()
    assert list(tmp_path.glob(".extract-*")) == []


def wait_for(process, log, check):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            details = log.read_bytes()[-4096:].decode("utf-8", errors="replace")
            pytest.fail(f"Супервизор завершился с кодом {process.returncode}\n{details}")
        if result := check():
            return result
        time.sleep(0.05)
    pytest.fail("Супервизор не подтвердил ожидаемое состояние")


def starts(data):
    witness = data / "worker-starts.jsonl"
    if not witness.exists():
        return []
    return [json.loads(line) for line in witness.read_text(encoding="utf-8").split("\n")[:-1]]


def assert_data_preserved(data, expected_calls):
    for name, contents in DATA_FILES.items():
        assert (data / name).read_bytes() == contents
    assert not (data / "users_data" / "candidate-only.json").exists()
    with closing(sqlite3.connect(data / "users_data/call_history.db")) as db:
        assert db.execute("SELECT id FROM calls ORDER BY id").fetchall() == expected_calls


def test_offline_supervisor_restarts_rolls_back_and_accepts_an_explicit_older_release(tmp_path, monkeypatch):
    original, data = tmp_path / "kit", tmp_path / "persistent-data"
    (original / "app").mkdir(parents=True)
    shutil.copyfile(ROOT / "offline/run.py", original / "run.py")
    for name in APP_FILES:
        shutil.copyfile(ROOT / name, original / "app" / name)
    (original / "app/server.py").write_text(worker_source("Rel 1.3.2"), encoding="utf-8")
    runtime = tuple(real_runtime_members())
    for name, content in runtime:
        destination = original / Path(name).relative_to("MonitoringSIP")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    if os.name != "nt":
        installer._python(original).chmod(0o700)
    (data / "users_data").mkdir(parents=True)
    for name, contents in DATA_FILES.items():
        (data / name).write_bytes(contents)
    db_path = data / "users_data/call_history.db"
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("CREATE TABLE calls(id INTEGER PRIMARY KEY)")
        db.execute("INSERT INTO calls(id) VALUES (1)")

    signer = Ed25519PrivateKey.generate()
    public_key = signer.public_key().public_bytes_raw()
    store = PackageStore(data / "users_data/federation-updates/packages", public_key)
    upgrade = signed_archive(store, signer, "Rel 1.3.3", kit_members("Rel 1.3.3", runtime))
    broken = signed_archive(store, signer, "Rel 1.3.4", kit_members("Rel 1.3.4", runtime, broken=True))
    older = signed_archive(store, signer, "Rel 1.3.1", kit_members("Rel 1.3.1", runtime))

    state = data / "users_data/.managed-release"
    monkeypatch.setenv(installer.STATE_ENV, str(state))
    env = {**os.environ, "FEDERATION_UPDATE_PUBLIC_KEY": encode_url64(public_key), "PYTHONUTF8": "1"}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(Path(cryptography.__file__).resolve().parents[1]),
                                                       env.get("PYTHONPATH"))))
    if os.name == "nt":
        env["PYTHONHOME"] = sys.base_prefix

    log = tmp_path / "supervisor.log"
    with log.open("wb") as output:
        process = subprocess.Popen([sys.executable, "-B", str(original / "run.py"), "--data-dir", str(data)],
                                   cwd=tmp_path, env=env, stdout=output, stderr=subprocess.STDOUT)

    def wait_result(get_result):
        def finished():
            if (state / "request.json").exists() or (state / "transaction.json").exists():
                return None
            result = get_result()
            return result if result and result["status"] in {"applied", "failed"} else None

        return wait_for(process, log, finished)

    try:
        initial = wait_for(process, log, lambda: starts(data))
        assert initial[0]["version"] == "Rel 1.3.2" and not initial[0]["package_id"]

        assert installer.queue_update(upgrade, "test-upgrade", "node")["status"] == "running"
        installed = wait_result(lambda: installer.update_result("test-upgrade", upgrade.id))
        assert installed["status"] == "applied" and installed["version"] == "Rel 1.3.3"
        assert_data_preserved(data, [(1,)])
        assert installer.queue_update(upgrade, "test-upgrade", "node") == installed

        with closing(sqlite3.connect(db_path)) as db, db:
            db.execute("INSERT INTO calls(id) VALUES (2)")
        assert installer.queue_update(broken, "test-broken", "node")["status"] == "running"
        rejected = wait_result(lambda: installer.update_result("test-broken", broken.id))
        assert rejected["status"] == "failed" and "rolled_back" in rejected["code"]
        wait_for(process, log, lambda: len(starts(data)) >= 4)
        assert_data_preserved(data, [(1,), (2,)])
        assert json.loads((state / "active.json").read_bytes())["package_id"] == upgrade.id

        assert installer.queue_update(older, "test-older", "node")["status"] == "running"
        downgraded = wait_result(lambda: installer.update_result("test-older", older.id))
        assert downgraded["status"] == "applied" and downgraded["version"] == "Rel 1.3.1"
        observed = starts(data)
        assert [row["version"] for row in observed] == [
            "Rel 1.3.2", "Rel 1.3.3", "Rel 1.3.4", "Rel 1.3.3", "Rel 1.3.1",
        ]
        assert len({row["pid"] for row in observed}) == len(observed)
        assert all(Path(row["cwd"]) == data for row in observed)
        assert [row["package_id"] for row in observed] == ["", upgrade.id, broken.id, upgrade.id, older.id]
        assert_data_preserved(data, [(1,), (2,)])
        assert not (state / "request.json").exists()
        assert not (state / "transaction.json").exists()

        monkeypatch.setenv(installer.PACKAGE_ENV, older.id)
        with pytest.raises(ValueError):
            installer.queue_maintenance("write", "Rel 1.3.1", "node", path=".env", contents=b"invalid")
        assert not (state / "request.json").exists()

        def maintenance(action, **change):
            queued = installer.queue_maintenance(action, "Rel 1.3.1", "node", **change)
            assert queued["status"] == "running"
            job_id = queued["job_id"]

            result = wait_result(lambda: installer.maintenance_status(job_id))
            assert result["package_id"] == older.id
            assert not (state / "incoming" / f"{job_id}.bin").exists()
            return result

        note_path = "assets/fixture.txt"
        written = maintenance("write", path=note_path, contents=b"test maintenance content")
        assert written["status"] == "applied"
        after_write = starts(data)[-1]
        assert after_write["pid"] != observed[-1]["pid"]
        assert after_write["version"] == "Rel 1.3.1" and after_write["note"] == "test maintenance content"
        active_after_write = json.loads((state / "active.json").read_bytes())
        assert active_after_write == {"id": written["job_id"], "package_id": older.id}

        protected = maintenance("delete", path="server.py")
        assert protected["status"] == "failed"
        assert starts(data)[-1] == after_write
        assert json.loads((state / "active.json").read_bytes()) == active_after_write

        deleted = maintenance("delete", path=note_path)
        assert deleted["status"] == "applied"
        after_delete = starts(data)[-1]
        assert after_delete["pid"] != after_write["pid"]
        assert after_delete["note"] is None
        active_after_delete = json.loads((state / "active.json").read_bytes())
        assert active_after_delete == {"id": deleted["job_id"], "package_id": older.id}

        restarted = maintenance("restart")
        assert restarted["status"] == "applied"
        assert starts(data)[-1]["pid"] != after_delete["pid"]
        assert json.loads((state / "active.json").read_bytes()) == active_after_delete
        assert_data_preserved(data, [(1,), (2,)])
    finally:
        # Останавливаем текущий тестовый worker через его собственный sentinel.
        (data / "stop-test-worker").touch()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
