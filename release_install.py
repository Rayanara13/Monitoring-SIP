"""Local supervisor for verified releases. Application data stays in one directory."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import os
import re
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

def _worker(release, data):
    release = Path(release).resolve()
    sys.path[:0] = [str(release / "app"), str(release / "vendor")]
    os.chdir(data)
    server = release / "app" / "server.py"
    sys.argv = [str(server)]
    runpy.run_path(str(server), run_name="__main__")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--worker":
        raise SystemExit("Use the offline kit launcher.")
    _worker(sys.argv[2], sys.argv[3])
    raise SystemExit(0)

from federation_updates import PackageStore, UpdateDownloadError, UpdateError, _installation_lock, _local_target, _write_receipt


STATE_ENV = "INEI_UPDATE_STATE"
READY_ENV = "INEI_UPDATE_READY"
PACKAGE_ENV = "INEI_RUNNING_PACKAGE"
ACTIVATION_ENV = "INEI_ACTIVATION_JOB"
_JOB = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")
_HASH = re.compile(r"[a-f0-9]{64}")
_ROLES = {"node", "victoria"}
_MAX_EXTRACTED = 768 * 1024 * 1024
_MAX_ENTRIES = 20_000
_PRIVATE = {".env", "auth.json", "ping-trust.json", "victoria-role.json", "victoria_role_authority.pem", "users_data"}
_MAX_MAINTENANCE_FILE = 10 * 1024 * 1024


def _read(path):
    import json

    if not path.exists():
        return None
    with path.open("rb") as source:
        record = json.loads(source.read(16_385))
    if not isinstance(record, dict):
        raise ValueError("invalid local update record")
    return record


def _write(path, record):
    path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    _write_receipt(path, record)


def managed():
    return bool(os.environ.get(STATE_ENV))


def _check_ids(job_id, package_id):
    if (not isinstance(job_id, str) or not _JOB.fullmatch(job_id)
            or not isinstance(package_id, str) or not _HASH.fullmatch(package_id)):
        raise UpdateError("invalid_job", "Некорректное локальное задание обновления.")


def update_result(job_id, package_id):
    _check_ids(job_id, package_id)
    record = _read(Path(os.environ[STATE_ENV]) / "results" / f"{job_id}.json")
    if record and record["package_id"] != package_id:
        raise UpdateError("job_conflict", "ID задания относится к другому пакету.")
    return record


def queue_update(package, job_id, role):
    _check_ids(job_id, package.id)
    if not managed() or role not in _ROLES:
        raise UpdateError("managed_update_unavailable", "Запустите сервер штатным установщиком.")
    root = Path(os.environ[STATE_ENV])
    job = {"id": job_id, "package_id": package.id, "version": package.manifest["version"], "role": role}
    with _installation_lock(root / "queue.lock"):
        if result := update_result(job_id, package.id):
            return result
        waiting = _read(root / "request.json")
        if waiting is not None and waiting != job:
            raise UpdateDownloadError("update_busy", "Дождитесь завершения текущего обновления.")
        if waiting is None:
            _write(root / "request.json", job)
    return {"status": "running", "code": "installation_queued", "package_id": package.id, "version": job["version"]}


def maintenance_status(job_id):
    if not managed() or not isinstance(job_id, str) or not _JOB.fullmatch(job_id):
        return None
    root = Path(os.environ[STATE_ENV])
    if result := _read(root / "results" / f"{job_id}.json"):
        return result
    waiting = _read(root / "request.json")
    if waiting and waiting["id"] == job_id and waiting.get("kind") == "maintenance":
        return {"job_id": job_id, "status": "running", "code": "maintenance_queued"}
    return None


def _maintenance_path(path):
    if (not isinstance(path, str) or not 1 <= len(path) <= 240 or "\\" in path
            or any(ord(character) < 32 for character in path)):
        raise UpdateError("file_change_rejected", "Недопустимый путь файла.")
    parts = path.split("/")
    protected = _PRIVATE | {"release_install.py", "run.py", "bootstrap.py", "update_authority.pub",
                             "config", "keys", "certs", "backup", "__pycache__"}
    if any(not part or part.startswith(".") or ":" in part or part.rstrip(". ") != part
           or part.casefold() in protected or part.casefold().endswith((".key", ".pem", ".bak", ".old", "~"))
           or re.match(r"(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", part) for part in parts):
        raise UpdateError("file_change_rejected", "Недопустимый путь файла.")
    return parts


def queue_maintenance(action, version, role, *, path=None, contents=None, job_id=None):
    if not managed() or role not in _ROLES:
        raise UpdateError("managed_update_unavailable", "Запустите сервер штатным установщиком.")
    if action not in {"restart", "write", "delete"}:
        raise UpdateError("invalid_job", "Недопустимая операция с приложением.")
    if action != "restart":
        _maintenance_path(path)
    if action == "write" and (not isinstance(contents, bytes) or len(contents) > _MAX_MAINTENANCE_FILE):
        raise UpdateError("file_change_rejected", "Файл слишком большой.")
    root = Path(os.environ[STATE_ENV])
    job_id = uuid4().hex if job_id is None else job_id
    package_id = os.environ.get(PACKAGE_ENV) or None
    _check_ids(job_id, package_id or "0" * 64)
    job = {"id": job_id, "kind": "maintenance", "action": action, "role": role,
           "package_id": package_id, "version": version, "path": path}
    with _installation_lock(root / "queue.lock"):
        if (root / "request.json").exists():
            raise UpdateDownloadError("update_busy", "Дождитесь завершения текущей операции.")
        if action == "write":
            import hashlib

            incoming = root / "incoming" / f"{job_id}.bin"
            incoming.parent.mkdir(mode=0o700, exist_ok=True)
            with incoming.open("xb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
            job["sha256"] = hashlib.sha256(contents).hexdigest()
        _write(root / "request.json", job)
    return {"job_id": job_id, "status": "running", "code": "maintenance_queued"}


def mark_ready(version, role):
    if filename := os.environ.get(READY_ENV):
        _write(Path(filename), {"version": version, "role": role, "pid": os.getpid()})


def wait_for_activation():
    """Wait for the supervisor to commit a candidate before publishing its state."""
    if not (job_id := os.environ.get(ACTIVATION_ENV)):
        return
    _check_ids(job_id, "0" * 64)
    active = Path(os.environ[STATE_ENV]) / "active.json"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if (_read(active) or {}).get("id") == job_id:
                return
        except OSError:
            pass  # A concurrent atomic replace can briefly block a Windows reader.
        time.sleep(0.05)
    raise RuntimeError("candidate activation was not committed by the supervisor")


def update_public_key(app_dir, data):
    value = os.environ.get("FEDERATION_UPDATE_PUBLIC_KEY")
    if value is not None:
        return value
    try:
        lines = (data / ".env").read_text().splitlines()
    except FileNotFoundError:
        lines = []
    setting = next((line.split("=", 1)[1].strip() for line in lines if line.startswith("FEDERATION_UPDATE_PUBLIC_KEY=")), "")
    if setting:
        return setting
    try:
        return (Path(app_dir) / "update_authority.pub").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return ""


def _archive_files(archive):
    seen = set()
    size = 0
    entries = archive.infolist()
    if len(entries) > _MAX_ENTRIES:
        raise ValueError("archive has too many files")
    for entry in entries:
        name = entry.filename
        parts = PurePosixPath(name).parts
        if (len(parts) < 2 or parts[0] != "MonitoringSIP" or name.startswith("/") or "\\" in name
                or any(part in {"", ".", ".."} or ":" in part or part.rstrip(". ") != part
                       for part in name.rstrip("/").split("/"))
                or stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG, stat.S_IFDIR}):
            raise ValueError("invalid archive member")
        relative = parts[1:]
        if relative[0] not in {"app", "vendor", "runtime"}:
            continue
        if relative[0] == "app" and any(part.lower() in _PRIVATE or part.lower().endswith((".pem", ".key"))
                                        for part in relative):
            raise ValueError("private file in update")
        key = "/".join(relative).casefold()
        if key in seen:
            raise ValueError("duplicate archive member")
        seen.add(key)
        size += entry.file_size
        if size > _MAX_EXTRACTED:
            raise ValueError("archive is too large after extraction")
        if not entry.is_dir():
            yield entry, relative


def _python(kit):
    if os.name == "nt":
        return kit / "runtime" / "windows" / "python.exe"
    return kit / "runtime" / "linux" / "python" / "bin" / "python3.13"


def _prepare(package, target, original, role):
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".extract-") as temporary:
        stage = Path(temporary)
        with ZipFile(package.path) as archive:
            for entry, relative in _archive_files(archive):
                output = stage.joinpath(*relative)
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, output.open("xb") as dest:
                    shutil.copyfileobj(source, dest, 1024 * 1024)
        app = stage / "app"
        central = (app / "federation_center.py").is_file()
        if (central != (role == "victoria") or not all((app / f).is_file() for f in
                ("server.py", "release_install.py", "federation_updates.py")) or not _python(stage).is_file()
                or not (stage / "vendor").is_dir()):
            raise ValueError("incorrect update profile or runtime")
        if central:
            shutil.copyfile(original / "app" / "victoria_role_authority.pem", app / "victoria_role_authority.pem")
        anchor = original / "app" / "update_authority.pub"
        if anchor.is_file():
            shutil.copyfile(anchor, app / anchor.name)
        if os.name != "nt":
            _python(stage).chmod(0o700)
        stage.rename(target)


def _mutable_files(data):
    for name in (".env", "auth.json", "ping-trust.json"):
        if (data / name).is_file():
            yield Path(name)
    for item in (data / "users_data").iterdir():
        if item.is_file() and (item.name == "first-start.txt"
                               or re.search(r"\.(?:json|db|sqlite3)(?:-wal|-shm|-journal)?$", item.name)):
            yield item.relative_to(data)


def _prepare_file_change(state, job, current, target):
    import hashlib

    parts = _maintenance_path(job["path"])
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".edit-") as temporary:
        stage = Path(temporary)

        def excluded(folder, names):
            return {name for name in names if name.casefold() in _PRIVATE - {"victoria_role_authority.pem"}
                    or name == "__pycache__" or (Path(folder) / name).is_symlink()}

        shutil.copytree(current / "app", stage / "app", ignore=excluded)
        for name in ("runtime", "vendor"):
            shutil.copytree(current / name, stage / name, symlinks=True)
        app = stage / "app"
        output = app.joinpath(*parts)
        if not output.resolve().is_relative_to(app.resolve()):
            raise ValueError("file resolves outside application")
        if job["action"] == "write":
            incoming = state / "incoming" / f"{job['id']}.bin"
            with incoming.open("rb") as stream:
                contents = stream.read(_MAX_MAINTENANCE_FILE + 1)
            if len(contents) > _MAX_MAINTENANCE_FILE or hashlib.sha256(contents).hexdigest() != job["sha256"]:
                raise ValueError("queued file has changed")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(contents)
        elif job["action"] == "delete":
            output.unlink()
        else:
            raise ValueError("unsupported file action")
        required = {"server.py", "release_install.py", "login.html", "panel.html"}
        if job["role"] == "victoria":
            required.update({"federation.html", "server_admin.html", "federation_identity.py"})
        if not all((app / name).is_file() for name in required):
            raise ValueError("required application file missing")
        stage.rename(target)


def _snapshot(data, backup):
    backup.mkdir(mode=0o700)
    for relative in _mutable_files(data):
        target = backup / relative
        target.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copy2(data / relative, target)


def _restore(data, backup):
    files = {path.relative_to(backup) for path in backup.rglob("*") if path.is_file()}
    for relative in set(_mutable_files(data)) - files:
        (data / relative).unlink()
    for relative in files:
        target = data / relative
        # A firewall helper may read ping-trust.json while rollback is restoring it.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".restore-", delete=False) as output:
                temporary = Path(output.name)
                with (backup / relative).open("rb") as original:
                    shutil.copyfileobj(original, output)
                output.flush()
                os.fsync(output.fileno())
            shutil.copystat(backup / relative, temporary)
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def _finish(state, job, status, code):
    result = {"status": status, "code": code, "package_id": job["package_id"], "version": job["version"]}
    if job.get("kind") == "maintenance":
        result["job_id"] = job["id"]
        result["finished_at"] = int(time.time())
    _write(state / "results" / f"{job['id']}.json", result)
    if job.get("kind") == "maintenance":
        (state / "incoming" / f"{job['id']}.bin").unlink(missing_ok=True)
    (state / "request.json").unlink(missing_ok=True)
    (state / "transaction.json").unlink(missing_ok=True)


def _stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def _spawn(original, release, data, state, package, *, activation_job=None):
    ready = state / f"ready-{uuid4().hex}.json"
    env = {**os.environ, STATE_ENV: str(state), READY_ENV: str(ready), PACKAGE_ENV: package or "",
           "FLASK_SKIP_DOTENV": "1"}
    if activation_job is None:
        env.pop(ACTIVATION_ENV, None)
    else:
        env[ACTIVATION_ENV] = activation_job
    env.setdefault("PYTHONIOENCODING", "utf-8")
    python = _python(release)
    if release == original and not python.is_file():
        python = Path(getattr(sys, "_base_executable", sys.executable) if os.name == "nt" else sys.executable)
    bootstrap = original / "app" / "release_install.py"
    child = subprocess.Popen([str(python), "-u", "-B", str(bootstrap), "--worker", str(release), str(data)],
                             cwd=data, env=env)
    return child, ready


def _wait_ready(child, ready, *, version=None, role=None):
    deadline = time.monotonic() + 25
    try:
        while child.poll() is None and time.monotonic() < deadline:
            if info := _read(ready):
                if (info["pid"] == child.pid and (version is None or info["version"] == version)
                        and (role is None or info["role"] == role)):
                    return True
                break
            time.sleep(0.2)
        return False
    finally:
        ready.unlink(missing_ok=True)


def _local_package(original, data, job):
    _check_ids(job.get("id"), job.get("package_id"))
    if job.get("role") not in _ROLES:
        raise ValueError("invalid role")
    suffix = "update_packages" if job["role"] == "victoria" else "federation-updates/packages"
    store = PackageStore(data / "users_data" / suffix, update_public_key(original / "app", data))
    package = store.lookup(job["package_id"])
    if ((package.manifest["platform"], package.manifest["arch"]) != _local_target()
            or package.manifest["version"] != job["version"]):
        raise ValueError("package target does not match")
    store.verify_file(package)
    return package


def _remove_tree(state, folder):
    if folder.is_dir() and not folder.is_symlink() and folder.resolve().is_relative_to(state.resolve()):
        shutil.rmtree(folder)


def _recover_transaction(state, data, active):
    if job := _read(state / "transaction.json"):
        _check_ids(job["id"], job["package_id"] or "0" * 64)
        backup = state / "backup" / job["id"]
        committed = active.get("id") == job["id"]
        if not committed:
            _restore(data, backup)
            _remove_tree(state, state / "versions" / job["id"])
        _finish(state, job, "applied" if committed else "failed",
                "restart_verified" if committed else "interrupted_rolled_back")
        _remove_tree(state, backup)


def _switch(original, state, data, child, active, job):
    maintenance = job.get("kind") == "maintenance"
    _check_ids(job.get("id"), job.get("package_id") or ("0" * 64 if maintenance else None))
    previous = state / "versions" / active["id"] if active else original
    if maintenance and job.get("action") == "restart":
        _stop(child)
        child, ready = _spawn(original, previous, data, state, active.get("package_id"))
        if _wait_ready(child, ready, version=job["version"], role=job["role"]):
            _finish(state, job, "applied", "restart_verified")
            return child, active
        _stop(child)
        _finish(state, job, "failed", "restart_failed")
        raise RuntimeError("application did not restart")
    target = state / "versions" / job["id"]
    backup = state / "backup" / job["id"]
    try:
        _remove_tree(state, target)
        if maintenance:
            _prepare_file_change(state, job, previous, target)
        else:
            package = _local_package(original, data, job)
            _prepare(package, target, original, job["role"])
    except (OSError, ValueError, KeyError, BadZipFile):
        _finish(state, job, "failed", "file_change_rejected" if maintenance else "package_cannot_be_installed")
        return child, active

    _stop(child)
    try:
        _remove_tree(state, backup)
        _snapshot(data, backup)
        _write(state / "transaction.json", job)
        child, ready = _spawn(original, target, data, state, job["package_id"], activation_job=job["id"])
        if _wait_ready(child, ready, version=job["version"], role=job["role"]):
            installed = {"id": job["id"], "package_id": job["package_id"]}
            _write(state / "active.json", installed)
            active = installed
        else:
            _stop(child)
    except (OSError, ValueError):
        _stop(child)
    finally:
        if (state / "transaction.json").exists():
            _recover_transaction(state, data, active)
        _remove_tree(state, backup)
    if active.get("id") == job["id"]:
        for old in (state / "versions").iterdir():
            if old != target and _JOB.fullmatch(old.name):
                _remove_tree(state, old)
        return child, active
    if not (state / "results" / f"{job['id']}.json").exists():
        _finish(state, job, "failed", "installation_rolled_back")
    replacement, ready = _spawn(original, previous, data, state, active.get("package_id"))
    if not _wait_ready(replacement, ready):
        _stop(replacement)
        raise RuntimeError("previous release did not restart")
    return replacement, active


def supervise(kit_root, data_dir):
    original, data = Path(kit_root).resolve(), Path(data_dir).resolve()
    state = data / "users_data" / ".managed-release"
    for name in ("versions", "backup", "results"):
        (state / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    stopping = False

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    previous_signals = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    child = None
    try:
        with _installation_lock(state / "supervisor.lock"):
            active = _read(state / "active.json") or {}
            if active:
                _check_ids(active["id"], active["package_id"] or "0" * 64)
            _recover_transaction(state, data, active)
            release = state / "versions" / active["id"] if active else original
            child, ready = _spawn(original, release, data, state, active.get("package_id"))
            if not _wait_ready(child, ready):
                return child.poll() or 1
            while not stopping and child.poll() is None:
                if job := _read(state / "request.json"):
                    child, active = _switch(original, state, data, child, active, job)
                else:
                    time.sleep(0.3)
            return 0 if stopping else child.returncode
    finally:
        if child is not None:
            _stop(child)
        for sig, handler in previous_signals.items():
            signal.signal(sig, handler)
