"""Проверка офлайн-пакетов и локальная передача установщику узла."""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
from typing import BinaryIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4096
CHUNK_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .+_-]{0,63}")
_FIELDS = {"version", "platform", "arch", "sha256", "size"}
_TARGETS = {("linux", "x86_64"), ("linux", "aarch64"), ("windows", "x86_64")}
_RECEIPT_CODES = {
    "installing": {"started"}, "staged": {"local_executor_not_configured"},
    "applied": {"executor_succeeded"}, "failed": {"executor_start_failed", "executor_failed"},
    "uncertain": {"executor_timeout"},
}


class UpdateError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class UpdateDownloadError(UpdateError):
    """Временный сбой до передачи установщику. Команду можно доставить повторно."""


def encode_url64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_url64(value: str, maximum: int, code: str) -> bytes:
    if (not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4
            or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value)):
        raise UpdateError(code, "Недопустимое поле в Base64.")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise UpdateError(code, "Недопустимое поле в Base64.") from None
    if len(raw) > maximum or encode_url64(raw).rstrip("=") != value.rstrip("="):
        raise UpdateError(code, "Недопустимое поле в Base64.")
    return raw


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UpdateError("invalid_manifest", "Манифест содержит повтор поля.")
        result[key] = value
    return result


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def canonical_manifest(value: bytes | str | dict) -> bytes:
    """Строгая схема и единственное представление для подписи Ed25519."""
    if isinstance(value, (bytes, str)):
        try:
            raw = value.encode("utf-8") if isinstance(value, str) else value
            if len(raw) > MAX_MANIFEST_BYTES:
                raise ValueError
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
        except (UnicodeError, ValueError, RecursionError):
            raise UpdateError("invalid_manifest", "Манифест должен быть небольшим объектом JSON.") from None
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise UpdateError("invalid_manifest", "Нужны ровно version, platform, arch, sha256 и size.")
    version, system, arch, digest, size = (value[key] for key in ("version", "platform", "arch", "sha256", "size"))
    if not isinstance(version, str) or not _VERSION.fullmatch(version) or version != version.strip():
        raise UpdateError("invalid_manifest", "Неверная версия пакета.")
    if not isinstance(system, str) or not isinstance(arch, str) or (system, arch) not in _TARGETS:
        raise UpdateError("invalid_manifest", "Неподдерживаемая ОС или архитектура пакета.")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise UpdateError("invalid_manifest", "Манифест должен содержать SHA-256 файла.")
    if type(size) is not int or not 1 <= size <= MAX_PACKAGE_BYTES:
        raise UpdateError("invalid_manifest", "Недопустимый размер пакета.")
    return _json_bytes(value)


def _signature(value: bytes | str) -> bytes:
    raw = _decode_url64(value, 64, "invalid_signature") if isinstance(value, str) else value
    if not isinstance(raw, bytes) or len(raw) != 64:
        raise UpdateError("invalid_signature", "Требуется подпись Ed25519 из 64 байт.")
    return raw


def _public_key(value: bytes | str):
    raw = _decode_url64(value, 32, "invalid_public_key") if isinstance(value, str) else value
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise UpdateError("invalid_public_key", "Ожидается открытый ключ Ed25519 из 32 байт.")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise UpdateError("crypto_unavailable", "В этом Python недоступна проверка Ed25519.") from None
    return Ed25519PublicKey.from_public_bytes(raw)


def _read_small(path: Path, maximum: int) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise UpdateError("local_data_invalid", "Повреждены локальные метаданные обновления.")
    return value


def _sync_directory(directory: Path) -> None:
    if os.name != "nt":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_file(path: Path, content: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _write_receipt(path: Path, content: dict) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".receipt-")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(_json_bytes(content))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _hash_stream(source: BinaryIO, size: int, target: BinaryIO | None = None) -> str:
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(CHUNK_BYTES, remaining))
        if not isinstance(chunk, bytes) or not chunk or len(chunk) > remaining:
            raise UpdateError("size_mismatch", "Размер файла не совпадает с манифестом.")
        remaining -= len(chunk)
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    if source.read(1) != b"":
        raise UpdateError("size_mismatch", "Размер файла не совпадает с манифестом.")
    return digest.hexdigest()


@dataclass(frozen=True)
class Package:
    id: str
    manifest: dict
    manifest_bytes: bytes
    signature: bytes
    path: Path

    @property
    def manifest_path(self) -> Path:
        return self.path.parent / "manifest.json"

    def public(self) -> dict:
        return {"package_id": self.id, **self.manifest}


class PackageStore:
    """Каталог проверенных пакетов. Публикация папки происходит одним rename."""

    def __init__(self, root: Path | str, public_key: bytes | str):
        self.key = _public_key(public_key)
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _verified(self, manifest: bytes | str | dict, signature: bytes | str) -> Package:
        from cryptography.exceptions import InvalidSignature

        canonical = canonical_manifest(manifest)
        signature = _signature(signature)
        try:
            self.key.verify(signature, canonical)
        except InvalidSignature:
            raise UpdateError("invalid_signature", "Подпись манифеста не прошла проверку.") from None
        package_id = hashlib.sha256(canonical).hexdigest()
        return Package(package_id, json.loads(canonical), canonical, signature,
                       self.root / package_id / "package.zip")

    def put(self, manifest_json: bytes | str | dict, signature: bytes | str, package: BinaryIO) -> Package:
        return self._put_verified(self._verified(manifest_json, signature), package)

    def _put_verified(self, metadata: Package, source: BinaryIO) -> Package:
        with tempfile.TemporaryDirectory(dir=self.root, prefix=".upload-") as name:
            stage = Path(name)
            with (stage / "package.zip").open("xb") as stream:
                digest = _hash_stream(source, metadata.manifest["size"], stream)
                if digest != metadata.manifest["sha256"]:
                    raise UpdateError("hash_mismatch", "SHA-256 файла не совпадает с манифестом.")
                stream.flush()
                os.fsync(stream.fileno())
            _write_file(stage / "manifest.json", metadata.manifest_bytes)
            _write_file(stage / "signature.ed25519", metadata.signature)
            _sync_directory(stage)
            try:
                stage.rename(metadata.path.parent)
            except OSError:
                if not metadata.path.parent.exists():
                    raise
                existing = self.lookup(metadata.id)
                self.verify_file(existing)
                return existing
            _sync_directory(self.root)
        return metadata

    def lookup(self, package_id: str) -> Package:
        if not isinstance(package_id, str) or not _SHA256.fullmatch(package_id):
            raise KeyError("unknown package")
        folder = self.root / package_id
        if not folder.is_dir():
            raise KeyError("unknown package")
        paths = [folder / name for name in ("manifest.json", "signature.ed25519", "package.zip")]
        if folder.is_symlink() or any(path.is_symlink() for path in paths):
            raise UpdateError("local_data_invalid", "Повреждён каталог пакета обновления.")
        try:
            canonical = _read_small(paths[0], MAX_MANIFEST_BYTES)
            signature = _read_small(paths[1], 64)
            metadata = self._verified(canonical, signature)
            if (metadata.id != package_id or canonical != metadata.manifest_bytes or not paths[2].is_file()
                    or paths[2].stat().st_size != metadata.manifest["size"]):
                raise UpdateError("local_data_invalid", "Повреждён пакет обновления.")
        except OSError:
            raise UpdateError("local_data_invalid", "Пакет обновления недоступен.") from None
        return metadata

    @staticmethod
    def verify_file(metadata: Package) -> None:
        with metadata.path.open("rb") as stream:
            actual = _hash_stream(stream, metadata.manifest["size"])
        if actual != metadata.manifest["sha256"]:
            raise UpdateError("hash_mismatch", "SHA-256 сохранённого файла не совпадает с манифестом.")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _TimedResponse:
    def __init__(self, response, deadline):
        self.read_chunk = getattr(response, "read1", response.read)
        self.deadline = deadline

    def read(self, size):
        try:
            if time.monotonic() >= self.deadline:
                raise TimeoutError
            value = self.read_chunk(size)
            if time.monotonic() >= self.deadline:
                raise TimeoutError
            return value
        except (OSError, http.client.HTTPException):
            raise UpdateDownloadError("download_unavailable", "Не удалось получить пакет обновления.") from None


def _center_url(link: dict) -> str:
    raw = link.get("url")
    if not isinstance(raw, str) or not 0 < len(raw) <= 512 or re.search(r"[\s\\\x00-\x1f\x7f]", raw):
        raise UpdateError("invalid_center_url", "Адрес сервера должен использовать HTTPS.")
    try:
        url = urlsplit(raw)
        port = url.port
    except ValueError:
        raise UpdateError("invalid_center_url", "Некорректный HTTPS-адрес сервера.") from None
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in {"", "/"} or port == 0):
        raise UpdateError("invalid_center_url", "Ожидается HTTPS-адрес сервера без пути и учётных данных.")
    return raw.rstrip("/")


def _local_target() -> tuple[str, str]:
    arch = platform.machine().lower()
    return platform.system().lower(), {"amd64": "x86_64", "arm64": "aarch64"}.get(arch, arch)


def _check_target(package: Package, payload: dict) -> None:
    if package.id != payload["package_id"]:
        raise UpdateError("package_mismatch", "Сервер вернул другой пакет обновления.")
    if (package.manifest["platform"], package.manifest["arch"]) != _local_target():
        raise UpdateError("target_mismatch", "Пакет предназначен для другой ОС или архитектуры.")
    if any(key in payload and payload[key] != package.manifest[key] for key in ("version", "platform", "arch")):
        raise UpdateError("target_mismatch", "Манифест не совпадает с заданием обновления.")


def _download(store: PackageStore, payload: dict, link: dict, opener, timeout: float) -> Package:
    url = _center_url(link) + "/api/federation/v1/update-packages/" + payload["package_id"]
    node, token = link.get("node_id"), link.get("token")
    if (not isinstance(node, str) or not _IDENT.fullmatch(node) or not isinstance(token, str)
            or not re.fullmatch(r"[!-~]{1,512}", token)):
        raise UpdateError("invalid_node_link", "У узла отсутствуют данные для загрузки обновления.")
    request = Request(url, headers={"Authorization": "Bearer " + token, "X-Node-Id": node,
                                    "Accept": "application/zip", "Accept-Encoding": "identity"})
    if opener is None:
        opener = build_opener(ProxyHandler({}), _NoRedirect()).open
    deadline = time.monotonic() + timeout
    try:
        with opener(request, timeout=timeout) as response:
            if response.status != 200 or response.geturl() != url or response.headers.get("Content-Encoding") not in {None, "identity"}:
                raise UpdateError("download_rejected", "Ответ загрузки обновления отклонён.")
            manifest = _decode_url64(response.headers.get("X-Update-Manifest"), MAX_MANIFEST_BYTES, "invalid_manifest")
            metadata = store._verified(manifest, response.headers.get("X-Update-Signature"))
            _check_target(metadata, payload)
            length = response.headers.get("Content-Length")
            if length is not None and length != str(metadata.manifest["size"]):
                raise UpdateError("size_mismatch", "Размер HTTP-ответа не совпадает с манифестом.")
            try:
                return store._put_verified(metadata, _TimedResponse(response, deadline))
            except OSError:
                raise UpdateError("local_storage_unavailable", "Хранилище обновлений на узле недоступно.") from None
    except HTTPError as error:
        if error.code in {408, 429} or error.code >= 500:
            raise UpdateDownloadError("download_unavailable", "Пакет временно недоступен на сервере.") from None
        raise UpdateError("download_rejected", "Сервер отклонил загрузку пакета.") from None
    except (OSError, URLError, http.client.HTTPException):
        raise UpdateDownloadError("download_unavailable", "Не удалось получить пакет обновления.") from None


@contextmanager
def _installation_lock(path: Path):
    try:
        with path.open("a+b") as stream:
            try:
                if os.name == "nt":
                    import msvcrt

                    if stream.tell() == 0:
                        stream.write(b"\0")
                        stream.flush()
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise UpdateDownloadError("update_busy", "Узел уже обрабатывает обновление.") from None
            yield
    except OSError:
        raise UpdateError("local_storage_unavailable", "Хранилище обновлений на узле недоступно.") from None


def _read_receipt(path: Path) -> dict:
    try:
        record = json.loads(_read_small(path, MAX_MANIFEST_BYTES))
        required = {"status", "code", "request_sha256", "package_id", "version"}
        if (not isinstance(record, dict) or set(record) not in (required, required | {"exit_code"})
                or record["status"] not in _RECEIPT_CODES or record["code"] not in _RECEIPT_CODES[record["status"]]
                or not _SHA256.fullmatch(record.get("request_sha256", ""))
                or not _SHA256.fullmatch(record.get("package_id", ""))
                or not _VERSION.fullmatch(record.get("version", ""))
                or ("exit_code" in record and type(record["exit_code"]) is not int)):
            raise ValueError
        return record
    except (OSError, ValueError, TypeError, RecursionError):
        raise UpdateError("receipt_invalid", "Повреждена запись о локальном обновлении.") from None


def _local_executor(executable: Path | str | None) -> Path | None:
    if executable is None:
        return None
    path = Path(executable)
    if not path.is_absolute() or not path.is_file():
        raise UpdateError("invalid_executor", "Укажите абсолютный путь к локальному установщику.")
    path = path.resolve()
    if os.name == "nt" and path.suffix.lower() != ".exe":
        raise UpdateError("invalid_executor", "Для Windows нужен локальный исполняемый файл .exe.")
    return path


def execute_update(command: dict, link: dict, data_dir: Path | str, *, public_key: bytes | str,
                   executable: Path | str | None = None, opener=None, download_timeout: float = 30,
                   executor_timeout: float = 1800, managed_role: str | None = None) -> dict:
    """Загрузить пакет и передать установщику. Связь и код запуска задаются локально.

    Переданный opener должен использовать проверенный TLS и запрещать редиректы.
    Статус uncertain сохраняет отметку запуска для ручной сверки результата.
    """
    if not isinstance(command, dict) or command.get("action") != "update.install" or not isinstance(link, dict):
        raise UpdateError("invalid_job", "Неверная команда установки обновления.")
    job_id, payload = command.get("id"), command.get("payload")
    if (not isinstance(job_id, str) or not _IDENT.fullmatch(job_id) or not isinstance(payload, dict)
            or set(payload) - {"package_id", "version", "platform", "arch"}
            or not isinstance(payload.get("package_id"), str) or not _SHA256.fullmatch(payload["package_id"])
            or any(not isinstance(value, str) or len(value) > 64 for value in payload.values())):
        raise UpdateError("invalid_job", "Недопустимые параметры задания обновления.")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
           or not 0 < value <= limit for value, limit in ((download_timeout, 300), (executor_timeout, 3600))):
        raise UpdateError("invalid_timeout", "Некорректные локальные таймауты обновления.")
    _center_url(link)
    try:
        root = Path(data_dir).resolve() / "federation-updates"
        jobs = root / "jobs"
        jobs.mkdir(mode=0o700, parents=True, exist_ok=True)
        _sync_directory(root)
        _sync_directory(root.parent)
    except OSError:
        raise UpdateError("local_storage_unavailable", "Хранилище обновлений на узле недоступно.") from None
    binding = hashlib.sha256(_json_bytes(payload)).hexdigest()
    with _installation_lock(root / ".executor.lock"):
        if managed_role is not None:
            from release_install import queue_update, update_result

            if previous := update_result(job_id, payload["package_id"]):
                return previous
            store = PackageStore(root / "packages", public_key)
            try:
                package = store.lookup(payload["package_id"])
                _check_target(package, payload)
            except KeyError:
                package = _download(store, payload, link, opener, download_timeout)
            store.verify_file(package)
            return queue_update(package, job_id, managed_role)

        receipt = jobs / f"{job_id}.json"
        if receipt.exists():
            previous = _read_receipt(receipt)
            if previous["request_sha256"] != binding:
                raise UpdateError("job_conflict", "ID задания уже относится к другому пакету.")
            result = {key: value for key, value in previous.items() if key != "request_sha256"}
            if result["status"] == "installing":
                result.update(status="uncertain", code="previous_execution_unconfirmed")
            return result

        installer = _local_executor(executable)
        if installer is not None and any(_read_receipt(path)["status"] in {"installing", "uncertain"}
                                         for path in jobs.glob("*.json")):
            raise UpdateError("previous_execution_unconfirmed", "Сначала проверьте результат предыдущей установки на узле.")
        store = PackageStore(root / "packages", public_key)
        package = _download(store, payload, link, opener, download_timeout)
        store.verify_file(package)
        result = {"package_id": package.id, "version": package.manifest["version"]}
        if installer is None:
            result.update(status="staged", code="local_executor_not_configured")
        else:
            _write_receipt(receipt, {**result, "request_sha256": binding, "status": "installing", "code": "started"})
            try:
                completed = subprocess.run(
                    [str(installer), "--package", str(package.path), "--manifest", str(package.manifest_path),
                     "--job-id", job_id],
                    cwd=root, shell=False, timeout=executor_timeout, check=False,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired:
                result.update(status="uncertain", code="executor_timeout")
            except OSError:
                result.update(status="failed", code="executor_start_failed")
            else:
                result.update(status="applied" if completed.returncode == 0 else "failed",
                              code="executor_succeeded" if completed.returncode == 0 else "executor_failed",
                              exit_code=completed.returncode)
        try:
            _write_receipt(receipt, {**result, "request_sha256": binding})
        except OSError:
            if installer is None:
                raise
            return {"package_id": package.id, "version": package.manifest["version"],
                    "status": "uncertain", "code": "executor_result_not_recorded"}
        return result
