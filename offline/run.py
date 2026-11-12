"""Лаунчер офлайн-комплекта Инея.

Запускается любым Python 3.10+ (встроенным из runtime/ или системным):
подкладывает зависимости из vendor/ и запускает приложение.
Ни pip, ни venv, ни интернета не нужно.
"""
import argparse
import os
import sys
from pathlib import Path

MIN_PY = (3, 10)
ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "app"
ROLE_KEY = "MONITORING_SIP_ROLE"


def configure_first_start(env_path):
    if ROLE_KEY in os.environ or os.environ.get("VICTORIA_ROLE_GRANT"):
        return
    if (env_path.parent / "victoria-role.json").exists():
        return
    existing = env_path.read_text() if env_path.exists() else None
    if existing is not None and any(line.startswith((f"{ROLE_KEY}=", "VICTORIA_ROLE_GRANT=")) for line in existing.splitlines()):
        return

    prefix = "\n" if existing and not existing.endswith("\n") else ""
    flags = os.O_APPEND | os.O_WRONLY
    if existing is None:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(env_path, flags, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "a") as env_file:
        env_file.write(f"{prefix}{ROLE_KEY}=node\n")


def main():
    if sys.version_info < MIN_PY:
        sys.exit(
            f"Нужен Python {MIN_PY[0]}.{MIN_PY[1]} или новее, "
            f"а запущен {sys.version.split()[0]} ({sys.executable})."
        )

    # Построчный вывод в терминал и журнал systemd при первом запуске.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass

    sys.path[:0] = [str(APP_DIR), str(ROOT / "vendor")]
    # .env читает сам server.py; Flask не должен обрабатывать его повторно.
    os.environ.setdefault("FLASK_SKIP_DOTENV", "1")
    if sys.argv[1:2] == ["--lab"]:
        from simulator.app import main as start_lab

        del sys.argv[1]
        raise SystemExit(start_lab())

    parser = argparse.ArgumentParser(description="Запуск Инея")
    parser.add_argument("--data-dir", type=Path, default=APP_DIR, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if not arguments.data_dir.is_absolute():
        parser.error("--data-dir должен быть абсолютным путём")
    data_dir = arguments.data_dir.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    configure_first_start(data_dir / ".env")
    from release_install import supervise

    print(f"Иней: Python {sys.version.split()[0]} ({sys.executable})", flush=True)
    raise SystemExit(supervise(ROOT, data_dir))


if __name__ == "__main__":
    main()
