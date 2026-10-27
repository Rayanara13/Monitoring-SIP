"""Лаунчер офлайн-комплекта Monitoring SIP.

Запускается любым Python 3.10+ (встроенным из runtime/ или системным):
подкладывает зависимости из vendor/ и стартует app/server.py.
Ни pip, ни venv, ни интернета не нужно.
"""
import os
import runpy
import sys
from pathlib import Path

MIN_PY = (3, 10)

if sys.version_info < MIN_PY:
    sys.exit(
        f"Нужен Python {MIN_PY[0]}.{MIN_PY[1]} или новее, "
        f"а запущен {sys.version.split()[0]} ({sys.executable})."
    )

# Построчный вывод даже в pipe/журнал systemd: пароль admin при первом запуске
# должен появиться сразу, а не застрять в буфере.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "app"
SERVER = APP_DIR / "server.py"

sys.path.insert(0, str(ROOT / "vendor"))
# .env читает сам server.py; без этого Flask советует поставить python-dotenv
os.environ.setdefault("FLASK_SKIP_DOTENV", "1")
# server.py работает с относительными путями (auth.json, .env, users_data/)
os.chdir(APP_DIR)
sys.argv = [str(SERVER)]

print(f"Monitoring SIP: Python {sys.version.split()[0]} ({sys.executable})", flush=True)
runpy.run_path(str(SERVER), run_name="__main__")
