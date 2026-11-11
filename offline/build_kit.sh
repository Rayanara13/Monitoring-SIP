#!/usr/bin/env bash
# Сборка офлайн-комплекта Monitoring SIP (Windows x64 + Linux x86_64) в один zip.
# Нужен интернет на машине сборки. Код приложения берётся из HEAD (git archive),
# поэтому незакоммиченные правки в комплект НЕ попадут.
#   bash offline/build_kit.sh          -> dist/MonitoringSIP_offline_<hash>.zip
set -euo pipefail

PY_VER=3.13.15
PBS_TAG=20260929   # релиз astral-sh/python-build-standalone с CPython $PY_VER

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CACHE="$HERE/.cache"
REV="$(git -C "$REPO" rev-parse --short HEAD)"
KIT="$REPO/dist/MonitoringSIP"
ZIP="$REPO/dist/MonitoringSIP_offline_${REV}.zip"

WIN_ZIP="python-${PY_VER}-embed-amd64.zip"
WIN_URL="https://www.python.org/ftp/python/${PY_VER}/${WIN_ZIP}"
LIN_TGZ="cpython-${PY_VER}+${PBS_TAG}-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
LIN_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${LIN_TGZ//+/%2B}"

if [ -n "$(git -C "$REPO" status --porcelain -- server.py yealink_setup.py panel.html login.html static)" ]; then
    echo "ВНИМАНИЕ: в коде приложения есть незакоммиченные правки — в комплект идёт HEAD ($REV)." >&2
fi

mkdir -p "$CACHE/wheels"
[ -f "$CACHE/$WIN_ZIP" ] || curl -fSL -o "$CACHE/$WIN_ZIP" "$WIN_URL"
[ -f "$CACHE/$LIN_TGZ" ] || curl -fSL -o "$CACHE/$LIN_TGZ" "$LIN_URL"

# Колёса по пиннам: чистый Python + markupsafe под обе платформы (его C-ускоритель
# подхватится только встроенным 3.13, прочие версии возьмут чистую реализацию).
PIPDL=(python3 -m pip download -q --no-deps --only-binary=:all: --python-version 3.13
       --implementation cp -d "$CACHE/wheels")
"${PIPDL[@]}" --platform win_amd64 -r "$HERE/requirements.lock"
"${PIPDL[@]}" --platform manylinux2014_x86_64 "$(grep -i '^markupsafe==' "$HERE/requirements.lock")"

rm -rf "$KIT" && mkdir -p "$KIT/app" "$KIT/vendor" "$KIT/runtime/windows" "$KIT/runtime/linux"

# Приложение — только отслеживаемые файлы из HEAD (без auth.json, .env, users_data/)
git -C "$REPO" archive HEAD server.py yealink_setup.py panel.html login.html static | tar -x -C "$KIT/app"

# vendor/: распакованные колёса из лока (по одной версии каждого пакета)
python3 - "$HERE/requirements.lock" "$CACHE/wheels" "$KIT/vendor" <<'EOF'
import re, sys, zipfile
from pathlib import Path
lock, wheels, dest = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
norm = lambda s: re.sub(r"[-_.]+", "_", s).lower()
pins = dict(l.strip().split("==") for l in lock.read_text().splitlines()
            if l.strip() and not l.startswith("#"))
for name, ver in pins.items():
    found = [w for w in wheels.glob("*.whl")
             if norm(w.name.split("-")[0]) == norm(name) and w.name.split("-")[1] == ver]
    if not found:
        sys.exit(f"нет колеса для {name}=={ver}")
    for w in found:
        zipfile.ZipFile(w).extractall(dest)
print(f"vendor: {len(pins)} пакетов")
EOF

# Windows: официальный embeddable Python
python3 -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
    "$CACHE/$WIN_ZIP" "$KIT/runtime/windows"

# Linux: портативный CPython, без tk/idle/man/заголовков/pip и без симлинков
tar -xzf "$CACHE/$LIN_TGZ" -C "$KIT/runtime/linux"
LP="$KIT/runtime/linux/python"
rm -rf "$LP/share" "$LP/include" "$LP/lib/pkgconfig" "$LP"/lib/libpython3* "$LP"/lib/libtcl* \
       "$LP"/lib/tcl* "$LP"/lib/tk* "$LP"/lib/itcl* "$LP"/lib/thread* \
       "$LP"/lib/python3.13/{idlelib,tkinter,turtledemo,ensurepip,site-packages/pip*} \
       "$LP"/lib/python3.13/config-3.13-*
find "$LP/bin" -mindepth 1 ! -name python3.13 -delete
find "$LP" -name __pycache__ -type d -prune -exec rm -rf {} +
if [ -n "$(find "$KIT" -type l)" ]; then echo "в комплекте остались симлинки" >&2; exit 1; fi

# Лаунчеры и инструкция (.bat — с CRLF)
cp "$HERE/run.py" "$HERE/start_linux.sh" "$HERE/install_service_linux.sh" "$KIT/"
for f in start_windows.bat open_port_windows.bat; do sed 's/\r*$/\r/' "$HERE/$f" > "$KIT/$f"; done
# инструкция: CRLF + BOM, чтобы старый Блокнот не показал кракозябры
{ printf '\xef\xbb\xbf'; sed 's/\r*$/\r/' "$HERE/ИНСТРУКЦИЯ.txt"; } > "$KIT/ИНСТРУКЦИЯ.txt"
chmod +x "$KIT"/*.sh "$LP/bin/python3.13"
echo "Сборка: $REV, Python $PY_VER, $(date +%Y-%m-%d)" > "$KIT/VERSION.txt"

rm -f "$ZIP"
(cd "$REPO/dist" && python3 - "$ZIP" MonitoringSIP <<'EOF'
import os, sys, zipfile
out, top = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(top):
        dirs.sort()
        for f in sorted(files):
            z.write(os.path.join(root, f))  # права unix сохраняются в external_attr
EOF
)
echo "Готово: $ZIP ($(du -h "$ZIP" | cut -f1))"
