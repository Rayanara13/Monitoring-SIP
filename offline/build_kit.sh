#!/usr/bin/env bash
# Сборка офлайн-комплекта Monitoring SIP.
# Нужен интернет на машине сборки. По умолчанию код берётся из HEAD.
# Флаг --worktree включает текущие версии только перечисленных файлов приложения.
#   bash offline/build_kit.sh                общедоступный Windows x64 + Linux x86_64
#   bash offline/build_kit.sh --windows-x64  общедоступный Windows x64
#   bash offline/build_kit.sh --linux-x64    общедоступный Linux x86_64
#   bash offline/build_kit.sh --linux-arm64  общедоступный Linux ARM64
set -euo pipefail

RELEASE=1.5
PY_VER=3.13.15
PBS_TAG=20260929   # релиз astral-sh/python-build-standalone с CPython $PY_VER

usage() {
    echo "Использование: bash offline/build_kit.sh [--public-node] [--windows-x64|--linux-x64|--linux-arm64] [--update-public-key FILE] [--worktree]"
}

TARGET=legacy
UPDATE_KEY=""
FROM_WORKTREE=false
while [ "$#" -gt 0 ]; do
    arg="$1"
    shift
    case "$arg" in
        --windows-x64) TARGET=windows_x64 ;;
        --linux-x64) TARGET=linux_x64 ;;
        --linux-arm64) TARGET=linux_arm64 ;;
        --public-node) ;;
        --update-public-key)
            if [ "$#" -eq 0 ] || [ -n "$UPDATE_KEY" ]; then usage >&2; exit 2; fi
            UPDATE_KEY="$1"
            shift ;;
        --worktree) FROM_WORKTREE=true ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
PUBLIC_KEY=""
if [ -n "$UPDATE_KEY" ]; then
    PUBLIC_KEY="$(python3 - "$UPDATE_KEY" <<'EOF'
import base64, binascii, re, sys
from pathlib import Path

try:
    with Path(sys.argv[1]).open("rb") as file:
        data = file.read(129)
    text = data.strip()
    if len(data) > 128 or not re.fullmatch(rb"[A-Za-z0-9_-]{43}=?", text):
        raise ValueError
    raw = base64.b64decode(text + b"=" * (-len(text) % 4), altchars=b"-_", validate=True)
    canonical = base64.urlsafe_b64encode(raw)
    if len(raw) != 32 or canonical.rstrip(b"=") != text.rstrip(b"="):
        raise ValueError
except (OSError, ValueError, binascii.Error):
    sys.exit("Нужен файл открытого ключа обновлений Ed25519: 32 байта в Base64url.")
print(canonical.decode("ascii"))
EOF
)"
fi
INCLUDE_WINDOWS=true
INCLUDE_LINUX=true
LINUX_ARCH=x86_64
PLATFORM_LABEL="Windows x64, Linux x86_64"
case "$TARGET" in
    windows_x64) INCLUDE_LINUX=false; PLATFORM_LABEL="Windows x64" ;;
    linux_x64) INCLUDE_WINDOWS=false; PLATFORM_LABEL="Linux x86_64" ;;
    linux_arm64) INCLUDE_WINDOWS=false; LINUX_ARCH=aarch64; PLATFORM_LABEL="Linux aarch64" ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CACHE="${INEI_BUILD_CACHE:-$HERE/.cache}"
WHEELS="$CACHE/wheels/$TARGET"
REV="$(git -C "$REPO" rev-parse --short HEAD)"
if $FROM_WORKTREE; then REV="$REV-worktree"; fi
DIST="$REPO/dist"
STAGING="$DIST/public_node/$TARGET"
ZIP="$DIST/MonitoringSIP_${RELEASE}_offline_${REV}.zip"
KIT_PROFILE=public_node
if [ "$TARGET" != legacy ]; then
    ZIP="$DIST/MonitoringSIP_${RELEASE}_offline_${TARGET}_${REV}.zip"
fi
if $FROM_WORKTREE; then STAGING="$STAGING/worktree"; fi
KIT="$STAGING/MonitoringSIP"

APP_FILES=(
    server.py yealink_setup.py panel.html login.html node_link.html release_install.py
    federation_logs.py federation_node.py federation_updates.py
    availability_probe.py availability_protocol.py ping_trust.py telemetry_node.py
    static/monitor.svg static/socket.io.min.js
    simulator/README.md simulator/__init__.py simulator/__main__.py
    simulator/app.py simulator/engine.py simulator/index.html
)
for source in "${APP_FILES[@]}"; do
    if $FROM_WORKTREE; then
        if [ ! -f "$REPO/$source" ] || [ -L "$REPO/$source" ]; then
            echo "Файл приложения отсутствует или является симлинком: $source" >&2
            exit 1
        fi
    elif ! git -C "$REPO" cat-file -e "HEAD:$source" 2>/dev/null; then
        echo "Файл приложения отсутствует в HEAD: $source" >&2
        exit 1
    fi
done

WIN_ZIP="python-${PY_VER}-embed-amd64.zip"
WIN_URL="https://www.python.org/ftp/python/${PY_VER}/${WIN_ZIP}"
LIN_TGZ="cpython-${PY_VER}+${PBS_TAG}-${LINUX_ARCH}-unknown-linux-gnu-install_only_stripped.tar.gz"
LIN_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${LIN_TGZ//+/%2B}"

if ! $FROM_WORKTREE && [ -n "$(git -C "$REPO" status --porcelain -- "${APP_FILES[@]}")" ]; then
    echo "ВНИМАНИЕ: в коде приложения есть незакоммиченные правки — в комплект идёт HEAD ($REV)." >&2
fi

download_runtime() {
    local file="$CACHE/$1"
    [ -f "$file" ] && return
    curl -fsSL -o "$file.part" "$2"
    mv -- "$file.part" "$file"
}

mkdir -p "$WHEELS"
if $INCLUDE_LINUX; then
    download_runtime "$LIN_TGZ" "$LIN_URL"
fi
if $INCLUDE_WINDOWS; then
    download_runtime "$WIN_ZIP" "$WIN_URL"
fi

PIPDL=(python3 -m pip download -q --no-deps --only-binary=:all: --implementation cp -d "$WHEELS")
CFFI_PIN="$(grep '^cffi==' "$HERE/requirements.lock")"
MARKUPSAFE_PIN="$(grep '^markupsafe==' "$HERE/requirements.lock")"
download_wheels() {
    local platform="$1" version
    # CPython 3.10 выбирает ABI cryptography, совместимый и с более новыми Python.
    "${PIPDL[@]}" --platform "$platform" --python-version 3.10 -r "$HERE/requirements.lock"
    # CFFI использует отдельный ABI каждой версии. Сохраняем системный Python
    # как запасной вариант, в том числе Python 3.12 в Ubuntu 24.04 на Jetson.
    for version in 3.11 3.12 3.13 3.14 3.15; do
        "${PIPDL[@]}" --platform "$platform" --python-version "$version" "$CFFI_PIN"
    done
    "${PIPDL[@]}" --platform "$platform" --python-version 3.13 "$MARKUPSAFE_PIN"
}

if $INCLUDE_WINDOWS; then
    download_wheels win_amd64
fi
if $INCLUDE_LINUX; then
    download_wheels "manylinux2014_$LINUX_ARCH"
fi

rm -rf "$KIT"
mkdir -p "$KIT/app" "$KIT/vendor"

# Список файлов приложения исключает локальные учётные данные и историю.
if $FROM_WORKTREE; then
    for source in "${APP_FILES[@]}"; do
        mkdir -p "$KIT/app/$(dirname "$source")"
        cp -P -- "$REPO/$source" "$KIT/app/$source"
    done
else
    git -C "$REPO" archive HEAD "${APP_FILES[@]}" | tar -x -C "$KIT/app"
fi
if [ -n "$PUBLIC_KEY" ]; then printf '%s\n' "$PUBLIC_KEY" > "$KIT/app/update_authority.pub"; fi

# vendor/: распакованные колёса из лока (по одной версии каждого пакета)
python3 - "$HERE/requirements.lock" "$WHEELS" "$KIT/vendor" <<'EOF'
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
    for w in sorted(found):
        zipfile.ZipFile(w).extractall(dest)
print(f"vendor: {len(pins)} пакетов")
EOF

# Windows: официальный embeddable Python
if $INCLUDE_WINDOWS; then
    mkdir -p "$KIT/runtime/windows"
    python3 -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
        "$CACHE/$WIN_ZIP" "$KIT/runtime/windows"
fi

# Linux: портативный CPython, без tk/idle/man/заголовков/pip и без симлинков
if $INCLUDE_LINUX; then
    mkdir -p "$KIT/runtime/linux"
    tar -xzf "$CACHE/$LIN_TGZ" -C "$KIT/runtime/linux"
    LP="$KIT/runtime/linux/python"
    rm -rf "$LP/share" "$LP/include" "$LP/lib/pkgconfig" "$LP"/lib/libpython3* "$LP"/lib/libtcl* \
           "$LP"/lib/tcl* "$LP"/lib/tk* "$LP"/lib/itcl* "$LP"/lib/thread* \
           "$LP"/lib/python3.13/{idlelib,tkinter,turtledemo,ensurepip,site-packages/pip*} \
           "$LP"/lib/python3.13/config-3.13-*
    find "$LP/bin" -mindepth 1 ! -name python3.13 -delete
    find "$LP" -name __pycache__ -type d -prune -exec rm -rf {} +
    cp "$HERE/start_linux.sh" "$HERE/install_service_linux.sh" "$HERE/configure_ping_linux.sh" \
       "$HERE/ping_firewall_linux.py" "$HERE/diagnose_linux.sh" "$KIT/"
    chmod +x "$KIT"/*.sh "$LP/bin/python3.13"
fi
if [ -n "$(find "$KIT" -type l)" ]; then echo "в комплекте остались симлинки" >&2; exit 1; fi

# Лаунчеры и инструкция (.bat — с CRLF)
cp "$HERE/run.py" "$HERE/diagnose.py" "$KIT/"
if $INCLUDE_WINDOWS; then
    for f in start_windows.bat open_port_windows.bat diagnose_windows.bat; do sed 's/\r*$/\r/' "$HERE/$f" > "$KIT/$f"; done
    cp "$HERE/configure_ping_windows.ps1" "$KIT/"
fi
# инструкция: CRLF + BOM, чтобы старый Блокнот не показал кракозябры
{ printf '\xef\xbb\xbf'; sed 's/\r*$/\r/' "$HERE/ИНСТРУКЦИЯ.txt"; } > "$KIT/ИНСТРУКЦИЯ.txt"
echo "Иней $RELEASE ($REV), Python $PY_VER, $PLATFORM_LABEL, $(date +%Y-%m-%d)" > "$KIT/VERSION.txt"
printf '%s\n' "$KIT_PROFILE" > "$KIT/PROFILE.txt"

(cd "$STAGING" && python3 - "$ZIP" MonitoringSIP <<'EOF'
import os, sys, tempfile, zipfile
from pathlib import Path
out, top = sys.argv[1], sys.argv[2]
with tempfile.NamedTemporaryFile(dir=Path(out).parent, suffix=".part", delete=False) as file:
    temporary = Path(file.name)
try:
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, dirs, files in os.walk(top):
            dirs.sort()
            for f in sorted(files):
                z.write(os.path.join(root, f))  # права unix сохраняются в external_attr
    os.replace(temporary, out)
finally:
    temporary.unlink(missing_ok=True)
EOF
)
echo "Готово: $ZIP ($(du -h "$ZIP" | cut -f1))"
