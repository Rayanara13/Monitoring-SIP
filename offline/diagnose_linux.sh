#!/usr/bin/env bash
set -u
KIT="$(dirname -- "$(readlink -f -- "$0")")"
PY="$KIT/runtime/linux/python/bin/python3.13"
if [ ! -f "$KIT/diagnose.py" ] || [ ! -f "$KIT/app/server.py" ] ||
   [ ! -f "$KIT/vendor/flask/__init__.py" ]; then
    echo '[FAIL] KIT_INCOMPLETE — отсутствуют файлы приложения или зависимостей.' >&2
    echo 'Распакуйте офлайн-комплект для вашей платформы целиком.' >&2
    exit 1
fi
if [ ! -x "$PY" ] || ! "$PY" -I -B -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
    echo '[FAIL] KIT_RUNTIME_MISSING — встроенный Python отсутствует или не запускается.' >&2
    echo 'Сверьте архитектуру, права исполнения и комплектность архива.' >&2
    exit 1
fi
exec "$PY" -I -B -X utf8 "$KIT/diagnose.py" "$@"
