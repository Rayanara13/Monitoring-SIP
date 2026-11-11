#!/usr/bin/env bash
# Monitoring SIP — запуск на Linux (офлайн-комплект).
# Сначала встроенный портативный Python, потом системный python3 (3.10+).
# Свой интерпретатор: PYTHON=/путь/к/python3 bash start_linux.sh
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1

BUNDLED="runtime/linux/python/bin/python3.13"
# права на исполнение теряются, если архив распаковали на Windows/флешке FAT
chmod +x "$BUNDLED" 2>/dev/null

works() { "$1" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; }

PY=""
for cand in "${PYTHON:-}" "$BUNDLED" python3 python; do
    if [ -z "$cand" ]; then continue; fi
    if works "$cand"; then PY="$cand"; break; fi
done

if [ -z "$PY" ]; then
    echo "ОШИБКА: не найден рабочий Python 3.10+." >&2
    echo "Встроенный лежит в runtime/linux — проверь, что архив распакован целиком." >&2
    echo "См. раздел «Проблемы» в ИНСТРУКЦИЯ.txt." >&2
    exit 1
fi

echo "Запуск Инея … Остановка: Ctrl+C."
exec "$PY" run.py "$@"
