#!/usr/bin/env bash
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
    echo 'Для настройки брандмауэра запустите этот скрипт через sudo.' >&2
    exit 1
fi
if [ ! -x /usr/bin/python3 ]; then
    echo 'Для службы брандмауэра нужен системный /usr/bin/python3.' >&2
    exit 1
fi

KIT="$(dirname -- "$(readlink -f -- "$0")")"
exec /usr/bin/python3 -I "$KIT/ping_firewall_linux.py" "$@"
