#!/usr/bin/env bash
# Автозапуск Monitoring SIP через systemd (необязательно).
# Запуск: sudo bash install_service_linux.sh      Удаление: sudo bash install_service_linux.sh --remove
# Перед этим хотя бы раз запусти start_linux.sh вручную и сохрани пароль admin.
set -eu
UNIT=/etc/systemd/system/monitoring-sip.service

if [ "$(id -u)" -ne 0 ]; then
    echo "Нужен root: sudo bash $0" >&2
    exit 1
fi

if [ "${1:-}" = "--remove" ]; then
    systemctl disable --now monitoring-sip.service 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    echo "Сервис monitoring-sip удалён."
    exit 0
fi

KIT="$(dirname "$(readlink -f "$0")")"
RUN_USER="${SUDO_USER:-root}"

cat > "$UNIT" <<EOF
[Unit]
Description=Monitoring SIP (Yealink panel)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$KIT
ExecStart=/bin/bash $KIT/start_linux.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now monitoring-sip.service
sleep 2
systemctl --no-pager --lines=5 status monitoring-sip.service || true
echo
echo "Готово: сервис monitoring-sip запущен от пользователя $RUN_USER и стартует при загрузке."
