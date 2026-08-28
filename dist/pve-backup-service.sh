#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-pve-backup-web}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$SCRIPT_DIR}"
BIN_PATH="${BIN_PATH:-$APP_DIR/pve-backup-web}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "This command must be run as root." >&2
    exit 1
  fi
}

install_service() {
  require_root
  if [[ ! -x "$BIN_PATH" ]]; then
    echo "Binary not found or not executable: $BIN_PATH" >&2
    exit 1
  fi
  cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=PVE Backup Web
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$BIN_PATH
Restart=on-failure
RestartSec=3
Environment=PVE_BACKUP_HOME=$APP_DIR

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  echo "Installed $UNIT_PATH"
}

case "${1:-help}" in
  install)
    install_service
    ;;
  enable)
    require_root
    systemctl enable "$SERVICE_NAME"
    ;;
  disable)
    require_root
    systemctl disable "$SERVICE_NAME"
    ;;
  start)
    require_root
    systemctl start "$SERVICE_NAME"
    ;;
  stop)
    require_root
    systemctl stop "$SERVICE_NAME"
    ;;
  restart)
    require_root
    systemctl restart "$SERVICE_NAME"
    ;;
  status)
    systemctl status "$SERVICE_NAME" --no-pager -l
    ;;
  uninstall)
    require_root
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
    echo "Uninstalled $SERVICE_NAME"
    ;;
  help|*)
    echo "Usage: $0 {install|enable|disable|start|stop|restart|status|uninstall}"
    echo "Environment overrides: SERVICE_NAME, APP_DIR, BIN_PATH"
    ;;
esac
