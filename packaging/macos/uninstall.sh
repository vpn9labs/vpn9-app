#!/bin/bash
set -euo pipefail

SERVICE_LABEL="system/com.vpn9.daemon"
SERVICE_PLIST="/Library/LaunchDaemons/com.vpn9.daemon.plist"
APP_PATH="/Applications/VPN9.app"
DAEMON_DIR="/usr/local/libexec/vpn9"
DAEMON_BIN="${DAEMON_DIR}/vpn9-daemon"
RUN_DIR="/var/run/vpn9"
LOG_FILES=(
  "/var/log/vpn9-daemon.log"
  "/var/log/vpn9-daemon.err"
  "/var/log/vpn9-installer.log"
)
RECEIPT_ID="com.vpn9.pkg"

log() {
  printf '[vpn9-uninstall] %s\n' "$1"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "This script must be run as root (try: sudo $0)"
    exit 1
  fi
}

stop_service() {
  if ! command -v launchctl >/dev/null 2>&1; then
    return
  fi

  log "Stopping vpn9 daemon (if running)"
  launchctl kill SIGTERM "${SERVICE_LABEL}" >/dev/null 2>&1 || true
  launchctl bootout system "${SERVICE_PLIST}" >/dev/null 2>&1 || true
  launchctl bootout "${SERVICE_LABEL}" >/dev/null 2>&1 || true
  launchctl disable "${SERVICE_LABEL}" >/dev/null 2>&1 || true

  if pgrep -f "${DAEMON_BIN}" >/dev/null 2>&1; then
    log "Killing remaining vpn9-daemon processes"
    pkill -f "${DAEMON_BIN}" >/dev/null 2>&1 || true
  fi
}

remove_launchdaemon() {
  if [ -f "${SERVICE_PLIST}" ]; then
    log "Removing LaunchDaemon plist"
    rm -f "${SERVICE_PLIST}"
  fi
}

remove_daemon() {
  if [ -f "${DAEMON_BIN}" ]; then
    log "Removing daemon binary"
    rm -f "${DAEMON_BIN}"
  fi
  if [ -d "${DAEMON_DIR}" ]; then
    if [ -z "$(find "${DAEMON_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]; then
      rmdir "${DAEMON_DIR}" 2>/dev/null || true
    fi
  fi
}

remove_app() {
  if [ -d "${APP_PATH}" ]; then
    log "Removing VPN9.app from /Applications"
    rm -rf "${APP_PATH}"
  fi
}

cleanup_runtime() {
  if [ -d "${RUN_DIR}" ]; then
    log "Removing runtime directory ${RUN_DIR}"
    rm -rf "${RUN_DIR}"
  fi
}

cleanup_logs() {
  for file in "${LOG_FILES[@]}"; do
    if [ -f "${file}" ]; then
      log "Removing log ${file}"
      rm -f "${file}"
    fi
  done
}

forget_receipt() {
  if command -v pkgutil >/dev/null 2>&1; then
    if pkgutil --pkgs | grep -q "${RECEIPT_ID}"; then
      log "Forgetting pkgutil receipt ${RECEIPT_ID}"
      pkgutil --forget "${RECEIPT_ID}" >/dev/null 2>&1 || true
    fi
  fi
}

main() {
  require_root
  stop_service
  remove_launchdaemon
  remove_daemon
  remove_app
  cleanup_runtime
  cleanup_logs
  forget_receipt
  log "Uninstall complete"
}

main "$@"
