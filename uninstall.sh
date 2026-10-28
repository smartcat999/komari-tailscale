#!/usr/bin/env bash
set -euo pipefail

# Komari Tailscale / Headscale Management Plugin Uninstaller
# Usage: sudo ./uninstall.sh [--komari-dir /opt/komari] [--purge-data]

KOMARI_DIR="/opt/komari"
PURGE_DATA=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --komari-dir)
      KOMARI_DIR="$2"
      shift 2
      ;;
    --purge-data)
      PURGE_DATA=1
      shift
      ;;
    -h|--help)
      echo "Usage: sudo $0 [--komari-dir /opt/komari] [--purge-data]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "错误：请使用 root 权限（sudo）运行卸载脚本。" >&2
  exit 1
fi

echo "==> 停止并移除 systemd 服务 ..."
systemctl disable --now komari-tailscale-collector.timer 2>/dev/null || true
systemctl disable --now komari-tailscale-collector.service 2>/dev/null || true
rm -f /etc/systemd/system/komari-tailscale-collector.service
rm -f /etc/systemd/system/komari-tailscale-collector.timer
systemctl daemon-reload

echo "==> 移除采集脚本与插件目录 ..."
rm -f /usr/local/libexec/komari-tailscale-collector.py
rm -rf "${KOMARI_DIR}/data/plugin/tailscale-status"

if [[ "$PURGE_DATA" -eq 1 ]]; then
  echo "==> 清理插件状态缓存 (${KOMARI_DIR}/data/plugin-data/tailscale-status) ..."
  rm -rf "${KOMARI_DIR}/data/plugin-data/tailscale-status"
fi

echo "卸载完成（Headscale 与 Tailscale 自身配置及数据未受影响）。"
