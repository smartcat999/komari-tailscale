#!/usr/bin/env bash
set -euo pipefail

# Komari Tailscale / Headscale Management Plugin Installer & Upgrader
# Usage: sudo ./install.sh [--komari-dir /opt/komari] [--port 25779]

KOMARI_DIR="/opt/komari"
CONTROL_PORT="25779"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --komari-dir)
      KOMARI_DIR="$2"
      shift 2
      ;;
    --port)
      CONTROL_PORT="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: sudo $0 [--komari-dir /opt/komari] [--port 25779]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "错误：请使用 root 权限（sudo）运行安装脚本。" >&2
  exit 1
fi

for cmd in python3 systemctl headscale; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "错误：未检测到必需命令 '$cmd'，请确认本机已安装 Headscale。" >&2
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${KOMARI_DIR}/data"
PLUGIN_DIR="${DATA_DIR}/plugin/tailscale-status"
STORAGE_DIR="${DATA_DIR}/plugin-data/tailscale-status"
COLLECTOR_DST="/usr/local/libexec/komari-tailscale-collector.py"
SERVICE_DST="/etc/systemd/system/komari-tailscale-collector.service"

KOMARI_USER="root"
KOMARI_GROUP="root"
if id -u komari >/dev/null 2>&1; then
  KOMARI_USER="komari"
  KOMARI_GROUP="$(id -gn komari)"
fi

echo "==> [1/4] 安装前端插件文件至 ${PLUGIN_DIR} ..."
install -d -m 0755 -o "$KOMARI_USER" -g "$KOMARI_GROUP" "$PLUGIN_DIR"
install -d -m 0700 -o "$KOMARI_USER" -g "$KOMARI_GROUP" "$STORAGE_DIR"
install -m 0644 -o "$KOMARI_USER" -g "$KOMARI_GROUP" "${SCRIPT_DIR}/plugin/komari-plugin.json" "${PLUGIN_DIR}/komari-plugin.json"
install -m 0644 -o "$KOMARI_USER" -g "$KOMARI_GROUP" "${SCRIPT_DIR}/plugin/script.js" "${PLUGIN_DIR}/script.js"
install -m 0644 -o "$KOMARI_USER" -g "$KOMARI_GROUP" "${SCRIPT_DIR}/plugin/status.html" "${PLUGIN_DIR}/status.html"

echo "==> [2/4] 安装本地采集与控制守护进程至 ${COLLECTOR_DST} ..."
install -d -m 0755 /usr/local/libexec
install -m 0755 -o root -g root "${SCRIPT_DIR}/collector.py" "$COLLECTOR_DST"

echo "==> [3/4] 配置 systemd 服务 (${SERVICE_DST}) ..."
cat > "$SERVICE_DST" <<EOF
[Unit]
Description=Tailscale and Headscale status & control daemon for Komari
Wants=tailscaled.service headscale.service
After=tailscaled.service headscale.service

[Service]
Type=simple
Environment="KOMARI_DATA_DIR=${DATA_DIR}"
Environment="KOMARI_TS_CONTROL_PORT=${CONTROL_PORT}"
ExecStart=/usr/bin/python3 ${COLLECTOR_DST} --daemon
Restart=always
RestartSec=2
UMask=0077
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$SERVICE_DST"
systemctl daemon-reload
systemctl enable --now komari-tailscale-collector.service
systemctl restart komari-tailscale-collector.service

echo "==> [4/4] 生成初始状态快照 ..."
KOMARI_DATA_DIR="${DATA_DIR}" KOMARI_TS_CONTROL_PORT="${CONTROL_PORT}" /usr/bin/python3 "$COLLECTOR_DST" || true
if systemctl is-active --quiet komari.service 2>/dev/null; then
  systemctl restart komari.service || true
fi

echo "安装完成！请在 Komari 后台「外观与插件 -> 插件」中启用「Tailscale 管理」，或直接从左侧导航栏进入。"
