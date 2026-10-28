# Komari Tailscale / Headscale 管理插件 (`tailscale-status`)

专为 **Komari 监控面板 + 本机自建 Headscale 控制面 + Tailscale 客户端** 同机部署场景打造的可视化组网管理插件。

## 功能概览

- **节点管理**：查看节点在线状态、内网 IP、直连/中继状态与延迟；支持测速、改名、修改固定内网 IP、路由审批、迁移用户、设置标签、设为永不过期、强制下线与移除节点。
- **本机配置**：在线安装本机客户端并一键入网，配置本机连接选项（允许入站、内网 DNS、子网路由、作为出口节点）及内置私有 DERP 中继参数。
- **用户与授权密钥**：管理 Headscale 用户与预授权密钥，提供多平台命令行、图形界面接入指引与免密钥审批接入。
- **子网路由与出口节点**：一键开启本机作为出口节点（自动开启内核转发并批准路由），审批任意节点的子网路由。
- **DNS 解析**：管理 MagicDNS、全局/分流 DNS 与自定义域名解析记录（实时热生效）。
- **访问控制 (ACL)**：提供可视化规则构建器、预设模式切换与 JSON 策略源码编辑。
- **网络诊断与配置备份**：查看 NAT 穿透状态、DERP 中继延迟及节点收发流量；支持一键导出配置快照或上传备份文件恢复 DNS、ACL 与中继配置。

## 安装与升级

### 环境要求

- Linux 主机（支持 `systemd` 与 `python3 >= 3.9`）
- 已运行 **Komari**（默认目录 `/opt/komari`）与 **Headscale**

### 一键安装

```bash
git clone https://github.com/smartcat999/komari-tailscale.git
cd komari-tailscale
sudo ./install.sh
```

若 Komari 安装在自定义目录，可通过参数指定：

```bash
sudo ./install.sh --komari-dir /opt/komari --port 25779
```

### 卸载

```bash
sudo ./uninstall.sh
```

## 开源许可

[MIT License](LICENSE)
