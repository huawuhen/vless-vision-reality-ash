# vless-vision-reality-ash

**VLESS + TCP + XTLS-Vision + Reality** 同网段 / 同 ASN“邻居伪装域名”自动筛选与 Linux 一键部署脚本。

解决默认使用大厂域名（如 `www.apple.com`）与小机房 VPS IP 之间存在的 **“路由与 ASN 悖论”** 破绽，通过自动检索本机所在 BGP 网段的证书透明度（CT）记录，筛选出**同网段、未套 CDN、支持 TLSv1.3 + HTTP/2 (ALPN h2)、直接返回 200 且握手延迟最低**的邻居域名并完成一键部署。

---

## 核心功能

1. **自动识别 ASN 与 BGP 号段**：查询本机公网 IPv4 所属 ASN 及 BGP 路由网段（`bgp.he.net` + `RIPEstat` 双源）。
2. **检索同网段邻居域名**：对接 `bgp.he.net` Certs 接口获取同号段所有邻居证书域名，优先筛选简短的 `.com` / `.net` 域名。
3. **严格合规性 & 防 CDN 校验**：
   - DNS 解析 IP 必须位于本机同 BGP 网段内，自动剔除 Cloudflare 等 CDN 节点。
   - 底层 TLS 握手 + `curl -I -v --tlsv1.3 --http2` 双重验证：
     - 必须支持 **`TLSv1.3`** 且证书合法有效
     - 必须支持 **`ALPN: h2` (HTTP/2)**
     - 状态码必须为 **`HTTP/2 200`**（无 301/302 重定向跳转）
4. **最低延迟优选 + 交互选择**：并发实测 TCP + TLSv1.3 握手耗时（ms），按**延迟从低到高**排序并列出 Top 10，**暂停由你选择**要使用的伪装域名（直接回车默认选延迟最低的）。
5. **一键部署 Xray & 导出链接**：
   - 自动清理 `443` 端口冲突、修复 Debian/Ubuntu `systemd` 低位端口绑定权限、开启 BBR。
   - 自动生成 UUID、`x25519` 公私钥、`shortId`。
   - 输出 **`vless://` 分享链接** 与 **终端二维码**，支持直接导入 **v2rayNG / v2rayN / Shadowrocket / Nekobox**。

---

## 快速使用

### 1. 全自动扫描最优邻居域名并一键部署（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/huawuhen/vless-vision-reality-ash/main/reality_neighbor.sh -o reality_neighbor.sh && chmod +x reality_neighbor.sh && sudo bash reality_neighbor.sh
```

### 2. 仅扫描同网段可用邻居域名与延迟排名（不安装 Xray）

```bash
bash reality_neighbor.sh --scan
```

### 3. 手动指定伪装域名或端口部署

```bash
sudo bash reality_neighbor.sh --domain example.com --port 443
```

### 4. 一键彻底卸载

```bash
sudo bash reality_neighbor.sh --uninstall
# 非交互式直接卸载（跳过确认提示）
sudo bash reality_neighbor.sh --uninstall --yes
```

---

## 命令行参数

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `--scan`, `-s` | 仅查询本机 ASN 并输出同网段合格邻居域名及延迟排名，不部署 Xray | 关闭 |
| `--domain`, `-d <域名>` | 跳过自动扫描，直接使用指定域名部署 Reality | 自动扫描最优 |
| `--port`, `-p <端口>` | 指定 Xray 监听端口 | `443` |
| `--max`, `-m <数量>` | 最大并发检测候选域名数量 | `80` |
| `--uninstall`, `-u` | 彻底卸载 Xray、systemd 覆盖配置、对应防火墙规则及节点信息文件 | 关闭 |
| `--yes`, `-y` | 配合 `--uninstall` 使用，跳过交互确认提示 | 关闭 |
| `--help`, `-h` | 查看帮助信息 | - |

---

## 常用维护命令

- **查看节点配置与 `vless://` 导入链接**：
  ```bash
  cat /root/vless_reality_neighbor_info.txt
  ```
- **查看 Xray 运行状态 / 日志**：
  ```bash
  systemctl status xray
  journalctl -u xray -n 30 --no-pager
  ```
- **修改配置后重启 Xray**：
  ```bash
  systemctl restart xray
  ```
