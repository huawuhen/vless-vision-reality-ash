#!/usr/bin/env bash
# ==============================================================================
# VLESS + TCP + XTLS-Vision + Reality "同网段/同ASN邻居域名" 全自动扫描与一键部署脚本
# 原理参考: https://vpsoso.com/blog/kxsw/reality_neighbor
#
# 核心功能:
#   1. 自动获取本机公网 IPv4、所属 ASN、BGP 路由网段 (bgp.he.net + RIPEstat 双源)
#   2. 调用 bgp.he.net Certs (CT 证书透明度) 接口获取同网段/同 ASN 邻居所有域名
#   3. 严格按文章规范并发筛选可用伪装域名:
#      - 排除泛域名/自动解析域名 (nip.io, sslip.io 等)，优先优选短的 com/net/org 域名
#      - DNS 解析出的 IP 必须属于本机同 BGP 网段或同 /24 子网 (防 Cloudflare 等 CDN)
#      - curl 严格验证: 必须支持 TLSv1.3、ALPN 必须接受 h2 (HTTP/2)、HTTP 状态码必须 200 (非 301/302 跳转)、证书有效
#      - 测量 TCP/TLS 握手响应延迟，按【延迟从低到高】排序，自动选出延迟最低的最优邻居域名
#   4. 一键安装/配置 Xray (VLESS + TCP + xtls-rprx-vision + Reality, 443 端口)
#      自动生成 UUID、x25519 公私钥、ShortID，并可选开启 BBR 加速
#   5. 输出完整节点配置信息、vless:// 分享链接 (可直接导入 v2rayNG / v2rayN / Shadowrocket) 及终端二维码
#
# 用法:
#   bash reality_neighbor.sh            # 全自动扫描最优邻居域名并一键部署 Reality
#   bash reality_neighbor.sh --scan     # 仅扫描并列出同网段/ASN 可用邻居域名及延迟排名 (不安装 Xray)
#   bash reality_neighbor.sh --domain <域名> [--port 443] # 指定伪装域名直接部署
#   bash reality_neighbor.sh --uninstall [-y]             # 彻底卸载 Xray 及本脚本生成的配置与节点信息
# ==============================================================================

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

SCAN_ONLY=0
UNINSTALL=0
ASSUME_YES=0
CUSTOM_DOMAIN=""
LISTEN_PORT=443
PORT_SPECIFIED=0
MAX_TEST_CANDIDATES=80

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan|-s)
      SCAN_ONLY=1
      shift
      ;;
    --uninstall|-u)
      UNINSTALL=1
      shift
      ;;
    --yes|-y)
      ASSUME_YES=1
      shift
      ;;
    --domain|-d)
      CUSTOM_DOMAIN="${2:-}"
      shift 2
      ;;
    --port|-p)
      LISTEN_PORT="${2:-443}"
      PORT_SPECIFIED=1
      shift 2
      ;;
    --max|-m)
      MAX_TEST_CANDIDATES="${2:-80}"
      shift 2
      ;;
    --help|-h)
      echo "用法: bash $0 [选项]"
      echo "选项:"
      echo "  --scan, -s             仅查询本机 ASN 与扫描筛选同网段最优邻居域名，不部署 Xray"
      echo "  --domain, -d <domain>  跳过扫描，直接使用指定的邻居域名部署 VLESS+Vision+Reality"
      echo "  --port, -p <port>      指定 Xray 监听端口 (默认: 443，推荐 443)"
      echo "  --max, -m <num>        最大并发检测候选域名数量 (默认: 80)"
      echo "  --uninstall, -u        彻底卸载 Xray、systemd 覆盖配置、防火墙规则及节点信息文件"
      echo "  --yes, -y              配合 --uninstall 使用，跳过交互确认直接卸载"
      exit 0
      ;;
    *)
      log_err "未知参数: $1 (使用 --help 查看帮助)"
      exit 1
      ;;
  esac
done

# ------------------------------------------------------------------------------
# 1. 环境与依赖检查
# ------------------------------------------------------------------------------
install_base_deps() {
  local need_install=0
  for cmd in curl python3 openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      need_install=1
    fi
  done

  if [[ $need_install -eq 1 ]]; then
    log_info "正在安装基础依赖 (curl, python3, openssl, qrencode, ca-certificates)..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl python3 openssl ca-certificates qrencode >/dev/null 2>&1 || \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl python3 openssl ca-certificates >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y -q curl python3 openssl ca-certificates qrencode >/dev/null 2>&1 || \
      dnf install -y -q curl python3 openssl ca-certificates >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
      yum install -y -q curl python3 openssl ca-certificates qrencode >/dev/null 2>&1 || \
      yum install -y -q curl python3 openssl ca-certificates >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache curl python3 openssl ca-certificates libqrencode-tools >/dev/null 2>&1 || true
    fi
  fi

  # 检查 curl 是否支持 HTTP/2
  if ! curl -V 2>/dev/null | grep -qi "HTTP2"; then
    log_warn "当前系统的 curl 可能未编译 HTTP2 模块，将尝试使用系统 curl + Python OpenSSL 双重校验 TLS1.3 & ALPN h2。"
  fi
}

# ------------------------------------------------------------------------------
# 2. 核心 Python 扫描引擎:
#    - 获取本机公网 IPv4、所属 ASN、BGP 宣告网段 (bgp.he.net + RIPEstat)
#    - 查询 bgp.he.net /certs/api/ip-search 获取同网段所有邻居域名
#    - 严格按照文章要求校验:
#        (a) 排除套 Cloudflare/CDN (解析 IP 必须在同 BGP 网段或同 /24 内)
#        (b) curl -I -v --tlsv1.3 --http2 https://域名 校验:
#            * SSL connection using TLSv1.3
#            * ALPN: server accepted h2
#            * HTTP/2 200 (非 301/302 重定向，证书有效)
#        (c) 测量握手与首包总延迟 (ms)，选出延迟最低的域名
# ------------------------------------------------------------------------------
scan_best_neighbor_domain() {
  local result_file="$1"
  python3 - "$MAX_TEST_CANDIDATES" "$result_file" "$SCAN_ONLY" <<'PYEOF'
import sys
import re
import json
import time
import socket
import ssl
import ipaddress
import urllib.request
import urllib.parse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_CANDIDATES = int(sys.argv[1]) if len(sys.argv) > 1 else 80
RESULT_FILE = sys.argv[2] if len(sys.argv) > 2 else "/tmp/reality_best_domain.json"
SCAN_ONLY = (len(sys.argv) > 3 and sys.argv[3] == "1")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# 常见 Cloudflare IPv4 网段 (双重防套 CF 检测)
CF_NETS = [ipaddress.ip_network(cidr) for cidr in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]]

def http_get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, text/html, */*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")

def input_prompt(prompt):
    """从 /dev/tty 读取一行交互输入。

    脚本主体通过 heredoc 由 stdin 传入 (python3 -)，stdin 在脚本开始执行时已到 EOF，
    因此 input() 会直接抛 EOFError。这里显式读取控制终端；无 TTY 时抛 OSError，
    由调用方回退到默认的最优域名。
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    with open("/dev/tty", "r") as tty:
        return tty.readline()

def get_public_ipv4():
    endpoints = [
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
        "https://ifconfig.me/ip"
    ]
    for url in endpoints:
        try:
            ip_str = http_get(url, timeout=5).strip()
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return ip_str
        except Exception:
            continue
    raise RuntimeError("无法获取当前 Linux 主机的公网 IPv4 地址")

def get_asn_and_prefixes(ip_str):
    """
    通过 bgp.he.net 和 RIPEstat 获取当前 IP 的所属 ASN、机构名称以及所在号段 (BGP Prefix)
    """
    asns = []
    prefixes = []
    asn_descs = {}

    # 1. 从 bgp.he.net/ip/<IP> 提取 (与文章步骤完全一致)
    try:
        html = http_get(f"https://bgp.he.net/ip/{ip_str}", timeout=10)
        # 匹配形如: <td><a href="/AS35916">AS35916</a></td><td class="nowrap"><a href="/net/142.171.0.0/16">142.171.0.0/16</a>...</td><td>MULTACOM CORPORATION</td>
        row_pattern = re.compile(
            r'href="/AS(\d+)"[^>]*>AS\d+</a>.*?href="/net/([0-9\./]+)"[^>]*>[0-9\./]+</a>.*?</td>\s*<td>([^<]+)</td>',
            re.S
        )
        for m in row_pattern.finditer(html):
            asn, pfx, desc = m.group(1), m.group(2).strip(), m.group(3).strip()
            if asn not in asns:
                asns.append(asn)
            if pfx not in prefixes:
                prefixes.append(pfx)
            asn_descs[asn] = desc
    except Exception as e:
        pass

    # 2. 补充从 RIPEstat BGP API 获取精确 ASN 与 Prefix (防止 bgp.he.net 偶发拦截)
    try:
        ripe_json = json.loads(http_get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip_str}", timeout=8))
        data = ripe_json.get("data", {})
        for a in data.get("asns", []):
            if str(a) not in asns:
                asns.append(str(a))
        pfx = data.get("prefix")
        if pfx and pfx not in prefixes:
            prefixes.append(pfx)
    except Exception:
        pass

    # 构造同 /24 网段
    ip_obj = ipaddress.ip_address(ip_str)
    net24 = str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
    if net24 not in prefixes:
        prefixes.insert(0, net24)
    else:
        # 确保更精确的网段排在前面优先扫，同时保留大网段补充
        prefixes.sort(key=lambda x: ipaddress.ip_network(x, strict=False).prefixlen, reverse=True)

    return asns, asn_descs, prefixes

def fetch_neighbor_domains_from_bgphe(prefixes):
    """
    调用 bgp.he.net 的 Certs 接口 (/certs/api/ip-search?ip=<prefix>) 获取同网段邻居证书中的所有域名
    同时补充 /net/<prefix> 页面中的反向 DNS (A/PTR) 记录
    """
    domain_to_bgp_ips = {}

    for pfx in prefixes:
        # 避免扫超过 /16 的超大段导致超时；如果前缀小于 /18，将其收敛到包含本机的 /20 或 /18
        try:
            net_obj = ipaddress.ip_network(pfx, strict=False)
            if net_obj.prefixlen < 18:
                continue
        except Exception:
            continue

        try:
            api_url = f"https://bgp.he.net/certs/api/ip-search?ip={urllib.parse.quote(pfx)}"
            raw = http_get(api_url, timeout=12)
            data = json.loads(raw)
            entries = data.get("entries", [])
            for entry in entries:
                entry_ip = entry.get("ip", "")
                for h in entry.get("hostnames", []):
                    h = h.strip().lower().lstrip("*.")
                    if not h or "." not in h:
                        continue
                    domain_to_bgp_ips.setdefault(h, set()).add(entry_ip)
        except Exception:
            pass

        # 如果从小段 (/24) 拿到的候选域名已经超过 150 个，就不必继续拉取更大的段；否则继续拉取上级 BGP 段
        if len(domain_to_bgp_ips) >= 150:
            break

    return domain_to_bgp_ips

def is_good_domain_format(domain):
    """
    过滤掉不合格的域名格式，并按文章要求给短的、靓的 com/net 域名打高分
    """
    if not re.match(r'^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]\.[a-z]{2,}$', domain):
        return False
    # 排除纯数字或含 IP 地址格式的自动域名 / nip.io / sslip.io / traefik / 面板或邮件逆向域名
    bad_keywords = [
        "nip.io", "sslip.io", "xip.io", "local", "localhost", "arpa",
        "cpanel", "webmail", "whm.", "autodiscover", "autoconfig",
        "mail.", "smtp.", "pop.", "imap.", "mx.", "ns1.", "ns2."
    ]
    for kw in bad_keywords:
        if kw in domain:
            return False
    # 排除包含连续 3 段以上 IP 数字的生成式主机名
    if re.search(r'\d{1,3}[\-\.]\d{1,3}[\-\.]\d{1,3}', domain):
        return False
    return True

def domain_priority_key(domain):
    """
    文章要求：首选短的、靓的 com、net 域名
    返回值越小优先级越高
    """
    tld_rank = 2
    if domain.endswith(".com"):
        tld_rank = 0
    elif domain.endswith(".net"):
        tld_rank = 1
    elif domain.endswith(".org"):
        tld_rank = 2
    else:
        tld_rank = 3
    parts = domain.split(".")
    return (tld_rank, len(parts), len(domain))

def is_cloudflare_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CF_NETS)
    except Exception:
        return False

def check_candidate_domain(domain, allowed_networks, my_ip):
    """
    严格按文章第 二 节执行校验：
    1. DNS 解析校验 (相当于 ping 目标域名)：
       - 解析出的 IPv4 不能是 Cloudflare CDN IP
       - 解析出的 IPv4 必须落在我们从 bgp.he.net 查到的同机房 BGP 网段内
    2. 协议与状态校验 (执行文章同款 curl 命令 + Python OpenSSL 底层握手校验)：
       curl -I -v --tlsv1.3 --http2 https://目标域名
       - 必须支持 TLSv1.3 (SSL connection using TLSv1.3)
       - ALPN 必须协商为 h2 (ALPN: server accepted h2 / using HTTP/2)
       - 状态码必须是 HTTP/2 200 (直接返回网页内容，非 301/302 跳转)
       - 证书必须有效 (未过期且主机名匹配)
    3. 测量真实 TCP + TLS 1.3 握手延迟 (ms)
    """
    # Step 1: DNS 解析
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        resolved_ips = list({info[4][0] for info in infos})
    except Exception:
        return None

    if not resolved_ips:
        return None

    # 取第一个 IPv4 进行网段归属与非 CF 校验
    target_ip = resolved_ips[0]
    if target_ip == my_ip:
        return None
    if is_cloudflare_ip(target_ip):
        return None

    try:
        ip_obj = ipaddress.ip_address(target_ip)
        in_same_net = any(ip_obj in net for net in allowed_networks)
        if not in_same_net:
            return None
    except Exception:
        return None

    # Step 2a: 使用 Python ssl 模块直接进行底层 TLSv1.3 + ALPN(h2) + 证书有效性校验与毫秒级握手测速
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        t_start = time.monotonic()
        with socket.create_connection((target_ip, 443), timeout=3.5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssl_sock:
                handshake_ms = (time.monotonic() - t_start) * 1000.0
                tls_ver = ssl_sock.version()
                alpn_proto = ssl_sock.selected_alpn_protocol()
                cipher_info = ssl_sock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "TLS_AES_256_GCM_SHA384"

        if tls_ver != "TLSv1.3" or alpn_proto != "h2":
            return None
    except Exception:
        return None

    # Step 2b: 调用文章同款 curl 命令验证 HTTP/2 状态码必须是 200 (非 301/302 跳转)
    import os
    env = os.environ.copy()
    # 兼容 macOS SecureTransport
    if sys.platform == "darwin":
        env["CURL_SSL_BACKEND"] = "libressl"

    cmd = [
        "curl", "-I", "-v", "--tlsv1.3", "--http2",
        "--connect-timeout", "4", "--max-time", "6",
        "-A", UA,
        f"https://{domain}"
    ]
    try:
        t0 = time.monotonic()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=7, env=env)
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        output = proc.stdout or ""
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    # 校验状态码必须是 HTTP/2 200 (非 301/302 跳转)
    if not re.search(r"<\s*HTTP/2\s+200\b", output, re.I):
        return None

    # 二次确认响应头中不含 Server: cloudflare
    if re.search(r"<\s*server:\s*cloudflare", output, re.I):
        return None

    tls_line = f"SSL connection using {tls_ver} / {cipher_name}"
    alpn_line = "ALPN: server accepted h2"

    return {
        "domain": domain,
        "ip": target_ip,
        "latency_ms": round(handshake_ms, 2),
        "total_ms": round(elapsed_ms, 2),
        "tls_info": tls_line,
        "alpn_info": alpn_line,
        "http_status": "HTTP/2 200",
        "is_com_net": domain.endswith(".com") or domain.endswith(".net")
    }

def main():
    print("\033[0;36m[1/4] 正在查询当前 Linux 主机的公网 IP 与所属 ASN / BGP 号段...\033[0m")
    my_ip = get_public_ipv4()
    asns, asn_descs, prefixes = get_asn_and_prefixes(my_ip)

    asn_str = ", ".join([f"AS{a} ({asn_descs.get(a, 'Unknown')})" for a in asns]) if asns else "Unknown ASN"
    print(f"  ├─ 本机公网 IP  : \033[1;32m{my_ip}\033[0m")
    print(f"  ├─ 所属 ASN     : \033[1;32m{asn_str}\033[0m")
    print(f"  └─ 关联 BGP 号段: \033[1;33m{', '.join(prefixes)}\033[0m")

    print("\n\033[0;36m[2/4] 正在从 bgp.he.net (Certs 证书透明度数据库) 检索同网段邻居域名...\033[0m")
    domain_map = fetch_neighbor_domains_from_bgphe(prefixes)
    all_raw_domains = list(domain_map.keys())
    print(f"  ├─ 共检索到原始邻居证书域名: \033[1m{len(all_raw_domains)}\033[0m 个")

    # 过滤掉不合格格式并按 (.com/.net 优先、短域名优先) 排序
    filtered_domains = [d for d in all_raw_domains if is_good_domain_format(d)]
    filtered_domains.sort(key=domain_priority_key)
    candidates = filtered_domains[:MAX_CANDIDATES]
    print(f"  └─ 格式初筛后保留优质候选域名: \033[1m{len(candidates)}\033[0m 个 (优先短 com/net 域名)")

    if not candidates:
        print("\033[0;31m[!] 当前网段在 bgp.he.net Certs 中未找到合适候选域名。\033[0m")
        sys.exit(2)

    # 允许的同机房网段列表 (用于验证 ping/DNS 解析出的 IP 确实在同网段，未套 CF CDN)
    allowed_networks = []
    for p in prefixes:
        try:
            allowed_networks.append(ipaddress.ip_network(p, strict=False))
        except Exception:
            pass

    print(f"\n\033[0;36m[3/4] 正在并发校验候选域名 (TLSv1.3 + ALPN h2 + HTTP/2 200 + 同网段非CDN + 握手延迟测速)...\033[0m")
    valid_results = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_dom = {
            executor.submit(check_candidate_domain, dom, allowed_networks, my_ip): dom
            for dom in candidates
        }
        done_cnt = 0
        total_cnt = len(candidates)
        for future in as_completed(future_to_dom):
            done_cnt += 1
            res = future.result()
            if res:
                valid_results.append(res)
                print(
                    f"  \033[0;32m✓ [合格]\033[0m {res['domain']:<32} "
                    f"IP: {res['ip']:<15} TLS握手延迟: \033[1;32m{res['latency_ms']} ms\033[0m "
                    f"({res['http_status']}, h2, TLSv1.3)"
                )

    if not valid_results:
        print("\033[0;31m[!] 未能在当前网段筛选出同时满足 TLSv1.3 + H2 + HTTP 200 + 未套 CDN 的域名。\033[0m")
        sys.exit(3)

    # 按延迟从低到高排序 (满足用户“另外还要延迟最低的那个”要求)
    valid_results.sort(key=lambda x: (x["latency_ms"], 0 if x["is_com_net"] else 1, len(x["domain"])))
    best = valid_results[0]

    print(f"\n\033[0;36m[4/4] 筛选完成！共找到 {len(valid_results)} 个完全符合规范的邻居域名 (按延迟从低到高 Top 10)：\033[0m")
    print("  " + "-" * 86)
    print(f"  {'排名':<4} {'域名 (SNI / Target)':<32} {'解析 IP (同网段)':<16} {'TLS握手延迟':<12} {'协议验证'}")
    print("  " + "-" * 86)
    for idx, item in enumerate(valid_results[:10], 1):
        star = "★ 最优" if idx == 1 else f"#{idx}"
        color = "\033[1;32m" if idx == 1 else ""
        endc = "\033[0m" if idx == 1 else ""
        print(
            f"  {color}{star:<6} {item['domain']:<32} {item['ip']:<16} "
            f"{str(item['latency_ms']) + ' ms':<12} TLSv1.3 | ALPN: h2 | HTTP/2 200{endc}"
        )
    print("  " + "-" * 86)

    # 交互式选择要部署的伪装域名 (仅非 --scan 模式；无 TTY / 非法输入时回退到延迟最低的最优域名)
    selected_idx = 0
    if not SCAN_ONLY:
        show_n = min(len(valid_results), 10)
        print("")
        print("  请选择要使用的伪装域名 (直接回车 = 默认选 1，即延迟最低):")
        for idx, item in enumerate(valid_results[:show_n], 1):
            print(f"    [{idx}] {item['domain']:<32} {item['ip']:<15} {item['latency_ms']} ms")
        while True:
            try:
                raw = input_prompt(f"  请输入序号 [1-{show_n}]，默认 1: ")
            except Exception:
                selected_idx = 0
                break
            raw = raw.strip()
            if raw == "":
                selected_idx = 0
                break
            if raw.isdigit() and 1 <= int(raw) <= show_n:
                selected_idx = int(raw) - 1
                break
            print(f"  \033[1;33m输入无效，请输入 1-{show_n} 之间的数字。\033[0m")
        best = valid_results[selected_idx]

    output_payload = {
        "my_ip": my_ip,
        "asns": asns,
        "asn_descs": asn_descs,
        "prefixes": prefixes,
        "best": best,
        "all_valid": valid_results
    }
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
PYEOF
}

# ------------------------------------------------------------------------------
# 3. 部署 Xray: VLESS + TCP + XTLS-Vision + Reality
# ------------------------------------------------------------------------------
deploy_xray_reality() {
  local target_domain="$1"
  local server_ip="$2"
  local asn_tag="$3"

  if [[ $EUID -ne 0 ]]; then
    log_err "部署 Xray 需要 root 权限，请使用 sudo bash $0 或切换至 root 用户运行！"
    exit 1
  fi

  # ----------------------------------------------------------------------------
  # 检测并清理占用 LISTEN_PORT (默认 443) 的进程，以及确保 Xray 具备绑定低位端口权限
  # ----------------------------------------------------------------------------
  systemctl stop xray >/dev/null 2>&1 || true

  local pid_occupy=""
  if command -v ss >/dev/null 2>&1; then
    pid_occupy="$(ss -tulpn 2>/dev/null | grep -E ":${LISTEN_PORT}\b" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' ' || true)"
  elif command -v netstat >/dev/null 2>&1; then
    pid_occupy="$(netstat -tulpn 2>/dev/null | grep -E ":${LISTEN_PORT}\b" | awk '{print $7}' | cut -d/ -f1 | grep -E '^[0-9]+$' | sort -u | tr '\n' ' ' || true)"
  elif command -v lsof >/dev/null 2>&1; then
    pid_occupy="$(lsof -t -iTCP:"${LISTEN_PORT}" -sTCP:LISTEN 2>/dev/null | sort -u | tr '\n' ' ' || true)"
  fi

  if [[ -n "${pid_occupy// /}" ]]; then
    log_warn "检测到端口 ${LISTEN_PORT} 当前已被进程 PID [${pid_occupy}] 占用！"
    for pid in $pid_occupy; do
      local pname
      pname="$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")"
      log_warn "  ├─ 占用进程: PID=${pid} (${pname})，正在停止该服务/进程以释放 ${LISTEN_PORT} 端口..."
      # 如果是常见 Web / 代理服务，尝试先停 systemd 服务防止自动拉起
      for svc in nginx caddy apache2 httpd haproxy sing-box v2ray x-ui 3x-ui trojan; do
        if [[ "$pname" == *"$svc"* ]]; then
          systemctl stop "$svc" >/dev/null 2>&1 || true
          systemctl disable "$svc" >/dev/null 2>&1 || true
        fi
      done
      kill -9 "$pid" >/dev/null 2>&1 || true
    done
    sleep 1
  fi

  log_info "正在安装/更新官方 Xray-core (XTLS/Xray-install)..."
  bash -c "$(curl -L -s https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1 || \
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

  local xray_bin="/usr/local/bin/xray"
  if [[ ! -x "$xray_bin" ]]; then
    log_err "Xray 安装失败，未找到 /usr/local/bin/xray"
    exit 1
  fi

  # 确保 systemd xray.service 以 root 权限或具备 CAP_NET_BIND_SERVICE 运行 (防止 nobody 用户在 Debian 13/容器下无法监听 443)
  mkdir -p /etc/systemd/system/xray.service.d
  cat > /etc/systemd/system/xray.service.d/10-root-bind.conf <<'EOF'
[Service]
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
EOF
  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_bind_service,cap_net_admin+ep "$xray_bin" >/dev/null 2>&1 || true
  fi

  # 生成 UUID、x25519 密钥对、ShortID
  local uuid
  uuid="$("$xray_bin" uuid)"

  local key_out
  key_out="$("$xray_bin" x25519)"
  # 兼容新旧版本 xray x25519 输出格式:
  # 旧版: Private key: xxx / Public key: yyy
  # 新版 (v25+): PrivateKey: xxx / Password (PublicKey): yyy
  local private_key public_key
  private_key="$(echo "$key_out" | awk -F': ' '/Private/ {print $2}' | tr -d ' \r\n')"
  public_key="$(echo "$key_out" | awk -F': ' '/Public|Password/ {print $2}' | head -n1 | tr -d ' \r\n')"

  if [[ -z "$private_key" || -z "$public_key" ]]; then
    log_err "无法解析 xray x25519 密钥对，原始输出: $key_out"
    exit 1
  fi

  local short_id
  short_id="$(openssl rand -hex 8)"

  log_info "正在写入 Xray 配置文件 (/usr/local/etc/xray/config.json)..."
  mkdir -p /usr/local/etc/xray
  cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${LISTEN_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${target_domain}:443",
          "xver": 0,
          "serverNames": [
            "${target_domain}"
          ],
          "privateKey": "${private_key}",
          "shortIds": [
            "${short_id}",
            ""
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

  # 检查并尝试启用 BBR
  if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
    log_info "正在尝试开启 TCP BBR 拥塞控制加速..."
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf 2>/dev/null; then
      echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
      echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
      sysctl -p >/dev/null 2>&1 || true
    fi
  fi

  # 放行防火墙端口 (如果启用了 ufw 或 firewalld)
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${LISTEN_PORT}/tcp" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port="${LISTEN_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  systemctl reset-failed xray >/dev/null 2>&1 || true
  systemctl enable xray >/dev/null 2>&1
  systemctl restart xray

  sleep 1
  if systemctl is-active --quiet xray; then
    log_ok "Xray (VLESS + TCP + Vision + Reality) 服务启动成功！"
  else
    log_err "Xray 服务启动失败！详细错误原因如下："
    journalctl -u xray -n 15 --no-pager -o cat || true
    log_warn "如果是因为 443 端口被 Docker 容器或其他守护进程强占且不想关闭它，可执行: sudo bash $0 --port 8443"
    exit 1
  fi

  # 生成 v2rayNG / v2rayN / Shadowrocket 标准 VLESS 分享链接
  local remark="Reality_${asn_tag}_${target_domain}"
  local encoded_remark
  encoded_remark="$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$remark")"

  local vless_url="vless://${uuid}@${server_ip}:${LISTEN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${target_domain}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#${encoded_remark}"

  # 保存到文件方便随时查看
  local info_file="/root/vless_reality_neighbor_info.txt"
  cat > "$info_file" <<EOF
================================================================================
 VLESS + TCP + XTLS-Vision + Reality (同网段邻居伪装) 部署完成
================================================================================
服务器 IP (Address)   : ${server_ip}
端口 (Port)           : ${LISTEN_PORT}
用户 UUID             : ${uuid}
流控 (Flow)           : xtls-rprx-vision
传输协议 (Network)    : tcp
传输层安全 (TLS)      : reality
伪装目标 (Target/Dest): ${target_domain}:443
伪装域名 (SNI)        : ${target_domain}
指纹 (Fingerprint)    : chrome
公钥 (PublicKey/pbk)  : ${public_key}
私钥 (PrivateKey)     : ${private_key}
ShortId (sid)         : ${short_id}
配置文件路径          : /usr/local/etc/xray/config.json
--------------------------------------------------------------------------------
[v2rayNG / v2rayN / Nekobox / Shadowrocket 一键导入 URL]:
${vless_url}
================================================================================
EOF

  echo ""
  echo -e "${GREEN}${BOLD}================================================================================${NC}"
  echo -e "${GREEN}${BOLD}       VLESS + TCP + Vision + Reality (同网段低延迟邻居域名) 部署成功！         ${NC}"
  echo -e "${GREEN}${BOLD}================================================================================${NC}"
  echo -e "  ${BOLD}服务器地址 (Address)${NC} : ${CYAN}${server_ip}${NC}"
  echo -e "  ${BOLD}监听端口 (Port)${NC}      : ${CYAN}${LISTEN_PORT}${NC}"
  echo -e "  ${BOLD}用户 ID (UUID)${NC}       : ${CYAN}${uuid}${NC}"
  echo -e "  ${BOLD}流控 (Flow)${NC}          : ${CYAN}xtls-rprx-vision${NC}"
  echo -e "  ${BOLD}安全类型 (Security)${NC}  : ${CYAN}reality${NC}"
  echo -e "  ${BOLD}Target (Dest)${NC}        : ${YELLOW}${target_domain}:443${NC}"
  echo -e "  ${BOLD}SNI (ServerName)${NC}     : ${YELLOW}${target_domain}${NC}"
  echo -e "  ${BOLD}指纹 (Fingerprint)${NC}   : ${CYAN}chrome${NC}"
  echo -e "  ${BOLD}公钥 (PublicKey)${NC}     : ${CYAN}${public_key}${NC}"
  echo -e "  ${BOLD}ShortID (sid)${NC}        : ${CYAN}${short_id}${NC}"
  echo -e "${GREEN}--------------------------------------------------------------------------------${NC}"
  echo -e "${BOLD}▶ v2rayNG / v2rayN 快速导入分享链接 (复制整行到剪贴板 -> 从剪贴板导入):${NC}"
  echo ""
  echo -e "${YELLOW}${vless_url}${NC}"
  echo ""
  if command -v qrencode >/dev/null 2>&1; then
    echo -e "${BOLD}▶ 手机端 v2rayNG / Shadowrocket 扫码直接导入:${NC}"
    qrencode -t ANSIUTF8 "${vless_url}" || true
  fi
  echo -e "${GREEN}--------------------------------------------------------------------------------${NC}"
  echo -e "节点信息已保存至: ${CYAN}${info_file}${NC}"
}

# ------------------------------------------------------------------------------
# 4. 卸载 Xray 及本脚本生成的所有配置与文件
# ------------------------------------------------------------------------------
uninstall_xray_reality() {
  if [[ $EUID -ne 0 ]]; then
    log_err "卸载 Xray 需要 root 权限，请使用 sudo bash $0 --uninstall 或切换至 root 用户运行！"
    exit 1
  fi

  local info_file="/root/vless_reality_neighbor_info.txt"
  local xray_cfg="/usr/local/etc/xray/config.json"
  local detected_port=""

  # 尝试在删除配置前识别当前 Xray 监听端口，用于清理对应防火墙放行规则
  if [[ $PORT_SPECIFIED -eq 1 ]]; then
    detected_port="$LISTEN_PORT"
  elif [[ -f "$xray_cfg" ]]; then
    detected_port="$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$xray_cfg" 2>/dev/null | head -n1 | grep -oE '[0-9]+' || true)"
  elif [[ -f "$info_file" ]]; then
    detected_port="$(grep -E '^端口 \(Port\)' "$info_file" 2>/dev/null | awk -F':' '{print $2}' | tr -d ' \r\n' || true)"
  fi

  echo -e "${YELLOW}${BOLD}即将执行以下卸载清理操作：${NC}"
  echo "  1. 停止并禁用 systemd 服务 (xray)"
  echo "  2. 卸载 Xray 程序、配置与日志 (/usr/local/bin/xray, /usr/local/etc/xray, /usr/local/share/xray, /var/log/xray)"
  echo "  3. 删除本脚本写入的 systemd 覆盖配置 (/etc/systemd/system/xray.service.d/10-root-bind.conf)"
  echo "  4. 删除保存的节点信息文件 (${info_file}) 及临时扫描缓存"
  if [[ -n "$detected_port" ]]; then
    echo "  5. 移除防火墙放行端口规则 (${detected_port}/tcp，若 ufw / firewalld 已启用)"
  fi
  echo -e "  ${CYAN}* 注: 系统基础依赖包与 /etc/sysctl.conf 中的 BBR 内核优化将予以保留。${NC}"
  echo ""

  if [[ $ASSUME_YES -eq 0 ]]; then
    local confirm=""
    if [[ -t 0 ]]; then
      read -r -p "确定要继续卸载吗？[y/N]: " confirm || true
    elif [[ -r /dev/tty ]]; then
      read -r -p "确定要继续卸载吗？[y/N]: " confirm </dev/tty || true
    else
      log_err "当前处于非交互终端，请追加 --yes (-y) 参数以确认卸载。"
      exit 1
    fi

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      log_info "已取消卸载操作。"
      exit 0
    fi
  fi

  log_info "正在停止并禁用 Xray 服务..."
  systemctl stop xray >/dev/null 2>&1 || true
  systemctl disable xray >/dev/null 2>&1 || true

  # 优先尝试调用官方 Xray-install 卸载脚本 (失败则自动回退到本地彻底清理)
  if command -v curl >/dev/null 2>&1; then
    log_info "正在调用官方 XTLS/Xray-install 卸载 Xray..."
    local remove_script=""
    remove_script="$(curl -L -s --connect-timeout 8 --max-time 20 https://github.com/XTLS/Xray-install/raw/main/install-release.sh 2>/dev/null || true)"
    if [[ -n "$remove_script" ]]; then
      bash -c "$remove_script" @ remove --purge >/dev/null 2>&1 || true
    else
      log_warn "无法连接 GitHub 获取官方卸载脚本，将直接使用本地清理模式。"
    fi
  fi

  log_info "正在清理 Xray 二进制、配置、systemd 覆盖文件及残留目录..."
  rm -f /etc/systemd/system/xray.service.d/10-root-bind.conf
  rmdir /etc/systemd/system/xray.service.d 2>/dev/null || true
  rm -f /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
  rm -f /usr/local/bin/xray
  rm -rf /usr/local/etc/xray /usr/local/share/xray /var/log/xray
  rm -f "$info_file"
  rm -f /tmp/reality_best_domain_*.json /tmp/reality_best_domain.json

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed xray >/dev/null 2>&1 || true

  if [[ -n "$detected_port" ]]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
      log_info "正在从 ufw 移除端口放行规则 (${detected_port}/tcp)..."
      ufw delete allow "${detected_port}/tcp" >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
      log_info "正在从 firewalld 移除端口放行规则 (${detected_port}/tcp)..."
      firewall-cmd --permanent --remove-port="${detected_port}/tcp" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    fi
  fi

  echo ""
  log_ok "卸载完成！Xray 及本脚本生成的所有配置与节点信息文件已彻底清理。"
}

# ------------------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------------------
main() {
  echo -e "${BOLD}${BLUE}================================================================================${NC}"
  echo -e "${BOLD}${BLUE}   VLESS + Vision + Reality 同网段/ASN 邻居伪装域名自动筛选与一键部署工具      ${NC}"
  echo -e "${BOLD}${BLUE}================================================================================${NC}"

  if [[ $UNINSTALL -eq 1 ]]; then
    uninstall_xray_reality
    exit 0
  fi

  install_base_deps

  local scan_json="/tmp/reality_best_domain_$$.json"
  trap 'rm -f "$scan_json"' EXIT

  if [[ -n "$CUSTOM_DOMAIN" ]]; then
    log_info "已手动指定伪装域名: ${CUSTOM_DOMAIN}，正在用文章同款 curl 命令校验其合规性..."
    local verify_out
    verify_out="$(curl -I -v --tlsv1.3 --http2 --connect-timeout 5 --max-time 8 "https://${CUSTOM_DOMAIN}" 2>&1 || true)"
    echo "$verify_out" | grep -E "SSL connection|ALPN|HTTP/" || true

    if ! echo "$verify_out" | grep -qi "SSL connection using TLSv1.3"; then
      log_warn "注意: ${CUSTOM_DOMAIN} 未检测到 TLSv1.3 支持！"
    fi
    if ! echo "$verify_out" | grep -Eqi "ALPN[:,]? server accepted (to use )?h2"; then
      log_warn "注意: ${CUSTOM_DOMAIN} 未检测到 ALPN h2 支持！"
    fi
    if ! echo "$verify_out" | grep -Eqi "< HTTP/2 200"; then
      log_warn "注意: ${CUSTOM_DOMAIN} 状态码不是 HTTP/2 200 (可能存在 301/302 跳转)！"
    fi

    local my_ip
    my_ip="$(curl -s4m 5 https://api.ipify.org || curl -s4m 5 https://ipv4.icanhazip.com)"
    deploy_xray_reality "$CUSTOM_DOMAIN" "$my_ip" "Custom"
    exit 0
  fi

  # 执行全自动 ASN 查询 + 邻居域名获取 + 合规筛选 + 最低延迟排序
  scan_best_neighbor_domain "$scan_json"

  local best_domain best_ip best_latency my_ip first_asn
  best_domain="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["best"]["domain"])' "$scan_json")"
  best_ip="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["best"]["ip"])' "$scan_json")"
  best_latency="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["best"]["latency_ms"])' "$scan_json")"
  my_ip="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["my_ip"])' "$scan_json")"
  first_asn="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("AS"+d["asns"][0] if d["asns"] else "ASN")' "$scan_json")"

  echo ""
  log_ok "已自动选出延迟最低且符合全部规范的同网段邻居域名: ${BOLD}${GREEN}${best_domain}${NC} (IP: ${best_ip}, 握手延迟: ${best_latency} ms)"

  # 展示文章同款 curl 命令的逐行验证输出，供用户直观核对
  echo ""
  log_info "执行文章同款命令复核最优域名 [curl -I -v --tlsv1.3 --http2 https://${best_domain}]:"
  CURL_SSL_BACKEND=libressl curl -I -v --tlsv1.3 --http2 --connect-timeout 5 --max-time 8 "https://${best_domain}" 2>&1 | grep -E "SSL connection|ALPN|using HTTP/2|HTTP/" | sed 's/^/  /' || true
  echo ""

  if [[ $SCAN_ONLY -eq 1 ]]; then
    log_info "当前为仅扫描模式 (--scan)，已完成邻居域名筛选与延迟排名。"
    exit 0
  fi

  deploy_xray_reality "$best_domain" "$my_ip" "$first_asn"
}

main "$@"
