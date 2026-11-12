#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fn-openwrt-manager 后端服务（纯 Python 标准库实现）。

功能：
1. 自动识别本机所在局域网网段（ip addr / 路由表 / socket 兜底）；
2. 并发 TCP + HTTP 探测，识别网段内的 OpenWrt / iStoreOS / ImmortalWrt 设备；
3. 手动添加路由器地址（支持 IP、IP:端口、完整 URL）；
4. 收藏地址持久化到 TRIM_PKGVAR/data/devices.json；
5. 提供静态页面与 JSON API。

环境变量：
    APP_PORT       监听端口（来自 manifest.service_port）
    APP_WWW_DIR    静态页面目录
    APP_DATA_DIR   数据目录
    APP_VERSION    版本号（仅用于页面展示）
"""

import collections
import gzip
import http.client
import ipaddress
import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

APP_VERSION = os.environ.get("APP_VERSION") or "1.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WWW_DIR = os.environ.get("APP_WWW_DIR") or os.path.join(os.path.dirname(BASE_DIR), "www")
DATA_DIR = os.environ.get("APP_DATA_DIR") or os.path.join(os.path.dirname(BASE_DIR), "data")
PORT = int(os.environ.get("APP_PORT") or 8199)
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")

# 扫描时尝试的端口，越靠前优先级越高
TARGET_PORTS = [80, 443, 8080, 8443]
PORT_PRIORITY = {80: 0, 8080: 1, 443: 2, 8443: 3}
SCAN_WORKERS = 128
CONNECT_TIMEOUT = 0.35
HTTP_TIMEOUT = 2.0
MAX_SCAN_HOSTS = 1024
UA = "fn-openwrt-manager/" + APP_VERSION
# 单个请求体上限：超过就丢弃并断开连接，避免占内存/以错位换省事
MAX_BODY = 8 * 1024 * 1024

LUCI_HINTS = ("openwrt", "istoreos", "immortalwrt", "gargoyle", "luci-app")
TITLE_HINTS = ("luci", "openwrt", "istoreos", "immortalwrt", "padavan", "gargoyle", "qwrt")


def log(*args):
    print("[%s]" % time.strftime("%Y-%m-%d %H:%M:%S"), *args, flush=True)


# ---------------------------------------------------------------- 网段识别

SKIP_IFACE_PREFIX = ("lo", "docker", "veth", "virbr", "br-", "tun", "tap", "zt", "wg", "kube", "cni")


def _run(cmd, timeout=5):
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        return proc.stdout.decode("utf-8", "ignore")
    except Exception:
        return ""


def _limit_net(ip, prefix):
    """把过大的网段（/16 之类）收敛成 /24，避免扫描量爆炸。"""
    if prefix < 24:
        return ipaddress.IPv4Network("%s/24" % ip, strict=False)
    if prefix > 30:
        return ipaddress.IPv4Network("%s/30" % ip, strict=False)
    return ipaddress.IPv4Network("%s/%d" % (ip, prefix), strict=False)


def list_interfaces():
    """返回 [{iface, ip, prefix, cidr, hosts}]"""
    found = []
    seen = set()
    raw = _run(["ip", "-4", "-o", "addr", "show"])
    for line in raw.splitlines():
        m = re.match(r"^\d+:\s+([^\s@]+)(?:@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        iface, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if iface.startswith(SKIP_IFACE_PREFIX):
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_link_local or addr.is_loopback:
            continue
        net = _limit_net(ip, prefix)
        if net.prefixlen not in (24, 30) and net.num_addresses > 256:
            continue
        if str(net) in seen:
            continue
        seen.add(str(net))
        found.append({
            "iface": iface,
            "ip": ip,
            "prefix": prefix,
            "cidr": str(net),
            "hosts": max(net.num_addresses - 2, 0),
        })

    if found:
        return found

    # 兜底：用 UDP 连接推本地出口 IP，按 /24 处理
    ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("223.5.5.5", 53))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        return []
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return []
    if addr.is_loopback:
        return []
    net = ipaddress.IPv4Network("%s/24" % ip, strict=False)
    return [{"iface": "auto", "ip": ip, "prefix": 24, "cidr": str(net), "hosts": 254}]


def default_gateway():
    raw = _run(["ip", "route", "show", "default"])
    m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", raw)
    if m:
        return m.group(1)
    try:
        with open("/proc/net/route", "r") as fp:
            for line in fp.readlines()[1:]:
                parts = line.split()
                if len(parts) < 3 or parts[1] != "00000000":
                    continue
                hexip = parts[2]
                return ".".join(str(int(hexip[i:i + 2], 16)) for i in (6, 4, 2, 0))
    except OSError:
        pass
    return ""


def arp_hosts(cidrs):
    """读取 ARP 缓存，作为扫描结果的补充（能发现不回 HTTP 的设备）。"""
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            continue
    out = []
    try:
        with open("/proc/net/arp", "r") as fp:
            for line in fp.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[2] == "0x0":
                    continue
                try:
                    addr = ipaddress.IPv4Address(parts[0])
                except ValueError:
                    continue
                if addr.is_link_local:
                    continue
                if any(addr in n for n in nets):
                    out.append(str(addr))
    except OSError:
        return []
    return out


# ---------------------------------------------------------------- 设备探测

def tcp_open(ip, port, timeout=CONNECT_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def http_fetch(url, timeout=HTTP_TIMEOUT):
    """返回 (final_url, status, headers_dict, body) 或 None。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            body = resp.read(65536).decode("utf-8", "ignore")
            return resp.geturl(), resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(65536).decode("utf-8", "ignore")
        except Exception:
            body = ""
        return url, exc.code, dict(exc.headers or {}), body
    except Exception:
        return None


def page_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.S | re.I)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:60]


def classify(fetched):
    """判断设备类型：openwrt / web / unknown（尽量降低误判）"""
    if not fetched:
        return "unknown", "", ""
    final_url, _status, headers, body = fetched
    server = (headers.get("Server") or "").strip()
    text = (body or "").lower()
    title = page_title(body)
    low_title = title.lower()
    score = 0

    if "uhttpd" in server.lower():
        score += 3
    if "cgi-bin/luci" in text:
        score += 3
    if any(k in text for k in LUCI_HINTS):
        score += 2
    if re.search(r"(?<![a-z0-9])luci(?![a-z0-9])", text[:40000]):
        score += 1
    if any(re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(k), low_title) for k in TITLE_HINTS):
        score += 2

    if score >= 2:
        return "openwrt", title, server
    return "web", title, server


def make_device(ip, port, scheme, kind, title, server, gateway=""):
    netloc = ip if port in (80, 443) else "%s:%d" % (ip, port)
    return {
        "id": "%s:%d" % (ip, port),
        "ip": ip,
        "port": port,
        "url": "%s://%s/" % (scheme, netloc),
        "kind": kind,
        "title": title or "",
        "server": server or "",
        "is_gateway": bool(gateway and ip == gateway),
    }


def probe_host(ip, gateway=""):
    """探测单台主机，命中返回设备信息，否则 None。"""
    open_ports = [p for p in TARGET_PORTS if tcp_open(ip, p)]
    if not open_ports:
        return None

    fallback = None
    for port in sorted(open_ports, key=lambda p: PORT_PRIORITY.get(p, 99)):
        scheme = "https" if port in (443, 8443) else "http"
        fetched = http_fetch("%s://%s:%d/" % (scheme, ip, port))
        kind, title, server = classify(fetched)
        device = make_device(ip, port, scheme, kind, title, server, gateway)
        if kind == "openwrt":
            return device
        if fallback is None:
            if not title and port in (80, 8080):
                fetched2 = http_fetch("%s://%s:%d/cgi-bin/luci/" % (scheme, ip, port))
                kind2, title2, server2 = classify(fetched2)
                if kind2 == "openwrt":
                    return make_device(ip, port, scheme, "openwrt", title2, server2, gateway)
            fallback = device
    return fallback


def probe_address(address):
    """手动添加地址时的探测：返回设备信息。"""
    url, host, port, scheme = normalize_address(address)
    open_flag = tcp_open(host, port, timeout=1.5)
    fetched = http_fetch(url) if open_flag else None
    kind, title, server = classify(fetched)
    if kind == "unknown" and open_flag:
        kind = "web"
    netloc = host if port in (80, 443) else "%s:%d" % (host, port)
    return {
        "id": "%s:%d" % (host, port),
        "ip": host,
        "port": port,
        "url": "%s://%s/" % (scheme, netloc),
        "kind": kind,
        "title": title,
        "server": server,
        "reachable": bool(open_flag),
        "is_gateway": False,
    }


def normalize_address(address):
    """把用户输入规范成 (url, host, port, scheme)。"""
    raw = (address or "").strip()
    if not raw:
        raise ValueError("地址不能为空")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        raise ValueError("地址格式不正确")
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("仅支持 http / https 地址")
    port = parsed.port or (443 if scheme == "https" else 80)
    if not (1 <= port <= 65535):
        raise ValueError("端口超出范围")
    path = parsed.path or "/"
    netloc = host if port in (80, 443) else "%s:%d" % (host, port)
    url = "%s://%s%s" % (scheme, netloc, path)
    return url, host, port, scheme


# ---------------------------------------------------------------- 扫描任务

class ScanState(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.cancel = False
        self.total = 0
        self.done = 0
        self.cidrs = []
        self.found = []
        self.error = ""
        self.started = 0.0
        self.finished = 0.0
        self.gateway = ""

    def start(self, cidrs, gateway):
        with self.lock:
            if self.running:
                return False
            self.running = True
            self.cancel = False
            self.total = 0
            self.done = 0
            self.cidrs = list(cidrs)
            self.found = []
            self.error = ""
            self.started = time.time()
            self.finished = 0.0
            self.gateway = gateway
            return True

    def snapshot(self):
        with self.lock:
            return {
                "running": self.running,
                "total": self.total,
                "done": self.done,
                "cidrs": list(self.cidrs),
                "found": list(self.found),
                "error": self.error,
                "gateway": self.gateway,
                "elapsed": round((self.finished or time.time()) - self.started, 1) if self.started else 0,
            }

    def add_result(self, device):
        with self.lock:
            self.done += 1
            if device:
                self.found.append(device)

    def add_extra(self, device):
        """扫描完成后的补充结果（不计入进度）。"""
        with self.lock:
            if device:
                self.found.append(device)

STATE = ScanState()


def sort_devices(devices, gateway):
    def key(d):
        kind_rank = {"openwrt": 0, "web": 1, "unknown": 2}.get(d.get("kind"), 3)
        gw_rank = 0 if (gateway and d.get("ip") == gateway) else 1
        try:
            ipkey = tuple(int(x) for x in d["ip"].split("."))
        except Exception:
            ipkey = (999, 999, 999, 999)
        return (kind_rank, gw_rank, ipkey)
    return sorted(devices, key=key)


def run_scan(cidrs, gateway):
    targets = []
    seen = set()
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        for host in net.hosts():
            ip = str(host)
            if ip in seen:
                continue
            seen.add(ip)
            targets.append(ip)
            if len(targets) >= MAX_SCAN_HOSTS:
                break
        if len(targets) >= MAX_SCAN_HOSTS:
            break

    with STATE.lock:
        STATE.total = len(targets)
    log("扫描开始 网段=%s 主机数=%d" % (",".join(cidrs), len(targets)))

    try:
        pending = set()
        cursor = {"i": 0}

        def submit_next(ex):
            if STATE.cancel:
                return False
            while cursor["i"] < len(targets):
                ip = targets[cursor["i"]]
                cursor["i"] += 1
                pending.add(ex.submit(probe_host, ip, gateway))
                return True
            return False

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as executor:
            for _ in range(SCAN_WORKERS * 2):
                if not submit_next(executor):
                    break
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        result = future.result()
                    except Exception:
                        result = None
                    STATE.add_result(result)
                if STATE.cancel:
                    break
                for _ in range(len(done)):
                    if not submit_next(executor):
                        break

        # ARP 缓存补充：能发现不开放 Web 端口的设备
        known = set()
        with STATE.lock:
            for item in STATE.found:
                known.add(item["ip"])
        for ip in arp_hosts(cidrs):
            if ip in known:
                continue
            known.add(ip)
            STATE.add_extra({
                "id": "%s:0" % ip,
                "ip": ip,
                "port": 80,
                "url": "http://%s/" % ip,
                "kind": "unknown",
                "title": "",
                "server": "",
                "is_gateway": bool(gateway and ip == gateway),
            })

        with STATE.lock:
            STATE.found = sort_devices(STATE.found, gateway)
        log("扫描结束 发现=%d 用时=%.1fs" % (len(STATE.found), time.time() - STATE.started))
    except Exception as exc:  # noqa: BLE001
        log("扫描异常:", repr(exc))
        with STATE.lock:
            STATE.error = str(exc)
    finally:
        with STATE.lock:
            STATE.running = False
            STATE.cancel = False
            STATE.finished = time.time()
            if STATE.done < STATE.total:
                STATE.done = STATE.total


# ---------------------------------------------------------------- 收藏持久化

DEVICES_LOCK = threading.Lock()


def load_devices():
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            data = data.get("devices", [])
        return [d for d in data if isinstance(d, dict) and d.get("url")]
    except (OSError, ValueError):
        return []


def save_devices(devices):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DEVICES_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump({"devices": devices}, fp, ensure_ascii=False, indent=2)
    os.replace(tmp, DEVICES_FILE)


def add_device(name, address):
    url, host, port, scheme = normalize_address(address)
    info = probe_address(address)
    entry = {
        "id": "%s-%d" % (host, int(time.time() * 1000) % 1000000),
        "name": (name or "").strip()[:40] or (info.get("title") or host),
        "url": url,
        "ip": host,
        "port": port,
        "kind": info.get("kind", "unknown"),
        "title": info.get("title", ""),
        "created_at": int(time.time()),
    }
    with DEVICES_LOCK:
        devices = load_devices()
        for old in devices:
            if old.get("url") == entry["url"]:
                return old, False
        devices.insert(0, entry)
        save_devices(devices)
    return entry, True


# ---------------------------------------------------------------- 扫描结果忽略列表
# 用户从扫描结果里「删除」的设备，记录在这里，下次扫描不再显示。

IGNORED_FILE = os.path.join(DATA_DIR, "ignored.json")
IGNORED_LOCK = threading.Lock()


def load_ignored():
    try:
        with open(IGNORED_FILE, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            data = data.get("ids", [])
        return [str(x) for x in data if str(x).strip()]
    except (OSError, ValueError):
        return []


def save_ignored(ids):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = IGNORED_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump({"ids": ids}, fp, ensure_ascii=False, indent=2)
    os.replace(tmp, IGNORED_FILE)


def ignore_device(dev_id):
    dev_id = (dev_id or "").strip()
    if not dev_id:
        raise ValueError("缺少设备标识")
    with IGNORED_LOCK:
        ids = load_ignored()
        if dev_id not in ids:
            ids.append(dev_id)
            save_ignored(ids)
    return ids


def unignore_device(dev_id):
    with IGNORED_LOCK:
        ids = load_ignored()
        if dev_id:
            ids = [x for x in ids if x != dev_id]
        else:
            ids = []
        save_ignored(ids)
    return ids


# ---------------------------------------------------------------- 反向代理
# 外网访问时浏览器到不了 192.168.x.x，由 NAS 代为请求并回传页面。
# 路径规则：/proxy/{scheme}/{host}:{port}/{原始路径}

PROXY_PREFIX = "/proxy/"
# 路由器上的长轮询 / 事件流可能很久才结束，超时给足
PROXY_TIMEOUT = 65

# 最近的中转请求记录，便于在应用内直接看到浏览器到底请求了什么
PROXY_LOG = collections.deque(maxlen=200)
PROXY_LOG_LOCK = threading.Lock()


def proxy_log(method, target, status, elapsed, note=""):
    with PROXY_LOG_LOCK:
        PROXY_LOG.append({
            "time": time.strftime("%H:%M:%S"),
            "method": method,
            "target": target,
            "status": status,
            "ms": int(elapsed * 1000),
            "note": note,
        })


def proxy_log_snapshot():
    with PROXY_LOG_LOCK:
        return list(PROXY_LOG)

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "accept-encoding", "content-length", "server", "date",
}

# 运行时补丁：把页面里动态拼出的绝对路径（XHR / fetch）也转成代理路径
PROXY_SHIM = r"""
<script data-proxy-shim>(function(){
  var P="__PREFIX__";
  var ORIGIN=location.protocol+"//"+location.host;
  function fix(u){
    if (typeof u !== "string" || !u) return u;
    if (u.indexOf(P) === 0) return u;
    if (u.charAt(0) === "/" && u.charAt(1) !== "/") return P + u;
    // 绝对地址但仍指向本应用：LuCI 会用 location.origin 把 RPC 地址展开成
    // http://<NAS>:8199/ubus/（它不支持子路径挂载），这里把路径补上前缀。
    if (u.indexOf(ORIGIN + "/") === 0) {
      var tail = u.slice(ORIGIN.length);
      if (tail.indexOf(P) === 0) return u;
      return ORIGIN + P + tail;
    }
    return u;
  }
  var X = window.XMLHttpRequest;
  if (X && X.prototype && X.prototype.open) {
    var o = X.prototype.open;
    X.prototype.open = function(){ var a = [].slice.call(arguments); a[1] = fix(a[1]); return o.apply(this, a); };
  }
  if (window.fetch) {
    var f = window.fetch;
    window.fetch = function(i, init){ return f.call(this, typeof i === "string" ? fix(i) : i, init); };
  }
  if (window.EventSource) {
    var E = window.EventSource;
    window.EventSource = function(u, c){ return new E(fix(u), c); };
  }
  if (window.WebSocket) {
    var W = window.WebSocket;
    window.WebSocket = function(u, protocols){
      var out = u;
      if (typeof u === "string") {
        if (u.charAt(0) === "/") {
          out = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + P + u;
        } else {
          var m = /^(wss?:\/\/)([^\/]+)([\s\S]*)$/.exec(u);
          if (m && m[2] === location.host) {
            var p = m[3] || "/";
            if (p.charAt(0) !== "/") p = "/" + p;
            out = location.protocol === "https:" ? "wss://" : "ws://";
            out += location.host + (p.indexOf(P) === 0 ? p : P + p);
          }
        }
      }
      return new W(out, protocols);
    };
    window.WebSocket.prototype = W.prototype;
    window.WebSocket.CONNECTING = W.CONNECTING;
    window.WebSocket.OPEN = W.OPEN;
    window.WebSocket.CLOSING = W.CLOSING;
    window.WebSocket.CLOSED = W.CLOSED;
  }
})();</script>
"""

CSP_TAG = re.compile(r"<head[^>]*>", re.I)
ATTR_ROOT = re.compile(r'(\s(?:href|src|action|poster|data-src)\s*=\s*)(["\'])(/(?!/))', re.I)
CSS_URL = re.compile(r"url\(\s*(['\"]?)/(?!/)", re.I)
JS_PREFIXES = ("/cgi-bin/luci", "/luci-static/", "/luci/", "/luci-static")


def proxy_base(scheme, host, port):
    return "%s%s/%s:%d" % (PROXY_PREFIX, scheme, host, port)


def allowed_proxy_host(host):
    """只允许代理到局域网私有地址，避免被当成任意 SSRF 跳板。"""
    try:
        addr = ipaddress.IPv4Address(host)
        return addr.is_private or addr.is_loopback or addr in ipaddress.IPv4Network("100.64.0.0/10")
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        try:
            addr = ipaddress.IPv4Address(info[4][0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
    return False


def rewrite_html(text, prefix):
    # 先改写原页面里的绝对路径，再注入 base/shim，避免 base 被二次加前缀
    text = ATTR_ROOT.sub(lambda m: m.group(1) + m.group(2) + prefix + m.group(3), text)
    text = CSS_URL.sub(lambda m: "url(" + m.group(1) + prefix + "/", text)
    for p in JS_PREFIXES:
        text = text.replace('"%s' % p, '"%s%s' % (prefix, p))
        text = text.replace("'%s" % p, "'%s%s" % (prefix, p))
    inject = '<base href="%s/">' % prefix + PROXY_SHIM.replace("__PREFIX__", prefix)
    if CSP_TAG.search(text):
        text = CSP_TAG.sub(lambda m: m.group(0) + inject, text, count=1)
    else:
        text = inject + text
    return text


def rewrite_css(text, prefix):
    text = CSS_URL.sub(lambda m: "url(" + m.group(1) + prefix + "/", text)
    return text


def rewrite_js(text, prefix):
    for p in JS_PREFIXES:
        text = text.replace('"%s' % p, '"%s%s' % (prefix, p))
        text = text.replace("'%s" % p, "'%s%s" % (prefix, p))
    return text


def rewrite_location(location, prefix):
    if not location:
        return location
    if location.startswith(prefix):
        return location
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", location):
        parts = urlsplit(location)
        path = parts.path or "/"
        return prefix + path + (("?" + parts.query) if parts.query else "")
    if location.startswith("/"):
        return prefix + location
    return location


def rewrite_cookie(value, prefix):
    value = re.sub(r";\s*domain=[^;]*", "", value, flags=re.I)
    if re.search(r";\s*path=", value, re.I):
        value = re.sub(r";\s*path=[^;]*", "; Path=%s/" % prefix, value, flags=re.I)
    else:
        value = value + "; Path=%s/" % prefix
    return value


def charset_of(content_type):
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    if m:
        name = m.group(1).lower()
        try:
            "".encode(name)
            return name
        except LookupError:
            return "utf-8"
    return "utf-8"


def decompress_body(data, encoding):
    encoding = (encoding or "").lower()
    try:
        if "gzip" in encoding:
            return gzip.decompress(data)
        if "deflate" in encoding:
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        return data
    return data


PROXY_ERROR_PAGE = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>中转失败</title></head>
<body style="font-family:system-ui,-apple-system,'Microsoft YaHei';background:#0d1117;color:#e6edf3;padding:48px">
<h2>无法通过 NAS 访问该路由器</h2>
<p style="color:#8b949e">%(reason)s</p>
<p style="color:#8b949e">请确认 NAS 与该设备在同一局域网，并且设备管理页面已开启。</p>
<p><a href="%(home)s" style="color:#2fd07a">返回路由管理</a></p>
</body></html>"""


# ---------------------------------------------------------------- HTTP 服务

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "fn-openwrt-manager"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # 当前请求体（每个请求在 _begin_request() 里重置）
    _body = None

    def log_message(self, fmt, *args):
        message = fmt % args if args else fmt
        if re.match(r'^\S+ "(GET|POST|PUT|DELETE) ', message):
            code = message.split('"')[2].strip().split(" ")[0] if message.count('"') >= 2 else ""
            if not code.startswith(("4", "5")):
                return
        log("%s %s" % (self.address_string(), message))

    # ---------- 基础输出

    def _send(self, code, body, content_type, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _error(self, code, message):
        self._json({"error": message}, code)

    def _read_json(self):
        raw = self._read_body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", "ignore") or "{}")
        except ValueError:
            return {}

    # ---------- 请求体

    def _begin_request(self):
        """每个请求的第一步：把请求体读满。

        protocol_version 是 HTTP/1.1，连接会被复用。只要有一条路径没把
        Content-Length 指定的字节读完，下一个请求的请求行就会从残留字节中间开始解析，
        变成 400 + HTML 错误页（LuCI 的批量 RPC 因此报 “No related RPC reply”）。
        所以无论这条请求是否用得上 body，都要先读完。
        """
        self._body = None
        return self._read_body()

    def _read_body(self):
        if self._body is not None:
            return self._body
        self._body = b""
        encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in encoding:
            self._body = self._read_chunked_body()
            return self._body
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._body
        if length > MAX_BODY:
            log("请求体过大(%d 字节)，丢弃并断开连接" % length)
            self._discard(length)
            self.close_connection = True
            return self._body
        data = self._read_exact(length)
        if data is None:
            self.close_connection = True
            return self._body
        self._body = data
        return self._body

    def _read_exact(self, length):
        data = b""
        while len(data) < length:
            chunk = self.rfile.read(length - len(data))
            if not chunk:
                # 客户端提前断开：已收下的部分不再可信，调用方会断开连接
                return None
            data += chunk
        return data

    def _discard(self, length):
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def _read_chunked_body(self):
        chunks = []
        total = 0
        while True:
            line = self.rfile.readline(1024)
            if not line:
                self.close_connection = True
                return b""
            try:
                size = int(line.split(b";")[0].strip() or b"0", 16)
            except ValueError:
                self.close_connection = True
                return b""
            if size == 0:
                # 吃掉 trailer / 结尾空行
                while True:
                    trailer = self.rfile.readline(1024)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            total += size
            if total > MAX_BODY:
                log("分块请求体过大(>%d 字节)，丢弃并断开连接" % MAX_BODY)
                self.close_connection = True
                return b""
            data = self._read_exact(size)
            if data is None:
                self.close_connection = True
                return b""
            chunks.append(data)
            self.rfile.read(2)  # 每块后面的 CRLF
        return b"".join(chunks)

    # ---------- 路由

    def do_GET(self):
        self._begin_request()
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith(PROXY_PREFIX):
            return self._proxy()
        if path.startswith("/api/"):
            return self._api_get(path)
        return self._serve_static(path)

    def do_POST(self):
        self._begin_request()
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith(PROXY_PREFIX):
            return self._proxy()
        if path == "/api/scan":
            payload = self._read_json()
            cidr = (payload.get("cidr") or "").strip()
            interfaces = list_interfaces()
            gateway = default_gateway()
            if cidr:
                try:
                    ipaddress.IPv4Network(cidr, strict=False)
                except ValueError:
                    return self._error(400, "网段格式不正确，例如 192.168.1.0/24")
                cidrs = [cidr]
            else:
                cidrs = [i["cidr"] for i in interfaces]
            if not cidrs:
                return self._error(400, "未能识别本机局域网网段，请手动填写网段")
            if not STATE.start( cidrs, gateway):
                return self._error(409, "已有扫描任务在进行中")
            threading.Thread(target=run_scan, args=(cidrs, gateway), daemon=True).start()
            return self._json({"ok": True, "cidrs": cidrs})
        if path == "/api/scan/stop":
            with STATE.lock:
                STATE.cancel = True
            return self._json({"ok": True})
        if path == "/api/devices":
            payload = self._read_json()
            try:
                entry, created = add_device(payload.get("name"), payload.get("address"))
            except ValueError as exc:
                return self._error(400, str(exc))
            return self._json({"device": entry, "created": created})
        if path == "/api/probe":
            payload = self._read_json()
            try:
                info = probe_address(payload.get("address"))
            except ValueError as exc:
                return self._error(400, str(exc))
            return self._json({"device": info})
        if path == "/api/ignored":
            payload = self._read_json()
            try:
                ids = ignore_device(payload.get("id"))
            except ValueError as exc:
                return self._error(400, str(exc))
            return self._json({"ids": ids})
        return self._error(404, "接口不存在")

    def do_PUT(self):
        self._begin_request()
        path = urlparse(self.path).path
        if path.startswith(PROXY_PREFIX):
            return self._proxy()
        if path == "/api/devices":
            payload = self._read_json()
            dev_id = payload.get("id")
            name = (payload.get("name") or "").strip()[:40]
            with DEVICES_LOCK:
                devices = load_devices()
                for item in devices:
                    if item.get("id") == dev_id:
                        item["name"] = name or item.get("name")
                        save_devices(devices)
                        return self._json({"device": item})
            return self._error(404, "未找到该地址")
        return self._error(404, "接口不存在")

    def do_DELETE(self):
        self._begin_request()
        parsed = urlparse(self.path)
        if parsed.path.startswith(PROXY_PREFIX):
            return self._proxy()
        if parsed.path == "/api/ignored":
            dev_id = (parse_qs(parsed.query or "").get("id") or [""])[0]
            return self._json({"ids": unignore_device(dev_id)})
        if parsed.path == "/api/devices":
            dev_id = (parse_qs(parsed.query or "").get("id") or [""])[0]
            with DEVICES_LOCK:
                devices = load_devices()
                remain = [d for d in devices if d.get("id") != dev_id]
                if len(remain) == len(devices):
                    return self._error(404, "未找到该地址")
                save_devices(remain)
            return self._json({"ok": True})
        return self._error(404, "接口不存在")

    # ---------- 具体处理

    def _api_get(self, path):
        if path == "/api/config":
            interfaces = list_interfaces()
            gateway = default_gateway()
            return self._json({
                "version": APP_VERSION,
                "port": PORT,
                "interfaces": interfaces,
                "gateway": gateway,
                "default_cidr": interfaces[0]["cidr"] if interfaces else "",
            })
        if path == "/api/devices":
            return self._json({"devices": load_devices()})
        if path == "/api/ignored":
            return self._json({"ids": load_ignored()})
        if path == "/api/proxylog":
            return self._json({"entries": proxy_log_snapshot()})
        if path == "/api/scan/status":
            return self._json(STATE.snapshot())
        return self._error(404, "接口不存在")

    def _serve_static(self, path):
        rel = unquote(path).lstrip("/") or "index.html"
        if rel.endswith("/"):
            rel += "index.html"
        full = os.path.normpath(os.path.join(WWW_DIR, rel))
        if not full.startswith(os.path.normpath(WWW_DIR)):
            return self._error(403, "禁止访问")
        if not os.path.isfile(full):
            if "." not in os.path.basename(rel):
                full = os.path.join(WWW_DIR, "index.html")
            if not os.path.isfile(full):
                return self._error(404, "页面不存在")
        ext = os.path.splitext(full)[1].lower()
        try:
            with open(full, "rb") as fp:
                body = fp.read()
        except OSError:
            return self._error(500, "读取文件失败")
        self._send(200, body, CONTENT_TYPES.get(ext, "application/octet-stream"))

    # ---------- 反向代理

    def _proxy_fail(self, status, reason):
        page = PROXY_ERROR_PAGE % {"reason": reason, "home": "/"}
        self._send(status, page, "text/html; charset=utf-8")

    def _proxy_head(self, status, rheaders, prefix, content_type, length=None, skip_encoding=True):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for key, value in rheaders:
            lower = key.lower()
            if lower in HOP_HEADERS:
                continue
            if lower in ("content-type", "content-length", "set-cookie", "location"):
                continue
            if lower == "content-encoding":
                if skip_encoding:
                    continue
                self.send_header(key, value)
                continue
            # 去掉禁止内嵌的头，否则应用内弹窗（iframe）会被浏览器拦截
            if lower in ("x-frame-options", "content-security-policy", "content-security-policy-report-only"):
                continue
            self.send_header(key, value)
        for key, value in rheaders:
            lower = key.lower()
            if lower == "location":
                self.send_header("Location", rewrite_location(value, prefix))
            elif lower == "set-cookie":
                self.send_header("Set-Cookie", rewrite_cookie(value, prefix))
        if length is None:
            # 流式响应（长轮询 / 事件流）用 chunked，前面的网关才能边收边转
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _proxy(self):
        parsed = urlparse(self.path)
        rest = parsed.path[len(PROXY_PREFIX):]
        scheme, _, rest = rest.partition("/")
        hostport, _, tail = rest.partition("/")
        scheme = scheme.lower()
        if scheme not in ("http", "https") or not hostport:
            return self._proxy_fail(400, "代理地址格式不正确：/proxy/http/192.168.1.1:80/")

        host, _, port_text = hostport.partition(":")
        port = int(port_text) if port_text.isdigit() else (443 if scheme == "https" else 80)
        if not allowed_proxy_host(host):
            return self._proxy_fail(403, "出于安全考虑，只允许中转到局域网私有地址")

        prefix = proxy_base(scheme, host, port)
        # 若应用被网关挂在子路径下（如 /app/xxx/），改写出的绝对路径也要带上前缀
        base = ""
        referer = self.headers.get("Referer") or ""
        if referer:
            ref = urlsplit(referer)
            same_host = (ref.netloc or "") == (self.headers.get("Host") or "")
            ref_path = ref.path or ""
            if same_host:
                idx = ref_path.find(PROXY_PREFIX)
                if idx > 0:
                    base = ref_path[:idx]
                elif idx < 0 and ref_path:
                    base = ref_path.rstrip("/")
                    if base.endswith("/index.html"):
                        base = base[: -len("/index.html")]
        if base and not base.startswith("/"):
            base = ""
        prefix = base + prefix

        target_path = "/" + tail
        if parsed.query:
            target_path += "?" + parsed.query

        started = time.time()
        # WebSocket（部分 LuCI 页面的 ubus 订阅走 ws），直接做字节隧道
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            proxy_log("WS", self.path, 101, 0)
            return self._proxy_websocket(host, port, scheme, hostport, target_path, prefix)

        body = self._read_body() or None

        headers = {}
        for key, value in self.headers.items():
            if key.lower() in HOP_HEADERS:
                continue
            if key.lower() in ("referer", "origin"):
                continue
            headers[key] = value
        headers["Host"] = hostport
        headers["Accept-Encoding"] = "identity"
        # 部分路由器会校验来源，统一改成指向目标自身
        headers["Referer"] = "%s://%s%s" % (scheme, hostport, target_path)
        headers["Origin"] = "%s://%s" % (scheme, hostport)

        conn = None
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=PROXY_TIMEOUT, context=SSL_CTX)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=PROXY_TIMEOUT)
            conn.request(self.command, target_path, body=body, headers=headers)
            resp = conn.getresponse()
        except Exception as exc:  # noqa: BLE001
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            log("代理失败 %s %s%s -> %s:%d (%r)" % (self.command, prefix, target_path, host, port, exc))
            proxy_log(self.command, self.path, "ERR", time.time() - started, str(exc))
            return self._proxy_fail(502, "连接 %s:%d 失败（%s）" % (host, port, exc))

        status = resp.status
        rheaders = resp.getheaders()
        content_type = resp.getheader("Content-Type") or ""
        encoding = (resp.getheader("Content-Encoding") or "").lower()
        proxy_log(self.command, self.path, status, time.time() - started,
                  (content_type.split(";")[0] or "")[:32])
        lower_type = content_type.lower()
        rewrite_kind = ""
        if "text/html" in lower_type:
            rewrite_kind = "html"
        elif "text/css" in lower_type:
            rewrite_kind = "css"
        elif "javascript" in lower_type or "ecmascript" in lower_type:
            rewrite_kind = "js"

        if os.environ.get("APP_PROXY_DEBUG") == "1":
            log("代理 %s %s%s -> %d %s" % (self.command, prefix, target_path, status, content_type))

        try:
            if rewrite_kind:
                raw = resp.read()
                if encoding:
                    raw = decompress_body(raw, encoding)
                charset = charset_of(content_type)
                if rewrite_kind == "html":
                    raw = rewrite_html(raw.decode(charset, "replace"), prefix).encode(charset, "replace")
                    content_type = "text/html; charset=%s" % charset
                elif rewrite_kind == "css":
                    raw = rewrite_css(raw.decode(charset, "replace"), prefix).encode(charset, "replace")
                    content_type = "text/css; charset=%s" % charset
                else:
                    raw = rewrite_js(raw.decode(charset, "replace"), prefix).encode(charset, "replace")
                    content_type = "application/javascript; charset=%s" % charset
                self._proxy_head(status, rheaders, prefix, content_type, len(raw))
                self.wfile.write(raw)
            elif self.command == "HEAD" or status in (204, 304):
                self._proxy_head(status, rheaders, prefix, content_type, 0, skip_encoding=not encoding)
            else:
                # JSON / 图片 / 长轮询等：边读边写，避免上游长时间不结束时整体超时
                self._proxy_head(status, rheaders, prefix, content_type, None, skip_encoding=not encoding)
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(("%x\r\n" % len(chunk)).encode("ascii") + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
        except Exception as exc:  # noqa: BLE001
            log("代理传输中断 %s%s (%r)" % (prefix, target_path, exc))
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _proxy_websocket(self, host, port, scheme, hostport, target_path, prefix):
        upstream = None
        try:
            upstream = socket.create_connection((host, port), timeout=PROXY_TIMEOUT)
            if scheme == "https":
                upstream = SSL_CTX.wrap_socket(upstream, server_hostname=host)
            lines = [
                "GET %s HTTP/1.1" % target_path,
                "Host: %s" % hostport,
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Sec-WebSocket-Key: %s" % (self.headers.get("Sec-WebSocket-Key") or ""),
                "Sec-WebSocket-Version: %s" % (self.headers.get("Sec-WebSocket-Version") or "13"),
            ]
            for name in ("Cookie", "Origin", "User-Agent", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"):
                value = self.headers.get(name)
                if value:
                    lines.append("%s: %s" % (name, value))
            upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))

            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = upstream.recv(4096)
                if not chunk:
                    raise IOError("上游关闭连接")
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            self.wfile.write(head + b"\r\n\r\n" + rest)
            self.wfile.flush()
            if b" 101 " not in head.split(b"\r\n")[0]:
                log("代理 WebSocket 升级被拒绝: %r" % head.split(b"\r\n")[0])
                return
            self.close_connection = True
            while True:
                readable, _, _ = select.select([self.connection, upstream], [], [], 120)
                if not readable:
                    continue
                if self.connection in readable:
                    data = self.connection.recv(65536)
                    if not data:
                        break
                    upstream.sendall(data)
                if upstream in readable:
                    data = upstream.recv(65536)
                    if not data:
                        break
                    self.wfile.write(data)
                    self.wfile.flush()
        except Exception as exc:  # noqa: BLE001
            log("代理 WebSocket 失败 %s%s (%r)" % (prefix, target_path, exc))
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # 路由器页面会瞬间并发几十个请求，默认 backlog=5 容易被拒，调大
    request_queue_size = 256


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    server = AppServer(("0.0.0.0", PORT), Handler)
    log("服务启动 http://0.0.0.0:%d www=%s data=%s" % (PORT, WWW_DIR, DATA_DIR))

    def shutdown(signum, _frame):
        log("收到信号 %s，准备退出" % signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, shutdown)
        except Exception:
            pass

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log("服务已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
