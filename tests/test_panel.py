#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""面板（弹窗第一屏）后端测试：LuCI 登录 → ubus 取数 → 聚合 → 中转带登录态。

假 LuCI 路由器模拟真实链路，数据源与 iStore 项目一致：
  1. POST /cgi-bin/luci/                表单登录 → 302 + Set-Cookie(sysauth) + Location(;stok=…)
  2. GET  /cgi-bin/luci/                页面里带 "sessionid":"<32 hex>"
  3. GET  /cgi-bin/luci/admin/status/overview   侧边栏菜单（tiles 来源）
  4. POST /ubus                         JSON-RPC：
       system board/info（load 为 65536 定点数）、network.interface dump、
       luci-rpc getNetworkDevices/getDHCPLeases/getWirelessDevices、
       luci getMountPoints/getBlockDevices/getProcessList/getConntrackList
  5. GET  /cgi-bin/luci/istore/system/status/   非 iStoreOS → 404
  6. GET  /cgi-bin/luci/admin/...       tile 探测（200 存在 / 404 未安装）

运行：python -m unittest discover -s tests -v
"""

import http.client
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PY = os.path.join(ROOT, "app", "server", "app.py")
WWW_DIR = os.path.join(ROOT, "app", "www")

SID = "0123456789abcdef0123456789abcdef"
PASSWORD = "s3cret"

MENU_HTML = """<!DOCTYPE html><html><head>
<script>L.env = {"sessionid":"%s","token":"t"};</script>
</head><body>
<div class="main menu">
<ul>
  <li><a href="/cgi-bin/luci/admin/status/overview">状态总览</a></li>
  <li><a href="/cgi-bin/luci/admin/network/network">网络</a></li>
  <li><a href="/cgi-bin/luci/admin/network/wireless">无线</a></li>
  <li><a href="/cgi-bin/luci/admin/network/firewall">防火墙</a></li>
  <li><a href="/cgi-bin/luci/admin/status/logs">系统日志</a></li>
  <li><a href="/cgi-bin/luci/admin/system/admin">管理权</a></li>
  <li><a href="/cgi-bin/luci/admin/store/">iStore 商店</a></li>
  <li><a href="/cgi-bin/luci/admin/docker/">Docker</a></li>
  <li><a href="/cgi-bin/luci/admin/quickstart">首页</a></li>
  <li><a href="/cgi-bin/luci/admin/linkease_status">linkease_status</a></li>
  <li><a href="/cgi-bin/luci/admin/file">file</a></li>
  <li><a href="/cgi-bin/luci/admin/logout">退出</a></li>
</ul>
</div>
</body></html>""" % SID


class FakeRouter(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    rx_bytes = 1000000
    tx_bytes = 500000
    cookies_seen = []

    def log_message(self, *args):
        pass

    # ---------- 工具

    def _send(self, code, body, content_type="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            if isinstance(value, (list, tuple)):
                for item in value:
                    self.send_header(key, item)
            else:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), "application/json")

    # ---------- 路由

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if self.path.startswith("/cgi-bin/luci/") and "ubus" not in self.path:
            form = body.decode("utf-8", "ignore")
            if "luci_password=" + PASSWORD not in form:
                self._send(302, "", extra={"Location": "/cgi-bin/luci/"})
                return
            # 真实固件可能同时下发多个 sysauth* cookie，两个都要带上
            # 真实固件可能一次下发多个 sysauth* cookie，客户端要把它们都带上
            self._send(302, "", extra={
                "Set-Cookie": ["sysauth_http=deadbeefcafe; path=/cgi-bin/luci",
                               "sysauth_extra=cafebabe; path=/cgi-bin/luci"],
                "Location": "/cgi-bin/luci/;stok=deadbeef/admin/status/overview",
            })
            return

        if self.path.startswith("/ubus") or "admin/ubus" in self.path:
            type(self).cookies_seen.append(self.headers.get("Cookie") or "")
            try:
                payload = json.loads(body.decode("utf-8"))
            except ValueError:
                self._json({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse error"}})
                return
            sid, obj, method = payload["params"][0], payload["params"][1], payload["params"][2]
            if sid != SID:
                self._json({"jsonrpc": "2.0", "id": 1,
                            "error": {"code": -32002, "message": "session invalid"}})
                return
            data = self._ubus(obj, method)
            if data is None:
                self._json({"jsonrpc": "2.0", "id": 1, "result": [4, "denied"]})
                return
            self._json({"jsonrpc": "2.0", "id": 1, "result": [0, data]})
            return

        self._send(404, "nope")

    def do_GET(self):
        path = self.path.split("?")[0]
        type(self).cookies_seen.append(self.headers.get("Cookie") or "")
        if path in ("/cgi-bin/luci/", "/cgi-bin/luci/admin/status/overview"):
            self._send(200, MENU_HTML)
            return
        if path.startswith("/cgi-bin/luci/admin/"):
            if path in ("/cgi-bin/luci/admin/network/network",
                        "/cgi-bin/luci/admin/network/wireless",
                        "/cgi-bin/luci/admin/quickstart"):
                self._send(200, "<html>ok</html>")
            else:
                self._send(404, "<html>404</html>")
            return
        self._send(404, "nope")

    # ---------- ubus 数据

    def _ubus(self, obj, method):
        if (obj, method) == ("system", "board"):
            return {"model": "MiaoYi R3", "cpu": "ARMv8 Processor rev 4",
                    "release": {"description": "ImmortalWrt 25.12-SNAPSHOT", "distribution": "ImmortalWrt"}}
        if (obj, method) == ("system", "info"):
            return {"uptime": 190000, "kernelversion": "6.6.0",
                    # ubus 的 load 是 65536 倍定点数：2816/65536=0.04，4192/65536=0.06
                    "load": [2816, 2560, 4192],
                    "memory": {"total": 1073741824, "free": 400000000, "available": 787000000},
                    "root": {"total": 7340032000, "used": 2055208960, "free": 5284823040}}
        if (obj, method) == ("network.interface", "dump"):
            return {"interface": [{
                "interface": "wan", "up": True, "proto": "dhcp", "l3_device": "wan",
                "ipv4-address": [{"address": "192.168.1.2", "mask": 24}],
                # 故意全 0：证明速率不再依赖接口统计
                "statistics": {"rx_bytes": 0, "tx_bytes": 0},
            }]}
        if (obj, method) == ("luci-rpc", "getNetworkDevices"):
            return {
                "wan": {"up": True, "stats": {"rx_bytes": type(self).rx_bytes,
                                              "tx_bytes": type(self).tx_bytes}},
                "br-lan": {"up": True, "stats": {"rx_bytes": 999999, "tx_bytes": 999999}},
                "lo": {"up": True, "stats": {"rx_bytes": 5, "tx_bytes": 5}},
            }
        if (obj, method) == ("luci-rpc", "getDHCPLeases"):
            return {"dhcp_leases": [
                {"macaddr": "aa:bb:cc:dd:ee:ff", "ipaddr": "192.168.1.50", "hostname": "phone", "expires": 3600},
                {"macaddr": "11:22:33:44:55:66", "ipaddr": "192.168.1.51", "hostname": "tv", "expires": 7200},
            ]}
        if (obj, method) == ("luci-rpc", "getWirelessDevices"):
            return {"radio0": {"interfaces": [{"ifname": "wlan0",
                                               "assoclist": [{"mac": "aa"}, {"mac": "bb"}]}]}}
        if (obj, method) == ("luci", "getMountPoints"):
            return {"result": [
                {"device": "/dev/mtdblock5", "mount": "/overlay", "size": 104857600,
                 "free": 73400320, "avail": 73400320},
                {"device": "tmpfs", "mount": "/tmp", "size": 1048576, "free": 524288, "avail": 524288},
            ]}
        if (obj, method) == ("luci", "getBlockDevices"):
            return {"mtdblock5": {"dev": "/dev/mtdblock5", "type": "jffs2"}}
        if (obj, method) == ("luci", "getProcessList"):
            return {"result": [{"%CPU": "7%"}, {"%CPU": "5.5%"}, {"%CPU": "0%"}]}
        if (obj, method) == ("luci", "getConntrackList"):
            return {"result": [{"src": "1.1.1.1"} for _ in range(7)]}
        if (obj, method) == ("file", "read"):
            return None  # ACL 拒绝：温度/频率取不到，面板显示 --
        return None


def load_app_module(data_dir):
    os.environ["APP_WWW_DIR"] = WWW_DIR
    os.environ["APP_DATA_DIR"] = data_dir
    os.environ.setdefault("APP_PORT", "0")
    spec = importlib.util.spec_from_file_location("fn_openwrt_app_panel", SERVER_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules["fn_openwrt_app_panel"] = module
    spec.loader.exec_module(module)
    return module


class PanelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="fn-owrt-panel-")
        cls.app = load_app_module(cls.data_dir)

        cls.router = ThreadingHTTPServer(("127.0.0.1", 0), FakeRouter)
        cls.router.daemon_threads = True
        threading.Thread(target=cls.router.serve_forever, daemon=True).start()
        cls.router_port = cls.router.server_address[1]
        cls.dev_id = "127.0.0.1:%d" % cls.router_port

        cls.server = cls.app.AppServer(("127.0.0.1", 0), cls.app.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.router.shutdown()
        cls.router.server_close()
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    # ---------- 工具

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            headers = {"Content-Type": "application/json"} if body is not None else {}
            payload = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, (json.loads(raw.decode("utf-8")) if raw else {})
        finally:
            conn.close()

    def login(self, password=PASSWORD):
        return self.call("POST", "/api/router/login",
                         {"id": self.dev_id, "username": "root", "password": password})

    def dashboard(self):
        self.app.DASH_CACHE.clear()
        return self.call("GET", "/api/router/dashboard?id=" + self.dev_id)[1]

    # ---------- 用例

    def test_01_wrong_password_is_rejected(self):
        status, data = self.login("wrong-one")
        self.assertEqual(status, 400)
        self.assertIn("登录路由器失败", data.get("error", ""))
        self.assertEqual(self.app.credentials_status(), {})

    def test_02_dashboard_values_are_accurate(self):
        status, data = self.login()
        self.assertEqual(status, 200, data)
        dash = self.dashboard()
        self.assertTrue(dash["authed"], dash)

        # 负载：ubus 定点数 65536 → 0.04 / 0.04 / 0.06
        self.assertEqual(dash["system"]["load"], [0.04, 0.04, 0.06])
        self.assertEqual(dash["system"]["uptime"], 190000)
        # CPU 使用率来自 luci getProcessList 求和
        self.assertEqual(dash["cpu"]["usage"], 12.5)
        self.assertIsNone(dash["cpu"]["temp"])
        self.assertIsNone(dash["cpu"]["freq"])
        # 内存
        self.assertGreater(dash["memory"]["pct"], 20)
        self.assertLess(dash["memory"]["pct"], 30)
        # 存储：只算 /dev/*，tmpfs 被过滤
        self.assertEqual(len(dash["disks"]), 1)
        self.assertEqual(dash["disks"][0]["mount"], "/overlay")
        self.assertEqual(dash["disks"][0]["fs"], "jffs2")
        self.assertEqual(dash["disks"][0]["pct"], 30.0)
        # 在线设备：DHCP 2 + 无线 2 + 连接数 7
        self.assertEqual(dash["clients"], {"dhcp": 2, "wireless": 2, "conntrack": 7})
        self.assertEqual(dash["wan"]["iface"], "wan")
        self.assertEqual(dash["wan"]["ip"], "192.168.1.2")
        self.assertTrue(dash["wan"]["up"])
        # tiles 来自路由器自己的菜单，退出被过滤
        labels = [t["label"] for t in dash["tiles"]]
        self.assertIn("状态总览", labels)
        self.assertIn("网络", labels)
        self.assertNotIn("退出", labels)
        self.assertEqual(dash["tiles"][0]["path"], "/cgi-bin/luci/admin/status/overview")
        self.assertEqual(dash["tiles"][0]["icon"], "grid")
        self.assertIn("首页", labels)
        # 应用与文件：在菜单里找到 iStore / Docker，没有文件管理就不出现
        app_ids = [a["id"] for a in dash["apps"]]
        self.assertEqual(app_ids, ["istore", "docker"])

    def test_03_rate_uses_device_counters(self):
        self.login()
        self.app.RATE_STATE.pop(self.dev_id, None)
        self.dashboard()
        fake = self.router.RequestHandlerClass
        fake.rx_bytes += 20480          # 20 KB
        fake.tx_bytes += 10240          # 10 KB
        time.sleep(1.2)
        dash = self.dashboard()
        self.assertIsNotNone(dash["rate"], "第二次取样应算出速率")
        self.assertGreater(dash["rate"]["down"], 1024)
        self.assertGreater(dash["rate"]["up"], 512)
        self.assertGreaterEqual(len(dash["history"]), 1)

    def test_04_credentials_are_stored_private(self):
        self.login()
        status, data = self.call("GET", "/api/router/auth")
        self.assertEqual(status, 200)
        entry = data["devices"][self.dev_id]
        self.assertEqual(entry["username"], "root")
        self.assertTrue(entry["has_password"])
        self.assertNotIn("password", entry)
        if os.name != "nt":   # Windows 上 chmod 是空操作，权限检查只在 POSIX 上做
            mode = oct(os.stat(self.app.ROUTERS_FILE).st_mode & 0o777)
            self.assertEqual(mode, "0o600")

    def test_05_proxy_attaches_saved_login(self):
        self.login()
        FakeRouter.cookies_seen = []
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request("GET", "/proxy/http/127.0.0.1:%d/cgi-bin/luci/" % self.router_port)
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 200)
        finally:
            conn.close()
        self.assertTrue(FakeRouter.cookies_seen, "中转请求应带上登录 cookie")
        self.assertIn("sysauth_http=deadbeefcafe", FakeRouter.cookies_seen[-1])

    def test_05b_all_sysauth_cookies_are_sent(self):
        """登录后要把收集到的 sysauth* cookie 一起发（掉一个就可能拿到登录页）。"""
        self.login()
        FakeRouter.cookies_seen = []
        self.dashboard()
        joined = " ".join(FakeRouter.cookies_seen)
        self.assertIn("sysauth_http=deadbeefcafe", joined)
        self.assertIn("sysauth_extra=cafebabe", joined)

    def test_06_menu_parsing_is_tolerant(self):
        """单引号、/;stok=/ 前缀、相对路径都要认出来；退出/非路由器链接要过滤。"""
        html = """
        <a href='/cgi-bin/luci/;stok=abc123/admin/network/network'><span>网络</span></a>
        <a href="/cgi-bin/luci/admin/status/overview?x=1">状态总览</a>
        <a href=admin/system/system>系统</a>
        <a href="/cgi-bin/luci/admin/logout">退出</a>
        <a href="/cgi-bin/luci/admin/translations">语言</a>
        <a href="https://example.com/foo">外链</a>
        """
        items = self.app.parse_menu(html)
        self.assertEqual([i["path"] for i in items], [
            "/cgi-bin/luci/admin/network/network",
            "/cgi-bin/luci/admin/status/overview",
            "/cgi-bin/luci/admin/system/system",
        ])
        self.assertEqual([i["label"] for i in items], ["网络", "状态总览", "系统"])

    def test_06b_unprefixed_luci_path_is_routed_back_to_router(self):
        """中转页面里用绝对路径跳转会漏掉 /proxy/ 前缀，服务端要按 Referer 接回路由器。"""
        self.login()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            referer = "http://127.0.0.1:%d/proxy/http/127.0.0.1:%d/cgi-bin/luci/" % (self.port, self.router_port)
            conn.request("GET", "/cgi-bin/luci/admin/status/overview", headers={"Referer": referer})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            self.assertEqual(resp.status, 200)
            # 必须拿到路由器页面（菜单 HTML），而不是我们自己的 index.html
            self.assertIn("L.env", body)
            self.assertNotIn("局域网路由管理", body)
        finally:
            conn.close()

    def test_06b2_unprefixed_path_recovered_by_cookie(self):
        """没有 Referer（Referrer-Policy 被上游设成 no-referrer）时，靠中转时种下的 cookie 接回。"""
        self.login()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request("GET", "/cgi-bin/luci/",
                         headers={"Cookie": "fn_proxy_target=http:127.0.0.1:%d" % self.router_port})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            self.assertEqual(resp.status, 200)
            self.assertIn("L.env", body)          # 路由器的页面
            self.assertNotIn("局域网路由管理", body)
        finally:
            conn.close()

    def test_06b3_proxy_sets_target_cookie(self):
        """中转响应要种 fn_proxy_target，供漏前缀的请求接回。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request("GET", "/proxy/http/127.0.0.1:%d/cgi-bin/luci/" % self.router_port)
            resp = conn.getresponse()
            resp.read()
            cookies = resp.headers.get_all("Set-Cookie") or []
        finally:
            conn.close()
        joined = " ".join(cookies)
        self.assertIn("fn_proxy_target=http:127.0.0.1:%d" % self.router_port, joined)

    def test_06c_unprefixed_path_without_referer_stays_local(self):
        """没有 Referer / 非私有地址时不做接回（避免变成任意代理跳板）。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request("GET", "/cgi-bin/luci/admin/status/overview")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            self.assertEqual(resp.status, 200)
            self.assertIn("局域网路由管理", body)   # 仍然是我们自己的页面
        finally:
            conn.close()

    def test_06d_dashboard_reports_home_path(self):
        """首页路径来自菜单里的「首页」，不能用 `/`（中文 LuCI 会重定向到状态概览）。"""
        self.login()
        dash = self.dashboard()
        self.assertEqual(dash["home"]["path"], "/cgi-bin/luci/admin/quickstart")
        self.assertEqual(dash["home"]["label"], "首页")

    def test_06e_menu_tiles_merge_with_common_entries(self):
        """菜单只认出几项（还夹杂 linkease_status / file 这种）时，要用常用入口补齐。"""
        self.login()
        dash = self.dashboard()
        paths = [t["path"] for t in dash["tiles"]]
        # 代码味标签被过滤
        self.assertNotIn("linkease_status", [t["label"] for t in dash["tiles"]])
        self.assertNotIn("/cgi-bin/luci/admin/file", paths)
        # 菜单里的真实项保留
        self.assertIn("/cgi-bin/luci/admin/network/network", paths)
        # 常用入口补齐（防火墙 mock 里没有）
        self.assertIn("/cgi-bin/luci/admin/network/firewall", paths)
        self.assertIn("/cgi-bin/luci/admin/system/system", paths)
        self.assertIn(dash["menu"]["source"], ("menu", "mixed"))

    def test_07_viewer_has_openwrt_home_button(self):
        """弹窗顶部要有「OpenWrt 首页」按钮，且指向 LuCI 原生首页。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            html = resp.read().decode("utf-8")
        finally:
            conn.close()
        self.assertIn('id="viewer-owrt"', html)
        self.assertIn("OpenWrt 首页", html)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/app.js")
            resp = conn.getresponse()
            js = resp.read().decode("utf-8")
        finally:
            conn.close()
        self.assertIn("/cgi-bin/luci/admin/status/overview", js)
        self.assertIn("viewer-owrt", js)

    def test_08_fallback_tiles_exist_when_no_menu(self):
        """解析不到菜单时要有兜底入口，不能让面板只剩状态卡。"""
        self.assertEqual(self.app.parse_menu("<html><body>登录</body></html>"), [])
        tiles = self.app.fallback_tiles()
        apps = self.app.fallback_apps()
        self.assertGreaterEqual(len(tiles), 8)
        self.assertGreaterEqual(len(apps), 2)
        self.assertTrue(all(t["path"].startswith("/cgi-bin/luci/") for t in tiles))

    def test_09_clear_credentials(self):
        self.login()
        status, _data = self.call("DELETE", "/api/router/login?id=" + self.dev_id)
        self.assertEqual(status, 200)
        self.assertNotIn(self.dev_id, self.app.credentials_status())
        dash = self.dashboard()
        self.assertFalse(dash["authed"])
        self.assertIn("账号密码", dash["error"])
        self.assertEqual(dash["tiles"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
