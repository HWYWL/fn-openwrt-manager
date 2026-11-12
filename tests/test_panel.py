#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""面板（弹窗第一屏）后端测试：LuCI 登录 → ubus 取数 → 聚合 → 中转带登录态。

用一个假 LuCI 路由器模拟真实的四个环节：
  1. POST /cgi-bin/luci/   表单登录 → 302 + Set-Cookie(sysauth) + Location(;stok=…)
  2. GET  /cgi-bin/luci/   页面里带 "sessionid":"<32 hex>"
  3. POST /ubus            JSON-RPC，按 params[1]/[2] 返回 system board/info 等
  4. GET  /cgi-bin/luci/admin/...  探测 tile 是否存在（200 存在 / 404 未安装）

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


class FakeRouter(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    rx_bytes = 1000
    tx_bytes = 500
    cookies_seen = []
    logins = 0

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
            type(self).logins += 1
            if "luci_password=" + PASSWORD not in form:
                self._send(302, "", extra={"Location": "/cgi-bin/luci/"})
                return
            self._send(302, "", extra={
                "Set-Cookie": "sysauth_http=deadbeefcafe; path=/cgi-bin/luci",
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
            self._json({"jsonrpc": "2.0", "id": 1, "result": [0, data] if data is not None else [4, "denied"]})
            return

        self._send(404, "nope")

    def do_GET(self):
        path = self.path.split("?")[0]
        type(self).cookies_seen.append(self.headers.get("Cookie") or "")
        if path in ("/cgi-bin/luci/", "/cgi-bin/luci/admin/status/overview"):
            self._send(200, '<html><head><script>L.env = {"sessionid":"%s","token":"t"};</script>'
                            '</head><body>LuCI</body></html>' % SID)
            return
        if path.startswith("/cgi-bin/luci/admin/"):
            # 只有状态总览与网络管理"装了"，其它 404
            if path in ("/cgi-bin/luci/admin/status/overview",
                        "/cgi-bin/luci/admin/network/network"):
                self._send(200, "<html>ok</html>")
            else:
                self._send(404, "<html>404</html>")
            return
        self._send(404, "nope")

    # ---------- ubus 数据

    def _ubus(self, obj, method):
        if (obj, method) == ("system", "board"):
            return {"model": "MT7986A", "system": "MediaTek MT7986A",
                    "release": {"description": "ImmortalWrt 24.10", "distribution": "ImmortalWrt"}}
        if (obj, method) == ("system", "info"):
            return {"uptime": 190000, "kernelversion": "6.6.0",
                    "load": [0.12, 0.18, 0.2],
                    "memory": {"total": 1073741824, "free": 400000000, "available": 787000000},
                    "root": {"total": 7340032000, "used": 2055208960, "free": 5284823040}}
        if (obj, method) == ("network.interface", "dump"):
            return {"interface": [{
                "interface": "wan", "up": True, "proto": "pppoe", "l3_device": "pppoe-wan",
                "ipv4-address": [{"address": "1.2.3.4", "mask": 32}],
                "statistics": {"rx_bytes": type(self).rx_bytes, "tx_bytes": type(self).tx_bytes},
            }]}
        if (obj, method) == ("dhcp", "ipv4leases"):
            return {"device": {}, "leases": {"aa:bb:cc:dd:ee:ff": {"ip": "192.168.200.50"},
                                             "11:22:33:44:55:66": {"ip": "192.168.200.51"}}}
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
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
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

    # ---------- 用例

    def test_01_wrong_password_is_rejected(self):
        status, data = self.login("wrong-one")
        self.assertEqual(status, 400)
        self.assertIn("登录路由器失败", data.get("error", ""))
        self.assertEqual(self.app.credentials_status(), {})

    def test_02_login_and_dashboard(self):
        status, data = self.login()
        self.assertEqual(status, 200, data)
        self.assertTrue(data.get("authed"))

        self.app.DASH_CACHE.clear()
        status, dash = self.call("GET", "/api/router/dashboard?id=" + self.dev_id)
        self.assertEqual(status, 200, dash)
        self.assertTrue(dash["authed"], dash)
        self.assertEqual(dash["board"]["firmware"], "ImmortalWrt 24.10")
        self.assertEqual(dash["system"]["uptime"], 190000)
        self.assertEqual(dash["system"]["load"], [0.12, 0.18, 0.2])
        self.assertGreater(dash["memory"]["pct"], 20)
        self.assertLess(dash["memory"]["pct"], 30)
        self.assertEqual(dash["wan"]["iface"], "pppoe-wan")
        self.assertEqual(dash["wan"]["ip"], "1.2.3.4")
        self.assertTrue(dash["wan"]["up"])
        self.assertEqual(dash["clients"]["dhcp"], 2)
        self.assertIsNone(dash["cpu"]["temp"])
        # tile 可用性来自真实探测
        tiles = {t["id"]: t["available"] for t in dash["tiles"]}
        self.assertTrue(tiles["overview"])
        self.assertTrue(tiles["network"])
        self.assertFalse(tiles["firewall"])
        apps = {a["id"]: a["available"] for a in dash["apps"]}
        self.assertTrue(all(v is False for v in apps.values()), apps)

    def test_03_rate_and_history(self):
        self.login()
        self.app.DASH_CACHE.clear()
        self.app.RATE_STATE.pop(self.dev_id, None)
        self.call("GET", "/api/router/dashboard?id=" + self.dev_id)
        fake = self.router.RequestHandlerClass
        fake.rx_bytes += 20480          # 20 KB
        fake.tx_bytes += 10240          # 10 KB
        time.sleep(1.2)
        self.app.DASH_CACHE.clear()
        status, dash = self.call("GET", "/api/router/dashboard?id=" + self.dev_id)
        self.assertEqual(status, 200)
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

    def test_06_clear_credentials(self):
        self.login()
        status, _data = self.call("DELETE", "/api/router/login?id=" + self.dev_id)
        self.assertEqual(status, 200)
        self.assertNotIn(self.dev_id, self.app.credentials_status())
        self.app.DASH_CACHE.clear()
        status, dash = self.call("GET", "/api/router/dashboard?id=" + self.dev_id)
        self.assertEqual(status, 200)
        self.assertFalse(dash["authed"])
        self.assertIn("账号密码", dash["error"])
        # 未登录也要给出 tiles（前端才能渲染入口）
        self.assertTrue(dash["tiles"])
        self.assertTrue(all(t["available"] is None for t in dash["tiles"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
