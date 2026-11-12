#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中转发帧与路径改写的回归测试（标准库 unittest）。

覆盖两个真实发生过的 bug：

1. 未命中路由的 POST 没有读掉请求体，keep-alive 连接上残留字节让**下一个**请求
   被解析成 `400 Bad request syntax` + HTML。LuCI 的批量 RPC 因此解析不出 JSON 数组，
   页面报 `Error: No related RPC reply`。
2. LuCI 会把 RPC 地址展开成 `http://<NAS>:8199/ubus/`（绝对地址，没有 /proxy/ 前缀），
   注入脚本必须把它改回中转路径。

运行：python -m unittest discover -s tests -v
"""

import http.client
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PY = os.path.join(ROOT, "app", "server", "app.py")
WWW_DIR = os.path.join(ROOT, "app", "www")

# ---------------------------------------------------------------- 模拟路由器

MOCK_HTML = """<!DOCTYPE html><html><head><title>LuCI</title>
<script src="/luci-static/resources/luci.js"></script></head>
<body><a href="/cgi-bin/luci/admin/status">status</a>
<img src="/luci-static/logo.png"><style>x{background:url(/luci-static/bg.png)}</style>
</body></html>"""


class MockRouter(BaseHTTPRequestHandler):
    """假路由器：/ubus 返回 JSON-RPC 数组，其余 POST 回显收到的 body。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, MOCK_HTML, "text/html; charset=utf-8")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if "/ubus" in self.path:
            # rpcd 的批量回复：一个请求对应一个回复，位置对齐
            calls = json.loads(body.decode("utf-8"))
            replies = [{"jsonrpc": "2.0", "id": item.get("id"), "result": [0, {}]} for item in calls]
            self._send(200, json.dumps(replies), "application/json")
            return
        self._send(200, json.dumps({
            "path": self.path,
            "body": body.decode("utf-8", "replace"),
            "length": length,
            "content_type": self.headers.get("Content-Type") or "",
            "accept_encoding": self.headers.get("Accept-Encoding") or "",
        }), "application/json")


# ---------------------------------------------------------------- 被测服务

def load_app_module():
    tmp = tempfile.mkdtemp(prefix="fn-owrt-test-")
    os.environ.setdefault("APP_PORT", "0")
    os.environ["APP_WWW_DIR"] = WWW_DIR
    os.environ["APP_DATA_DIR"] = tmp
    spec = importlib.util.spec_from_file_location("fn_openwrt_app", SERVER_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules["fn_openwrt_app"] = module
    spec.loader.exec_module(module)
    return module, tmp


class ProxyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, cls.data_dir = load_app_module()
        cls.mock = ThreadingHTTPServer(("127.0.0.1", 0), MockRouter)
        cls.mock.daemon_threads = True
        threading.Thread(target=cls.mock.serve_forever, daemon=True).start()
        cls.mock_port = cls.mock.server_address[1]

        cls.server = cls.app.AppServer(("127.0.0.1", 0), cls.app.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.mock.shutdown()
        cls.mock.server_close()
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    # ---------- 工具

    def proxy_path(self, path="/"):
        return "/proxy/http/127.0.0.1:%d%s" % (self.mock_port, path)

    def request(self, conn, method, path, body=None, headers=None):
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        payload = resp.read()
        return resp, payload

    # ---------- 用例：keep-alive 分帧

    def test_unknown_post_does_not_break_next_request(self):
        """未命中路由的 POST 之后，同一条连接上的下一个请求必须还能正常处理。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            probe = json.dumps({"jsonrpc": "2.0", "id": "init", "method": "list"}).encode()
            resp, payload = self.request(
                conn, "POST", "/ubus/?1699999999", probe,
                {"Content-Type": "application/json"},
            )
            self.assertEqual(resp.status, 404)
            self.assertIn("error", json.loads(payload.decode("utf-8")))

            calls = json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "call",
                                 "params": ["sid", "session", "login", {}]}]).encode()
            resp2, payload2 = self.request(
                conn, "POST", self.proxy_path("/cgi-bin/luci/admin/ubus?1700000000"), calls,
                {"Content-Type": "application/json"},
            )
            # 修复前：400 + HTML 错误页（残留 body 被当成请求行）
            self.assertEqual(resp2.status, 200, payload2[:200])
            self.assertIn("application/json", resp2.getheader("Content-Type") or "")
            replies = json.loads(payload2.decode("utf-8"))
            self.assertIsInstance(replies, list)
            self.assertEqual(len(replies), 1)
        finally:
            conn.close()

    def test_unknown_post_keeps_connection_alive(self):
        """404 不应提前关闭连接（否则浏览器要重开连接，掩盖问题）。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            resp, _ = self.request(
                conn, "POST", "/ubus/?1", b"{}", {"Content-Type": "application/json"},
            )
            self.assertEqual(resp.status, 404)
            self.assertNotEqual((resp.getheader("Connection") or "").lower(), "close")
        finally:
            conn.close()

    def test_unknown_get_does_not_break_next_request(self):
        """GET 路径也保持分帧正确（无 body 时不应阻塞或错位）。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            resp, _ = self.request(conn, "GET", "/ubus/")
            self.assertIn(resp.status, (200, 404))
            resp2, payload2 = self.request(conn, "GET", "/api/config")
            self.assertEqual(resp2.status, 200)
            self.assertIn("interfaces", json.loads(payload2.decode("utf-8")))
        finally:
            conn.close()

    # ---------- 用例：中转本身

    def test_proxied_batch_reaches_router_intact(self):
        """中转批量 RPC：body 原样到上游，回复原样回浏览器。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            calls = [
                {"jsonrpc": "2.0", "id": 1, "method": "call", "params": ["sid", "system", "info", {}]},
                {"jsonrpc": "2.0", "id": 2, "method": "call", "params": ["sid", "network.interface", "dump", {}]},
            ]
            body = json.dumps(calls).encode()
            resp, payload = self.request(
                conn, "POST", self.proxy_path("/ubus/?1700000001"), body,
                {"Content-Type": "application/json"},
            )
            self.assertEqual(resp.status, 200)
            replies = json.loads(payload.decode("utf-8"))
            self.assertEqual([r["id"] for r in replies], [1, 2])
        finally:
            conn.close()

    def test_proxied_post_body_and_query_survive(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            body = b'{"hello":"world"}'
            resp, payload = self.request(
                conn, "POST", self.proxy_path("/echo?x=1"), body,
                {"Content-Type": "application/json"},
            )
            self.assertEqual(resp.status, 200)
            seen = json.loads(payload.decode("utf-8"))
            self.assertEqual(seen["path"], "/echo?x=1")
            self.assertEqual(seen["body"], body.decode("utf-8"))
            self.assertEqual(seen["content_type"], "application/json")
            self.assertEqual(seen["accept_encoding"], "identity")
        finally:
            conn.close()

    def test_chunked_request_body_is_decoded_and_forwarded(self):
        """浏览器用 chunked 上传时也要解码转发，而不是丢掉 body。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            body = b'[{"jsonrpc":"2.0","id":1,"method":"list"}]'
            conn.putrequest("POST", self.proxy_path("/echo?chunked=1"))
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            for start in range(0, len(body), 7):
                chunk = body[start:start + 7]
                conn.send(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
            conn.send(b"0\r\n\r\n")
            resp = conn.getresponse()
            payload = resp.read()
            self.assertEqual(resp.status, 200)
            seen = json.loads(payload.decode("utf-8"))
            self.assertEqual(seen["body"], body.decode("utf-8"))
            self.assertEqual(seen["length"], len(body))
        finally:
            conn.close()

    def test_html_is_rewritten_and_shim_injected(self):
        """HTML 里的绝对路径要加前缀，注入脚本要在 <head> 之后。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            resp, payload = self.request(conn, "GET", self.proxy_path("/"))
            self.assertEqual(resp.status, 200)
            html = payload.decode("utf-8")
            prefix = self.proxy_path("").rstrip("/")
            self.assertIn('src="%s/luci-static/resources/luci.js"' % prefix, html)
            self.assertIn('href="%s/cgi-bin/luci/admin/status"' % prefix, html)
            self.assertIn('url(%s/luci-static/bg.png)' % prefix, html)
            self.assertIn("data-proxy-shim", html)
            self.assertLess(html.index("data-proxy-shim"), html.index("luci.js"))
        finally:
            conn.close()

    # ---------- 用例：弹窗 iframe 的配色

    def test_viewer_iframe_pins_light_color_scheme(self):
        """弹窗 iframe 必须声明 color-scheme: only light。

        iStoreOS 的 Argon 主题在 argon.global.mode=normal 时把深色样式包在
        @media (prefers-color-scheme: dark) 里，而 Chromium/Firefox 会把嵌入元素的 used
        color scheme 传给内嵌文档；深色飞牛窗口里页面因此变深色（图表还被反色）。
        子文档自己写 color-scheme 拦不住这个 media query，只能写在我们的 iframe 元素上。
        """
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            resp, payload = self.request(conn, "GET", "/style.css")
            self.assertEqual(resp.status, 200)
            css = payload.decode("utf-8")
            rule = "".join(block for block in css.split("}") if ".viewer iframe" in block)
            self.assertIn(".viewer iframe", rule)
            self.assertIn("color-scheme: only light", rule)

            resp2, payload2 = self.request(conn, "GET", "/")
            self.assertEqual(resp2.status, 200)
            self.assertIn('id="viewer-frame"', payload2.decode("utf-8"))
        finally:
            conn.close()

    # ---------- 用例：本体亮/暗切换

    def test_app_theme_switch_wiring(self):
        """本体亮/暗切换：默认浅色、顶栏图标入口、首帧前应用、令牌分两套。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            resp, payload = self.request(conn, "GET", "/")
            self.assertEqual(resp.status, 200)
            html = payload.decode("utf-8")
            self.assertIn('id="btn-theme"', html)
            self.assertIn("theme-toggle", html)
            # 首帧之前就按保存的值上主题，默认浅色
            self.assertIn("fn-openwrt-manager.theme", html)
            self.assertIn('content="light dark"', html)

            resp2, payload2 = self.request(conn, "GET", "/style.css")
            css = payload2.decode("utf-8")
            self.assertIn('html[data-theme="dark"]', css)
            # :root 是浅色默认值，深色靠 data-theme 覆盖
            root_block = css.split(':root {', 1)[1].split('}', 1)[0]
            self.assertIn("--bg: #f3f6fb", root_block)
            dark_block = css.split('html[data-theme="dark"] {', 1)[1].split('}', 1)[0]
            self.assertIn("--bg: #080b11", dark_block)
            # 本体切深色不该动弹窗里的路由器页面
            self.assertIn("color-scheme: only light", css)

            resp3, payload3 = self.request(conn, "GET", "/app.js")
            js = payload3.decode("utf-8")
            self.assertIn("fn-openwrt-manager.theme", js)
            self.assertIn("function applyTheme", js)
            self.assertIn("#btn-theme", js)
        finally:
            conn.close()

    # ---------- 用例：手机端适配

    def test_mobile_layout_rules(self):
        """窄屏规则存在性（防止被无意删掉）：全屏弹窗、两行头部、安全区、页脚收起。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            resp, payload = self.request(conn, "GET", "/")
            html = payload.decode("utf-8")
            self.assertIn("viewport-fit=cover", html)
            self.assertIn('class="foot-hint"', html)

            resp2, payload2 = self.request(conn, "GET", "/style.css")
            css = payload2.decode("utf-8")
            mobile = css.split("@media (max-width: 620px)", 1)[1]
            self.assertIn("100dvh", mobile)
            self.assertIn("100vh", mobile)  # 老浏览器兵底
            self.assertIn("env(safe-area-inset-top", mobile)
            self.assertIn("env(safe-area-inset-bottom", mobile)
            self.assertIn("grid-template-columns: repeat(4, minmax(0, 1fr))", mobile)
            self.assertIn(".viewer-addr { display: none;", mobile)
            self.assertIn(".foot .foot-hint { display: none;", mobile)
        finally:
            conn.close()

    # ---------- 用例：注入脚本的路径改写

    @unittest.skipUnless(shutil.which("node"), "需要 node 来执行注入脚本")
    def test_shim_rewrites_same_origin_absolute_urls(self):
        prefix = self.proxy_path("").rstrip("/")
        shim = self.app.PROXY_SHIM.replace("__PREFIX__", prefix)
        shim = shim.replace("<script data-proxy-shim>", "").replace("</script>", "")
        harness = """
const calls = [];
class XHR { open(m, u) { calls.push(u); } send() {} }
let clickHandler = null;
const document = {
  addEventListener: (type, fn) => { if (type === 'click') clickHandler = fn; },
};
const sandbox = {
  location: { protocol: 'http:', host: 'nas:8199' },
  XMLHttpRequest: XHR,
  fetch: (u) => { calls.push(u); return Promise.resolve(); },
  document,
};
sandbox.window = sandbox;
new Function(...Object.keys(sandbox), process.env.SHIM_SRC)(...Object.values(sandbox));
const urls = [
  '/ubus/?1',
  'http://nas:8199/ubus/?1',
  'http://nas:8199%s/ubus/?1',
  'http://192.168.200.1/ubus/?1',
];
const out = [];
for (const u of urls) { new sandbox.XMLHttpRequest().open('POST', u); }
sandbox.fetch('http://nas:8199/ubus/?2');
// 点击拦截：没带前缀的绝对链接补前缀，已带前缀/异源不动
const anchors = ['/cgi-bin/luci/admin/quickstart', 'http://nas:8199%s/cgi-bin/luci/admin/nas/'];
const clicked = [];
for (const href of anchors) {
  const a = { tagName: 'A', attrs: { href }, getAttribute(k) { return this.attrs[k]; }, setAttribute(k, v) { this.attrs[k] = v; } };
  clickHandler({ target: a });
  clicked.push(a.getAttribute('href'));
}
console.log(JSON.stringify({ calls, clicked }));
""" % (prefix, prefix)
        env = dict(os.environ, SHIM_SRC=shim)
        result = subprocess.run(
            ["node", "-e", harness], capture_output=True, text=True, env=env, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        got = json.loads(result.stdout)
        self.assertEqual(got["calls"], [
            prefix + "/ubus/?1",                          # 相对绝对路径
            "http://nas:8199" + prefix + "/ubus/?1",       # 同源绝对地址（本次 bug）
            "http://nas:8199" + prefix + "/ubus/?1",       # 已带前缀，保持不动
            "http://192.168.200.1/ubus/?1",               # 异源，保持不动
            "http://nas:8199" + prefix + "/ubus/?2",       # fetch 走同一套改写
        ])
        # 点击拦截：路由器侧边栏那种绝对链接补上前缀，已带前缀的不重复加
        self.assertEqual(got["clicked"], [
            prefix + "/cgi-bin/luci/admin/quickstart",
            "http://nas:8199" + prefix + "/cgi-bin/luci/admin/nas/",
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
