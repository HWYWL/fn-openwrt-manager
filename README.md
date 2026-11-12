# fn-openwrt-manager

飞牛 fnOS 应用：局域网 OpenWrt / iStoreOS 路由器管理器。

## 功能

- **自动扫描**：自动识别 NAS 所在网段（多网卡会逐个列出），并发探测 `80 / 443 / 8080 / 8443`，
  通过响应头（`uhttpd`）、页面内容（`cgi-bin/luci`、`OpenWrt`、`iStoreOS`）判断是否为 OpenWrt；
  另外会读取 ARP 缓存补充不回 Web 的设备。
- **只显示 OpenWrt**：扫描结果默认按「仅 OpenWrt」过滤（开关在扫描面板右上角，状态会记住），
  内网里的其他 Web 服务不再混在列表里；每张卡片可点删除（忽略），下次扫描不再出现，
  需要时点「恢复已忽略」还原（忽略列表存 `TRIM_PKGVAR/data/ignored.json`）。
- **手动添加**：支持 `192.168.1.1`、`192.168.1.1:8080`、`http://router.lan` 等写法，添加时即时探测。
- **一键打开**：点击卡片 / 按钮在应用内的弹窗（iframe）中打开 LuCI 管理页面，弹窗顶部可刷新、
  在新标签页打开或关闭；按住 `Shift`（或 `Ctrl`/`⌘`）点击则直接在新标签页打开。
- **弹窗内固定浅色**：弹窗的 iframe 上声明了 `color-scheme: only light`。iStoreOS 的 Argon 主题在
  `argon.global.mode=normal`（跟随系统）时把深色样式包在 `@media (prefers-color-scheme: dark)` 里，
  而现代浏览器会把**宿主页面（飞牛桌面窗口）的配色**传给内嵌文档，于是深色窗口里路由器页面会跟着变深色、
  图表还被反色成高饱和青紫。声明在 iframe 元素上就会让内嵌页面的 `prefers-color-scheme: dark` 不命中，
  配色与直接用浏览器打开一致（直连、中转两种模式都适用）；路由器自己把 Argon 设成「强制深色」时仍按路由器的来。
- **亮色 / 暗色**：顶栏右上角有一个切换图标（浅色时显示月亮、深色时显示太阳），**默认浅色**，
  选择记在浏览器本地（`localStorage`）。配色靠 `style.css` 里两套 CSS 变量（`:root` 浅色 /
  `html[data-theme="dark"]` 深色），切换只改 `<html data-theme>`，不会重新加载页面；
  **只影响应用本体**，弹窗里的路由器页面仍固定浅色，按路由器自己的主题走。
- **外网可用**：顶部访问方式切换「自动 / 直连 / 中转」。选「中转」时由 NAS 反向代理路由器页面
  （`/proxy/http/192.168.1.1:80/...`），外网通过 NAS 域名也能打开；「自动」会先探测直连是否可用，
  不通再自动走中转。代理会去掉上游的 `X-Frame-Options` / `frame-ancestors`，保证能在应用内弹窗正常显示。
- **手机端适配**：窄屏（≤620px）下弹窗直接全屏（`100dvh` + 安全区 padding），头部拆成两行——
  第一行状态点 + 名称 + 模式徽标，第二行四个操作按钮（刷新/日志/新标签/关闭）平分整行；
  地址行与页脚的长提示句在手机上隐藏，顶栏变成“访问方式 + 主题图标”一行、两个按钮平分一行，不再横向溢出。
- **收藏持久化**：收藏的路由器保存到 `TRIM_PKGVAR/data/devices.json`，升级/重启不丢失。

> 中转只允许访问私有地址（10/8、172.16/12、192.168/16、127/8、100.64/10），避免被当成公网代理跳板。

## 目录结构

```
manifest              应用信息（service_port = 8199）
cmd/main              启停脚本：探测 python3 → 启动 app/server/app.py
app/server/app.py     后端（纯 Python 标准库：HTTP 服务 + 网段识别 + 扫描）
app/www/              前端页面（原生 HTML/CSS/JS，无构建步骤）
app/ui/config         桌面入口（type = iframe，在飞牛桌面窗口内打开 http://<NAS>:8199/）
tests/                回归测试（标准库 unittest：中转发帧 + 路径改写）
config/               权限与资源配置
```

## 本地调试

```bash
APP_PORT=8199 APP_WWW_DIR=./app/www APP_DATA_DIR=./data python3 app/server/app.py
# 打开 http://127.0.0.1:8199
```

```bash
# 回归测试（中转 keep-alive 分帧、HTML 路径改写、注入脚本改写；后者有 node 时才跑）
python3 -m unittest discover -s tests -v
```

## 打包

```bash
fnpack build fn-openwrt-manager
```

生成的 `fn-openwrt-manager.fpk` 在飞牛「应用中心 → 手动安装」上传即可。

## 说明

- NAS 上需要存在 `python3`（fnOS 系统自带，也兼容 `/var/apps/python312` 等托管运行时）。
- 扫描范围为每个网卡所在网段，网段过大会自动收敛到 `/24`，最多 1024 个地址。
- 设备管理页面本身由路由器提供，本应用只负责发现与跳转。

## 中转（代理）实现要点

- 响应按类型处理：`text/html`、`text/css`、`javascript` 会缓冲后改写路径；其余（JSON、图片、事件流、
  长轮询）**边读边写流式转发**，不会因为上游迟迟不结束而整体超时（上游超时 65s）。
- 支持 `Upgrade: websocket` 的原样隧道（LuCI 的 ubus 订阅等），并在页面里注入了 WebSocket 路径改写。
- 转发时会带一个指向目标自身的 `Referer`（部分路由器会校验来源），并透传 `Cookie`。
- 上游的 `X-Frame-Options` / `Content-Security-Policy` 会被去掉，保证能在应用内弹窗显示。
- 流式响应使用 `Transfer-Encoding: chunked`（HTTP/1.1），避免前置网关/反代把响应整段缓冲到超时。
- 会自动识别应用被网关挂在子路径的情况（从 `Referer` 推导），改写出的绝对路径带上该前缀。
- **每个请求都先把请求体读满**（`Content-Length` 或 `Transfer-Encoding: chunked`）。HTTP/1.1 连接会被复用，
  只要有一条路径没读完 body（包括没命中路由的 404），下一个请求的请求行就会从残留字节中间开始解析，
  变成 `400 + HTML`。LuCI 的批量 RPC 拿到非 JSON 数组的响应就会在页面上报
  `Error: No related RPC reply`——所以“读满 body”不是优化，是正确性要求。
- 注入脚本除了改写以 `/` 开头的相对路径，也会改写**指向本应用的绝对地址**：LuCI 的
  `Request.expandURL()` 会把 RPC 地址（默认 `/ubus/`）展开成 `http://<NAS>:8199/ubus/`，
  绕过 `/proxy/...` 前缀（LuCI 至今不支持子路径反代），注入脚本会把它补回中转路径。
  同一套改写覆盖 XHR / `fetch` / `EventSource` / `WebSocket`。
- 排查问题：点页面底部的版本号可打开「中转请求日志」，实时显示最近 200 条中转请求
  （时间 / 方法 / 状态 / 耗时 / 路径）；同一份记录也会写进 `${TRIM_PKGVAR}/info.log`
  （设置 `APP_PROXY_DEBUG=1` 会记录全部请求，否则只记录失败与异常）。
