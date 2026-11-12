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
- **一键打开 → 面板**：点击卡片 / 按钮先在弹窗里打开「面板」——实时速率、运行时长、在线设备数（DHCP + 无线 + 连接数）、
  CPU 占用/负载/温度、内存、真实磁盘挂载点，加上**路由器自己菜单里的**快捷操作与 iStore / Docker / 文件入口；
  点任意一项就在**同一个弹窗里**切到对应 LuCI 页，顶部「← 面板」返回；
  「LuCI 首页」去的是**路由器自己的首页**（取菜单里的「首页」/ `quickstart`，拿不到才退回 `/`，
  避免中文 LuCI 把 `/` 重定向成「状态概览」），旁边的「OpenWrt 首页」则固定进 LuCI 原生首页（状态总览）；
  按住 `Shift`（或 `Ctrl`/`⌘`）点击卡片仍然直接在新标签页开 LuCI。
- **面板数据怎么取**：在面板里填一次路由器账号密码（存 `TRIM_PKGVAR/data/routers.json`，权限 `600`），
  NAS 服务端表单登录 LuCI 拿会话，再用 ubus JSON-RPC 取数（与 iStore 客户端同一条路）：
  - `system info` 的 `load` 是 **65536 倍定点数**，除完才是真实负载；
  - 速率用 `luci-rpc getNetworkDevices` 的**设备级字节数**两次采样算（`network.interface dump` 的
    `statistics` 在不少固件上是 0，不再依赖它），历史保留 90 个点画曲线；
  - CPU 占用：iStoreOS 的 `istore/system/status` → `luci getProcessList` 汇总 `%CPU` → `/proc/stat` 双采样；
  - 在线设备：`luci-rpc getDHCPLeases`（降级 `/tmp/dhcp.leases`）+ `luci-rpc getWirelessDevices` 的
    assoclist；连接数来自 `luci getConntrackList`（15 秒缓存）；
  - 存储：`luci getMountPoints` + `getBlockDevices`，只统计 `/dev/*` 真实分区（过滤 tmpfs / overlayfs）；
  - 温度/频率：iStoreOS quickstart 或 `/sys/class/thermal`、`scaling_cur_freq`，rpcd 没放行就显示 `--`。
  顺带让**中转自动带上登录态**，弹窗里进 LuCI 不用再输密码。
- **快捷操作来自路由器自己的菜单**：登录后抓一页 LuCI 的侧边栏（名称 + 路径，10 分钟缓存），所以你这台装了
  哪些插件就显示哪些，点进去一定有；图标按路径关键字自动配。“应用与文件”从菜单里按路径识别 iStore / Docker /
  文件管理，菜单里没有就不显示。
  解析是容错的：`href` 单/双引号、不带引号、`/cgi-bin/luci/;stok=xxx/admin/...` 老式前缀、相对路径都能认。
  万一某个主题把菜单渲染成 JS 拼的（解析不到），面板不会空着，会退回一份**默认入口**并在标题旁标注
  「默认入口（未取到路由器菜单）」；想查原因可以直接访问 `GET /api/router/menu?id=<ip>:<port>`，
  它会返回尝试过的页面、HTTP 状态、抓到的字节数与解析条数。
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
app/server/app.py     后端（纯 Python 标准库：HTTP 服务 + 网段识别 + 扫描 + 中转 + 面板数据）
app/www/              前端页面（原生 HTML/CSS/JS，无构建步骤）
app/ui/config         桌面入口（type = iframe，在飞牛桌面窗口内打开 http://<NAS>:8199/）
tests/                回归测试（标准库 unittest：中转发帧、路径改写、面板登录与取数）
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
- **漏掉前缀的路由器请求会被接回**：中转页面里若有 JS 用绝对路径做客户端跳转（`location.href = '/cgi-bin/luci/...'`），
  浏览器会回到我们域名下的同名路径。这类请求（`/cgi-bin/luci*`、`/luci-static*`、`/ubus`）会按 `Referer` 里的
  `/proxy/<scheme>/<host>:<port>/` 接回对应中转目标，并且只允许私有地址——修掉了“点首页跳回自己应用页面、样式还全丢”的问题。
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
