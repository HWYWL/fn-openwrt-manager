/* fn-openwrt-manager 前端逻辑 */
(function () {
  'use strict';

  var $ = function (sel) { return document.querySelector(sel); };
  var state = {
    config: null,
    cidr: '',
    scan: null,
    saved: [],
    timer: null,
    // auto：先试直连，不通则走 NAS 中转；direct：强制直连；proxy：强制中转
    mode: localStorage.getItem('fn-openwrt-manager.mode') || 'auto',
    // 应用本体的亮/暗配色，默认浅色（只影响应用自身，不影响弹窗里的路由器页面）
    theme: storedTheme(),
    // 默认只看 OpenWrt，避免把内网里各种 Web 服务都列出来
    onlyOpenwrt: localStorage.getItem('fn-openwrt-manager.onlyOpenwrt') !== '0',
    ignored: {},
    viewerSeq: 0,
    viewerUrl: '',
    viewerProxy: '',
    viewerLoaded: false,
    viewerDirect: false,
    viewIndex: 'panel',
    panelTarget: null,
    panelTimer: null,
    panelSeq: 0,
    frameTimer: null,
    frameHintTimer: null,
    debugTimer: null,
    // 记住直连失败的设备，10 分钟内不再重复探测等待
    directFail: {}
  };

  var ICONS = {
    router: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="2.5" y="13" width="19" height="7" rx="2.2"/><path d="M6.5 16.5h.01M9.8 16.5h.01"/><path d="M12 9.5c-1.6-1.6-1.6-4.2 0-5.8M16 9.5c-1.6-1.6-1.6-4.2 0-5.8"/></svg>',
    web: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.2 2.4 3.3 5.4 3.3 8.5S14.2 18.1 12 20.5c-2.2-2.4-3.3-5.4-3.3-8.5S9.8 5.9 12 3.5z"/></svg>',
    unknown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M8 20.5h8"/></svg>',
    open: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M14 5h5v5M19 5l-8.5 8.5"/><path d="M18 14.5v4a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6h4"/></svg>',
    star: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 3.6l2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M9.5 7V4.8h5V7M6.5 7l.8 12.2a1.5 1.5 0 0 0 1.5 1.4h6.4a1.5 1.5 0 0 0 1.5-1.4L17.5 7"/></svg>',
    edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 20h4l10.5-10.5a2.1 2.1 0 0 0-3-3L5 17v3z"/></svg>'
  };

  /* ------------------------------------------------ 亮色 / 暗色 */

  function storedTheme() {
    try {
      return localStorage.getItem('fn-openwrt-manager.theme') === 'dark' ? 'dark' : 'light';
    } catch (e) {
      return 'light';
    }
  }

  // 只改 <html data-theme>，配色全由 style.css 的两套令牌控制
  function applyTheme(theme, persist) {
    var next = theme === 'dark' ? 'dark' : 'light';
    state.theme = next;
    document.documentElement.setAttribute('data-theme', next);
    var btn = $('#btn-theme');
    if (btn) {
      var label = next === 'dark' ? '切换到浅色' : '切换到深色';
      btn.title = label;
      btn.setAttribute('aria-label', label);
    }
    if (persist) {
      try { localStorage.setItem('fn-openwrt-manager.theme', next); } catch (e) {}
    }
  }

  function toggleTheme() {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark', true);
  }

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function toast(message, type) {
    var wrap = $('#toast-wrap');
    var el = document.createElement('div');
    el.className = 'toast ' + (type || '');
    el.textContent = message;
    wrap.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity .25s ease';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 260);
    }, 2600);
  }

  function api(path, options) {
    return fetch('api/' + path, options || {}).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error(data.error || ('请求失败 HTTP ' + res.status));
        return data;
      });
    });
  }

  function postJSON(path, body) {
    return api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
  }

  /* ------------------------------------------------ 打开设备 */

  function proxyUrl(device) {
    var secure = String(device.url || '').indexOf('https://') === 0;
    var scheme = secure ? 'https' : 'http';
    var port = device.port || (secure ? 443 : 80);
    return 'proxy/' + scheme + '/' + device.ip + ':' + port + '/';
  }

  function probeDirect(url) {
    return new Promise(function (resolve) {
      var ctrl = window.AbortController ? new AbortController() : null;
      var done = false;
      var finish = function (ok) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(ok);
      };
      var timer = setTimeout(function () {
        if (ctrl) { try { ctrl.abort(); } catch (e) {} }
        finish(false);
      }, 1500);
      try {
        fetch(url, { mode: 'no-cors', cache: 'no-store', signal: ctrl ? ctrl.signal : undefined })
          .then(function () { finish(true); })
          .catch(function () { finish(false); });
      } catch (e) {
        finish(false);
      }
    });
  }

  function openDevice(direct, proxy) {
    if (state.mode === 'direct') {
      window.open(direct, '_blank', 'noopener');
      return;
    }
    if (state.mode === 'proxy') {
      window.open(proxy, '_blank', 'noopener');
      return;
    }
    var win = window.open('', '_blank');
    probeDirect(direct).then(function (ok) {
      var target = ok ? direct : proxy;
      if (win && !win.closed) {
        try {
          win.location.href = target;
        } catch (e) {
          window.open(target, '_blank', 'noopener');
        }
      } else {
        window.open(target, '_blank', 'noopener');
      }
      if (!ok) toast('当前网络无法直连该设备，已通过 NAS 中转打开', '');
    });
  }

  /* ------------------------------------------------ 面板（弹窗第一屏） */

  var PANEL_ICONS = {
    grid: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.6"/>',
    swap: '<path d="M4 8h13l-3-3M20 16H7l3 3"/>',
    wifi: '<path d="M3 9a14 14 0 0 1 18 0M6 12.5a9.5 9.5 0 0 1 12 0M9.2 16a5 5 0 0 1 5.6 0"/><circle cx="12" cy="19.2" r="1"/>',
    shield: '<path d="M12 3.5l7 2.6v5.2c0 4.4-2.9 7.4-7 9.2-4.1-1.8-7-4.8-7-9.2V6.1z"/>',
    list: '<path d="M8 6.5h12M8 12h12M8 17.5h12"/><circle cx="4.3" cy="6.5" r="1"/><circle cx="4.3" cy="12" r="1"/><circle cx="4.3" cy="17.5" r="1"/>',
    cpu: '<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 3.5v3M14 3.5v3M10 17.5v3M14 17.5v3M3.5 10h3M3.5 14h3M17.5 10h3M17.5 14h3"/>',
    log: '<path d="M14.5 3.5H7a1.5 1.5 0 0 0-1.5 1.5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V7.5z"/><path d="M14.5 3.5v4h4M9.5 12.5h5M9.5 16h5"/>',
    term: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 10l2.5 2L7 14M12.5 14.5H17"/>',
    chart: '<path d="M4 20V9M9.3 20V4M14.6 20v-7M20 20v-11"/>',
    link: '<path d="M9.5 14.5l5-5"/><path d="M10.8 7.2l1.6-1.6a3.6 3.6 0 0 1 5 5l-1.6 1.6M13.2 16.8l-1.6 1.6a3.6 3.6 0 0 1-5-5l1.6-1.6"/>',
    wave: '<path d="M3 15l4.5-6 4 4.5L16 7l5 6"/>',
    tool: '<circle cx="12" cy="12" r="3"/><path d="M12 3.5v2.6M12 17.9v2.6M3.5 12h2.6M17.9 12h2.6M6 6l1.8 1.8M16.2 16.2L18 18M18 6l-1.8 1.8M7.8 16.2L6 18"/>',
    bag: '<path d="M5.5 8h13l-1 12h-11z"/><path d="M9 8V6.5a3 3 0 0 1 6 0V8"/>',
    box: '<path d="M12 3.5l8 4v9l-8 4-8-4v-9z"/><path d="M4 7.5l8 4 8-4M12 11.5v9"/>',
    folder: '<path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4l2 2.5h8A1.5 1.5 0 0 1 20.5 10v8a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 18z"/>'
  };

  function panelIcon(name) {
    var path = PANEL_ICONS[name] || PANEL_ICONS.grid;
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
      'stroke-linecap="round" stroke-linejoin="round">' + path + '</svg>';
  }

  function fmtBytes(value) {
    var n = Number(value) || 0;
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
    return (i === 0 ? String(Math.round(n)) : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + units[i];
  }

  function fmtRate(value) {
    if (value == null) return '--';
    return fmtBytes(value) + '/s';
  }

  function fmtUptime(seconds) {
    var s = Math.max(0, Math.floor(Number(seconds) || 0));
    var d = Math.floor(s / 86400);
    var h = Math.floor((s % 86400) / 3600);
    var m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + '天 ' + h + ':' + (m < 10 ? '0' + m : m);
    if (h > 0) return h + ':' + (m < 10 ? '0' + m : m);
    return m + ' 分钟';
  }

  function sparkline(history) {
    var points = (history || []).slice(-60);
    if (points.length < 2) return '';
    var max = 1;
    points.forEach(function (p) { max = Math.max(max, p[1], p[2]); });
    function pathOf(index) {
      return points.map(function (p, i) {
        var x = (i / (points.length - 1)) * 320;
        var y = 60 - Math.min(58, (p[index] / max) * 56);
        return (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1);
      }).join(' ');
    }
    return '<svg class="spark" viewBox="0 0 320 60" preserveAspectRatio="none">' +
      '<path d="' + pathOf(1) + '" fill="none" stroke="var(--accent)" stroke-width="2"/>' +
      '<path d="' + pathOf(2) + '" fill="none" stroke="var(--purple, #7c3aed)" stroke-width="1.6" stroke-dasharray="4 3"/>' +
      '</svg>';
  }

  function panelLoginForm(dev) {
    return '<form class="panel-login" id="panel-login-form" data-dev="' + esc(dev) + '">' +
      '<div class="panel-login-text"><b>填入路由器账号密码</b>' +
      '<span>只保存在这台 NAS 上（文件权限 600），用来读取面板数据，并让中转后的 LuCI 免登录。</span></div>' +
      '<label><span>用户名</span><input name="username" value="root" autocomplete="username" spellcheck="false"></label>' +
      '<label><span>密码</span><input name="password" type="password" autocomplete="current-password" required></label>' +
      '<button class="btn primary tiny" type="submit">保存并连接</button>' +
      '<button class="btn tiny" type="button" id="panel-login-clear">清除已存密码</button>' +
      '</form>';
  }

  function renderPanel(data) {
    var box = $('#viewer-panel');
    if (!data) return;
    var hasForm = !!box.querySelector('#panel-login-form');
    if (!data.authed && hasForm) return;   // 正在输密码，不要被轮询刷掉
    var scrollTop = box.scrollTop;

    var dev = (state.panelTarget && state.panelTarget.dev) || '';
    var html = '';

    if (!data.authed) {
      html += '<div class="panel-note"><b>未连接</b><span>' +
        esc(data.error || '还没有保存这台路由器的账号密码') + '</span></div>' + panelLoginForm(dev);
      html += panelTilesHtml(data, true) + panelAppsHtml(data);
      box.innerHTML = html;
      box.scrollTop = scrollTop;
      return;
    }

    var board = data.board || {};
    var memory = data.memory || {};
    var storage = data.storage || {};
    var wan = data.wan || {};
    var rate = data.rate || null;
    var load = (data.system && data.system.load) || [];
    var cpu = data.cpu || {};
    var clients = data.clients || {};

    html += '<div class="panel-sec">运行状态<span class="panel-sec-hint">每 3 秒刷新</span></div>';
    html += '<div class="panel-stats">';
    html += '<div class="panel-card hero"><h4>实时速率</h4>' +
      '<div class="panel-rate"><div><b>' + fmtRate(rate && rate.down) + '</b><small>↓</small></div>' +
      '<div><b>' + fmtRate(rate && rate.up) + '</b><small>↑</small></div></div>' +
      sparkline(data.history) +
      '<div class="panel-hint">' + (wan.iface ? esc(wan.iface) + ' · ' : '') +
      (wan.ip ? esc(wan.ip) + ' · ' : '') + (wan.up ? '链路正常' : '链路断开') + '</div></div>';
    html += '<div class="panel-card"><h4>运行时长</h4><div class="panel-big">' +
      fmtUptime(data.system && data.system.uptime) + '</div>' +
      '<div class="panel-kv"><span>负载 1/5/15</span><b>' + (load.length ? load.join(' / ') : '--') + '</b></div>' +
      '<div class="panel-kv"><span>固件</span><b>' + esc(board.firmware || board.model || '--') + '</b></div></div>';
    html += '<div class="panel-card"><h4>在线设备</h4><div class="panel-big">' + (clients.dhcp || 0) +
      '<span> 台</span></div>' +
      '<div class="panel-kv"><span>DHCP 租约</span><b>' + (clients.dhcp || 0) + '</b></div>' +
      '<div class="panel-kv"><span>WAN 状态</span><b>' + (wan.up ? '已连接' : '未连接') + '</b></div></div>';
    html += '</div>';

    html += '<div class="panel-sec">系统资源</div><div class="panel-res">';
    html += '<div class="panel-card"><h4>处理器</h4><div class="panel-big">' +
      (load.length ? Number(load[0]).toFixed(2) : '--') + '<span> 负载 1m</span></div>' +
      '<div class="panel-bar g"><i style="width:' + Math.min(100, Math.max(2, (Number(load[0]) || 0) * 100)) + '%"></i></div>' +
      '<div class="panel-kv"><span>温度 / 频率</span><b>' + (cpu.temp != null ? cpu.temp + '℃' : '--') +
      ' / ' + (cpu.freq ? cpu.freq + 'MHz' : '--') + '</b></div>' +
      '<div class="panel-kv"><span>型号</span><b>' + esc(board.cpu || board.model || '--') + '</b></div></div>';
    html += '<div class="panel-card"><h4>内存</h4><div class="panel-big">' + (memory.pct || 0) + '%</div>' +
      '<div class="panel-bar b"><i style="width:' + Math.min(100, memory.pct || 0) + '%"></i></div>' +
      '<div class="panel-kv"><span>已用 / 总量</span><b>' + fmtBytes(memory.used) + ' / ' + fmtBytes(memory.total) + '</b></div>' +
      '<div class="panel-kv"><span>可用</span><b>' + fmtBytes(memory.available) + '</b></div></div>';
    html += '<div class="panel-card"><h4>存储</h4><div class="panel-big">' + (storage.pct || 0) + '%</div>' +
      '<div class="panel-bar p"><i style="width:' + Math.min(100, storage.pct || 0) + '%"></i></div>' +
      '<div class="panel-kv"><span>根分区</span><b>' + fmtBytes(storage.used) + ' / ' + fmtBytes(storage.total) + '</b></div>' +
      '<div class="panel-kv"><span>剩余</span><b>' + fmtBytes(storage.free) + '</b></div></div>';
    html += '</div>';

    html += panelTilesHtml(data, true) + panelAppsHtml(data);
    box.innerHTML = html;
    box.scrollTop = scrollTop;
  }

  function panelTilesHtml(data, enabled) {
    var tiles = data.tiles || [];
    if (!tiles.length) return '';
    var body = tiles.map(function (t) {
      var off = t.available === false;
      return '<button type="button" class="panel-tile js-tile' + (off ? ' off' : '') + '"' +
        ' data-path="' + esc(t.path) + '" data-label="' + esc(t.label) + '"' +
        (off || !enabled ? ' disabled' : '') + ' title="' + esc(off ? t.label + '（路由器上未安装）' : t.label) + '">' +
        '<i class="pic ' + esc(t.color || 'n') + '">' + panelIcon(t.icon) + '</i><span>' + esc(t.label) + '</span></button>';
    }).join('');
    return '<div class="panel-sec">快捷操作</div><div class="panel-tiles">' + body + '</div>';
  }

  function panelAppsHtml(data) {
    var apps = data.apps || [];
    if (!apps.length) return '';
    var body = apps.map(function (a) {
      var off = a.available === false;
      return '<button type="button" class="panel-app js-tile' + (off ? ' off' : '') + '"' +
        ' data-path="' + esc(a.path) + '" data-label="' + esc(a.label) + '"' +
        (off ? ' disabled' : '') + '>' +
        '<i class="pic ' + esc(a.color || 'n') + '">' + panelIcon(a.icon) + '</i>' +
        '<span><strong>' + esc(a.label) + '</strong><em>' + esc(a.desc || '') + '</em></span></button>';
    }).join('');
    return '<div class="panel-sec">应用与文件</div><div class="panel-apps">' + body + '</div>';
  }

  function stopPanelPolling() {
    if (state.panelTimer) {
      clearInterval(state.panelTimer);
      state.panelTimer = null;
    }
  }

  function loadPanel() {
    var target = state.panelTarget;
    if (!target || !target.dev) return;
    var seq = state.panelSeq + 1;
    state.panelSeq = seq;
    api('router/dashboard?id=' + encodeURIComponent(target.dev)).then(function (data) {
      if (seq !== state.panelSeq) return;
      renderPanel(data);
    }).catch(function (err) {
      if (seq !== state.panelSeq) return;
      $('#viewer-panel').innerHTML = '<div class="panel-note err"><b>读取失败</b><span>' + esc(err.message) + '</span></div>';
    });
  }

  function startPanelPolling() {
    stopPanelPolling();
    loadPanel();
    state.panelTimer = setInterval(loadPanel, 3000);
  }

  function showPanelView() {
    state.viewIndex = 'panel';
    $('#viewer-panel').hidden = false;
    $('#viewer-frame-wrap').hidden = true;
    $('#viewer-back').hidden = true;
    $('#viewer-home').hidden = false;
    $('#viewer-loading').hidden = true;
    $('#viewer-hint').hidden = true;
    var tag = $('#viewer-mode');
    tag.textContent = '面板';
    tag.classList.remove('direct');
    tag.classList.add('panel');
    startPanelPolling();
  }

  function showFrameView(url, isDirect) {
    state.viewIndex = 'frame';
    stopPanelPolling();
    $('#viewer-panel').hidden = true;
    $('#viewer-frame-wrap').hidden = false;
    $('#viewer-back').hidden = false;
    $('#viewer-home').hidden = true;
    loadFrame(url, isDirect);
  }

  // 面板/首页里点某个 LuCI 路径：按当前访问方式决定走直连还是中转
  function openFrameFor(path) {
    var target = state.panelTarget;
    if (!target) return;
    var directUrl = target.directBase + path;
    var proxyUrl = target.proxyBase + path;
    var seq = state.viewerSeq;

    function useProxy() {
      setChannel('中转');
      showFrameView(proxyUrl, false);
    }

    if (state.mode === 'direct') {
      setChannel('直连', true);
      showFrameView(directUrl, true);
      return;
    }
    if (state.mode === 'proxy') { useProxy(); return; }

    setChannel('自动');
    var host = hostOf(directUrl);
    if (!pageIsLocal() || directRecentlyFailed(host)) { useProxy(); return; }
    probeDirect(directUrl).then(function (ok) {
      if (seq !== state.viewerSeq) return;
      if (ok) {
        setChannel('直连', true);
        showFrameView(directUrl, true);
        return;
      }
      if (host) state.directFail[host] = Date.now();
      setChannel('中转');
      showFrameView(proxyUrl, false);
    });
  }

  /* ------------------------------------------------ 应用内弹窗查看 */

  function viewerFrame() {
    return $('#viewer-frame');
  }

  function setChannel(text, isDirect) {
    var tag = $('#viewer-mode');
    tag.textContent = text;
    tag.classList.remove('panel');
    tag.classList.toggle('direct', !!isDirect);
  }

  // 当前页面本身是不是在内网地址上打开的；不是（公网域名/远程访问）就说明浏览器到不了内网
  function pageIsLocal() {
    var host = location.hostname || '';
    return /^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) ||
      host === '[::1]' || host === '::1';
  }

  function hostOf(url) {
    try { return new URL(url, location.href).hostname; } catch (e) { return ''; }
  }

  function directRecentlyFailed(host) {
    var at = host && state.directFail[host];
    return !!(at && Date.now() - at < 10 * 60 * 1000);
  }

  function loadFrame(url, isDirect) {
    var frame = viewerFrame();
    state.viewerUrl = url;
    state.viewerLoaded = false;
    state.viewerDirect = !!isDirect;
    $('#viewer-loading').hidden = false;
    $('#viewer-hint').hidden = true;
    clearTimeout(state.frameTimer);
    clearTimeout(state.frameHintTimer);
    state.frameTimer = setTimeout(function () {
      $('#viewer-loading').hidden = true;
    }, 3000);
    if (isDirect) {
      // 直连模式跨域，加载失败无法直接探测，超时后给个切中转的提示
      state.frameHintTimer = setTimeout(function () {
        if (!state.viewerLoaded) $('#viewer-hint').hidden = false;
      }, 6000);
    }
    frame.onload = function () {
      state.viewerLoaded = true;
      clearTimeout(state.frameTimer);
      clearTimeout(state.frameHintTimer);
      $('#viewer-loading').hidden = true;
      $('#viewer-hint').hidden = true;
    };
    frame.src = url;
  }

  function openViewer(opts) {
    var dialog = $('#viewer');
    state.viewerSeq += 1;
    state.panelTarget = {
      dev: opts.dev || '',
      directBase: String(opts.direct || '').replace(/\/+$/, ''),
      proxyBase: String(opts.proxy || '').replace(/\/+$/, '')
    };
    state.panelSeq = 0;
    state.viewerProxy = opts.proxy;
    $('#viewer-title').textContent = opts.title || '路由器';
    $('#viewer-addr').textContent = opts.addr || '';
    $('#viewer-panel').innerHTML = '<div class="panel-loading">正在读取路由器状态…</div>';
    if (!dialog.open) dialog.showModal();
    showPanelView();
  }

  function closeViewer() {
    stopPanelPolling();
    var dialog = $('#viewer');
    if (dialog.open) dialog.close();
  }

  function reloadFrame() {
    if (!state.viewerUrl) return;
    var url = state.viewerUrl;
    var isDirect = state.viewerDirect;
    var frame = viewerFrame();
    frame.src = 'about:blank';
    setTimeout(function () { loadFrame(url, isDirect); }, 60);
  }

  /* ------------------------------------------------ 渲染 */

  function deviceCard(device, mode) {
    var kind = device.kind || 'unknown';
    var iconClass = kind === 'openwrt' ? '' : kind;
    var icon = kind === 'openwrt' ? ICONS.router : (kind === 'web' ? ICONS.web : ICONS.unknown);
    var title = device.name || device.title || device.ip || '未知设备';
    var address = (device.ip || '') + (device.port && device.port !== 80 && device.port !== 443 ? ':' + device.port : '');
    var tags = [];
    if (kind === 'openwrt') tags.push('<span class="tag ok">LuCI 管理后台</span>');
    else if (kind === 'web') tags.push('<span class="tag">Web 服务</span>');
    else tags.push('<span class="tag">端口未识别</span>');
    if (device.is_gateway) tags.push('<span class="tag gw">网关</span>');
    if (device.server) tags.push('<span class="tag">' + esc(device.server) + '</span>');
    if (state.mode === 'proxy') tags.push('<span class="tag">经 NAS 中转</span>');

    var direct = device.url;
    var proxied = proxyUrl(device);

    var meta = ' data-title="' + esc(title) + '" data-addr="' + esc(address) + '"' +
      ' data-dev="' + esc((device.ip || '') + ':' + (device.port || 80)) + '"';
    var actions = '<button type="button" class="btn primary tiny js-open" data-direct="' + esc(direct) +
      '" data-proxy="' + esc(proxied) + '"' + meta + ' title="先看面板，需要时再进 LuCI（Shift + 点击直接在新标签页打开）">' +
      ICONS.open + '打开面板' + (kind === 'openwrt' ? ' / LuCI' : '') + '</button>';

    if (mode === 'scan') {
      actions += '<button class="btn tiny icon js-fav" data-url="' + esc(device.url) + '" data-title="' + esc(device.title || device.ip) +
        '" title="收藏到我的路由器">' + ICONS.star + '</button>';
      actions += '<button class="btn tiny icon danger js-hide" data-ip="' + esc(device.ip || '') +
        '" title="从结果中删除（以后扫描不再显示）">' + ICONS.trash + '</button>';
    } else {
      actions += '<button class="btn tiny icon js-rename" data-id="' + esc(device.id) + '" title="重命名">' + ICONS.edit + '</button>';
      actions += '<button class="btn tiny icon danger js-del" data-id="' + esc(device.id) + '" title="删除">' + ICONS.trash + '</button>';
    }

    return '<div class="card" data-direct="' + esc(direct) + '" data-proxy="' + esc(proxied) + '"' + meta + '>' +
      '<div class="card-top">' +
        '<div class="card-icon ' + esc(iconClass) + '">' + icon + '</div>' +
        '<div class="card-title"><strong title="' + esc(title) + '">' + esc(title) + '</strong><span>' + esc(address) + '</span></div>' +
      '</div>' +
      '<div class="tags">' + tags.join('') + '</div>' +
      '<div class="card-actions">' + actions + '</div>' +
    '</div>';
  }

  function renderSaved() {
    var grid = $('#saved-list');
    var empty = $('#saved-empty');
    $('#saved-count').textContent = state.saved.length;
    if (!state.saved.length) {
      grid.innerHTML = '';
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    grid.innerHTML = state.saved.map(function (d) { return deviceCard(d, 'saved'); }).join('');
  }

  function visibleScanDevices() {
    var found = (state.scan && state.scan.found) || [];
    return found.filter(function (d) {
      if (state.ignored[d.ip] || state.ignored[d.id]) return false;
      if (state.onlyOpenwrt && (d.kind || 'unknown') !== 'openwrt') return false;
      return true;
    });
  }

  function renderScan() {
    var grid = $('#scan-results');
    var empty = $('#scan-empty');
    var list = visibleScanDevices();
    var total = ((state.scan && state.scan.found) || []).length;
    var running = !!(state.scan && state.scan.running);

    grid.innerHTML = list.map(function (d) { return deviceCard(d, 'scan'); }).join('');
    empty.hidden = list.length > 0 || running;

    if (!list.length && !running) {
      if (total && state.onlyOpenwrt) {
        $('#scan-empty-title').textContent = '没有发现 OpenWrt 设备';
        $('#scan-empty-desc').textContent = '共发现 ' + total + ' 台其他服务，已按「仅 OpenWrt」过滤。取消勾选可查看全部。';
      } else if (total) {
        $('#scan-empty-title').textContent = '没有可显示的设备';
        $('#scan-empty-desc').textContent = '结果里的 ' + total + ' 台设备都被忽略了，点上方「恢复已忽略」可以还原。';
      } else {
        $('#scan-empty-title').textContent = '还没有扫描结果';
        $('#scan-empty-desc').textContent = '点击右上角「开始扫描」，程序会并发探测当前网段内的路由器';
      }
    }
  }

  function updateRestoreBtn() {
    var count = Object.keys(state.ignored).length;
    $('#btn-restore').hidden = count === 0;
    $('#ignored-count').textContent = count;
  }

  function renderChips() {
    var box = $('#cidr-chips');
    var list = [{ cidr: '', label: '全部网段' }];
    ((state.config && state.config.interfaces) || []).forEach(function (item) {
      list.push({ cidr: item.cidr, label: item.cidr, iface: item.iface });
    });
    box.innerHTML = list.map(function (item) {
      var active = (state.cidr || '') === item.cidr ? ' active' : '';
      return '<button type="button" class="chip' + active + '" data-cidr="' + esc(item.cidr) + '" title="' +
        esc(item.iface ? item.iface + ' 网卡' : '扫描全部网卡') + '">' + esc(item.label) + '</button>';
    }).join('');
  }

  function renderNetInfo() {
    var cfg = state.config || {};
    var ifaces = cfg.interfaces || [];
    var text;
    if (ifaces.length) {
      text = '本机地址 ' + ifaces.map(function (i) { return i.ip + '（' + i.iface + '）'; }).join('、');
      if (cfg.gateway) text += ' · 网关 ' + cfg.gateway;
    } else {
      text = '未能自动识别网段，请下拉选择或到设置页检查网络';
    }
    $('#net-info').textContent = text;
  }

  function setScanUI() {
    var scan = state.scan || {};
    var btn = $('#btn-scan');
    var bar = $('#progress');
    var fill = $('#progress-bar');
    var running = !!scan.running;

    btn.disabled = running;
    btn.querySelector('span').textContent = running ? '扫描中…' : '开始扫描';
    btn.querySelector('svg').classList.toggle('spin', running);
    bar.hidden = !running && !scan.total;

    if (scan.total) {
      var pct = Math.min(100, Math.round((scan.done / scan.total) * 100));
      fill.classList.remove('indeterminate');
      fill.style.width = pct + '%';
      $('#scan-count').textContent = scan.done + ' / ' + scan.total + ' 台主机';
    } else if (running) {
      fill.classList.add('indeterminate');
      $('#scan-count').textContent = '正在准备…';
    }

    var text;
    if (running) {
      text = '正在并发探测 ' + (scan.cidrs || []).join('、');
    } else if (scan.total) {
      var shown = visibleScanDevices().length;
      var all = (scan.found || []).length;
      text = '扫描完成 · 发现 ' + shown + ' 台' + (state.onlyOpenwrt ? ' OpenWrt' : '设备') +
        ' · 用时 ' + (scan.elapsed || 0) + 's';
      if (all > shown) text += ' · 已过滤 ' + (all - shown) + ' 台';
    } else {
      text = '待扫描';
    }
    if (scan.error) text = '扫描失败：' + scan.error;
    $('#scan-state').textContent = text;
  }

  /* ------------------------------------------------ 扫描 */

  function stopPolling() {
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
  }

  function pollOnce() {
    return api('scan/status').then(function (data) {
      var wasRunning = state.scan && state.scan.running;
      state.scan = data;
      renderScan();
      setScanUI();
      if (!data.running) {
        stopPolling();
        if (wasRunning) {
          var count = (data.found || []).length;
          if (data.error) toast('扫描失败：' + data.error, 'err');
          else toast(count ? '扫描完成，发现 ' + count + ' 台设备' : '扫描完成，未发现设备', count ? 'ok' : '');
        }
      }
    }).catch(function (err) {
      stopPolling();
      toast(err.message, 'err');
    });
  }

  function startScan(cidr) {
    if (state.scan && state.scan.running) return;
    state.cidr = cidr || '';
    renderChips();
    stopPolling();
    state.scan = { running: true, total: 0, done: 0, found: [], cidrs: [] };
    setScanUI();
    renderScan();

    postJSON('scan', { cidr: state.cidr }).then(function () {
      pollOnce();
      state.timer = setInterval(pollOnce, 700);
    }).catch(function (err) {
      state.scan = { running: false, total: 0, done: 0, found: [], error: err.message };
      setScanUI();
      toast(err.message, 'err');
    });
  }

  /* ------------------------------------------------ 收藏 */

  function loadSaved() {
    return api('devices').then(function (data) {
      state.saved = data.devices || [];
      renderSaved();
    }).catch(function (err) { toast(err.message, 'err'); });
  }

  function favDevice(url, title) {
    return postJSON('devices', { address: url, name: title }).then(function (res) {
      toast(res.created ? '已添加到我的路由器' : '该地址已收藏过了', res.created ? 'ok' : '');
      return loadSaved();
    }).catch(function (err) { toast(err.message, 'err'); });
  }

  function removeDevice(id) {
    return api('devices?id=' + encodeURIComponent(id), { method: 'DELETE' }).then(function () {
      toast('已删除', 'ok');
      return loadSaved();
    }).catch(function (err) { toast(err.message, 'err'); });
  }

  function renameDevice(id) {
    var current = state.saved.filter(function (d) { return d.id === id; })[0];
    var name = window.prompt('新的名称', current ? current.name : '');
    if (name === null) return;
    api('devices', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id, name: name })
    }).then(function () {
      toast('已重命名', 'ok');
      return loadSaved();
    }).catch(function (err) { toast(err.message, 'err'); });
  }

  /* ------------------------------------------------ 扫描结果忽略 */

  function loadIgnored() {
    return api('ignored').then(function (res) {
      var map = {};
      (res.ids || []).forEach(function (key) { map[key] = 1; });
      state.ignored = map;
      updateRestoreBtn();
    }).catch(function () {});
  }

  function hideDevice(ip) {
    if (!ip) return;
    return postJSON('ignored', { id: ip }).then(function (res) {
      var map = {};
      (res.ids || []).forEach(function (key) { map[key] = 1; });
      state.ignored = map;
      renderScan();
      setScanUI();
      updateRestoreBtn();
      toast('已从扫描结果中删除', 'ok');
    }).catch(function (err) { toast(err.message, 'err'); });
  }

  function restoreIgnored() {
    return api('ignored', { method: 'DELETE' }).then(function () {
      state.ignored = {};
      renderScan();
      setScanUI();
      updateRestoreBtn();
      toast('已恢复全部忽略的设备', 'ok');
    }).catch(function (err) { toast(err.message, 'err'); });
  }

  /* ------------------------------------------------ 中转日志 */

  function loadProxyLog() {
    return api('proxylog').then(function (res) {
      var entries = res.entries || [];
      var box = $('#debug-list');
      if (!entries.length) {
        box.textContent = '（暂无中转请求。先在弹窗里打开一次路由器页面，再回来查看）';
        return;
      }
      var lines = entries.slice().reverse().map(function (e) {
        var status = String(e.status);
        var pad = function (s, n) { s = String(s); while (s.length < n) s += ' '; return s; };
        var left = function (s, n) { s = String(s); while (s.length < n) s = ' ' + s; return s; };
        return e.time + '  ' + pad(e.method, 4) + ' ' + pad(status, 3) + ' ' +
          left(e.ms + 'ms', 7) + '  ' + e.target + (e.note ? '  [' + e.note + ']' : '');
      });
      box.textContent = lines.join('\n');
    }).catch(function (err) {
      $('#debug-list').textContent = '读取失败: ' + err.message;
    });
  }

  /* ------------------------------------------------ 访问方式 */

  function setMode(mode, silent) {
    if (['auto', 'direct', 'proxy'].indexOf(mode) < 0) return;
    state.mode = mode;
    try { localStorage.setItem('fn-openwrt-manager.mode', mode); } catch (e) {}
    var buttons = document.querySelectorAll('#access-mode button');
    Array.prototype.forEach.call(buttons, function (btn) {
      btn.classList.toggle('active', btn.dataset.mode === mode);
    });
    if (!silent) {
      renderScan();
      renderSaved();
      if (mode === 'proxy') toast('已切换到 NAS 中转，外网访问也能打开路由器', 'ok');
    }
  }

  /* ------------------------------------------------ 事件 */

  function openDebug() {
    var dialog = $('#debug-dialog');
    if (!dialog.open) dialog.showModal();
    loadProxyLog();
    clearInterval(state.debugTimer);
    state.debugTimer = setInterval(loadProxyLog, 1500);
  }

  function bind() {
    $('#btn-scan').addEventListener('click', function () { startScan(state.cidr); });

    $('#btn-theme').addEventListener('click', toggleTheme);

    $('#cidr-chips').addEventListener('click', function (event) {
      var chip = event.target.closest('.chip');
      if (!chip) return;
      if (state.scan && state.scan.running) {
        toast('扫描进行中，请稍候', '');
        return;
      }
      startScan(chip.dataset.cidr || '');
    });

    $('#access-mode').addEventListener('click', function (event) {
      var btn = event.target.closest('button[data-mode]');
      if (!btn) return;
      setMode(btn.dataset.mode);
    });

    $('#only-openwrt').addEventListener('change', function (event) {
      state.onlyOpenwrt = !!event.target.checked;
      try {
        localStorage.setItem('fn-openwrt-manager.onlyOpenwrt', state.onlyOpenwrt ? '1' : '0');
      } catch (e) {}
      renderScan();
      setScanUI();
    });

    $('#btn-restore').addEventListener('click', restoreIgnored);

    var debugDialog = $('#debug-dialog');
    $('#ver').addEventListener('click', openDebug);
    $('#debug-reload').addEventListener('click', loadProxyLog);
    debugDialog.addEventListener('close', function () {
      clearInterval(state.debugTimer);
      state.debugTimer = null;
    });

    var viewer = $('#viewer');
    $('#viewer-close').addEventListener('click', closeViewer);
    $('#viewer-reload').addEventListener('click', function () {
      if (state.viewIndex === 'panel') { loadPanel(); return; }
      reloadFrame();
    });
    $('#viewer-log').addEventListener('click', openDebug);
    $('#viewer-back').addEventListener('click', function () {
      $('#viewer-panel').innerHTML = '';
      showPanelView();
    });
    $('#viewer-home').addEventListener('click', function () { openFrameFor('/'); });
    // 面板里的 tile / 应用入口 / 登录表单
    $('#viewer-panel').addEventListener('click', function (event) {
      var tile = event.target.closest('.js-tile');
      if (tile && !tile.disabled) {
        openFrameFor(tile.dataset.path || '/');
        return;
      }
      if (event.target.closest('#panel-login-clear')) {
        var dev = (state.panelTarget && state.panelTarget.dev) || '';
        api('router/login?id=' + encodeURIComponent(dev), { method: 'DELETE' }).then(function () {
          toast('已清除路由器密码', 'ok');
          $('#viewer-panel').innerHTML = '';
          startPanelPolling();
        }).catch(function (err) { toast(err.message, 'err'); });
      }
    });
    $('#viewer-panel').addEventListener('submit', function (event) {
      if (event.target.id !== 'panel-login-form') return;
      event.preventDefault();
      var dev = (state.panelTarget && state.panelTarget.dev) || '';
      var form = event.target;
      var username = (form.querySelector('[name=username]').value || '').trim() || 'root';
      var password = form.querySelector('[name=password]').value || '';
      var btn = form.querySelector('button[type=submit]');
      if (!password) { toast('请输入路由器密码', 'err'); return; }
      btn.disabled = true;
      btn.textContent = '连接中…';
      postJSON('router/login', { id: dev, username: username, password: password })
        .then(function () {
          toast('已连接路由器，面板数据开始加载', 'ok');
          $('#viewer-panel').innerHTML = '<div class="panel-loading">正在读取路由器状态…</div>';
          startPanelPolling();
        })
        .catch(function (err) {
          toast(err.message, 'err');
          btn.disabled = false;
          btn.textContent = '保存并连接';
        });
    });
    $('#viewer-switch').addEventListener('click', function () {
      if (!state.viewerProxy) return;
      setChannel('中转');
      showFrameView(state.viewerProxy, false);
    });
    $('#viewer-tab').addEventListener('click', function () {
      if (state.viewerUrl) window.open(state.viewerUrl, '_blank', 'noopener');
    });
    viewer.addEventListener('close', function () {
      stopPanelPolling();
      viewerFrame().src = 'about:blank';
      clearTimeout(state.frameTimer);
      clearTimeout(state.frameHintTimer);
      state.viewerUrl = '';
      state.panelTarget = null;
      $('#viewer-panel').innerHTML = '';
      $('#viewer-hint').hidden = true;
    });
    viewer.addEventListener('click', function (event) {
      if (event.target === viewer) closeViewer();
    });

    function openFrom(el, event) {
      var opts = {
        dev: el.dataset.dev,
        direct: el.dataset.direct,
        proxy: el.dataset.proxy,
        title: el.dataset.title,
        addr: el.dataset.addr
      };
      if (event.shiftKey || event.ctrlKey || event.metaKey) openDevice(opts.direct, opts.proxy);
      else openViewer(opts);
    }

    document.addEventListener('click', function (event) {
      var open = event.target.closest('.js-open');
      if (open) {
        event.preventDefault();
        event.stopPropagation();
        openFrom(open, event);
        return;
      }
      var fav = event.target.closest('.js-fav');
      if (fav) {
        event.preventDefault();
        event.stopPropagation();
        favDevice(fav.dataset.url, fav.dataset.title);
        return;
      }
      var hideBtn = event.target.closest('.js-hide');
      if (hideBtn) {
        event.preventDefault();
        event.stopPropagation();
        hideDevice(hideBtn.dataset.ip);
        return;
      }
      var del = event.target.closest('.js-del');
      if (del) {
        event.preventDefault();
        event.stopPropagation();
        removeDevice(del.dataset.id);
        return;
      }
      var ren = event.target.closest('.js-rename');
      if (ren) {
        event.preventDefault();
        event.stopPropagation();
        renameDevice(ren.dataset.id);
        return;
      }
      var card = event.target.closest('.card');
      if (card && card.dataset.direct && !event.target.closest('a,button')) {
        openFrom(card, event);
      }
    });

    var dialog = $('#add-dialog');
    $('#btn-add').addEventListener('click', function () {
      $('#add-address').value = '';
      $('#add-name').value = '';
      dialog.showModal();
      setTimeout(function () { $('#add-address').focus(); }, 30);
    });
    $('#add-cancel').addEventListener('click', function () { dialog.close(); });

    $('#add-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var address = $('#add-address').value.trim();
      var name = $('#add-name').value.trim();
      if (!address) return;
      var btn = $('#add-submit');
      btn.disabled = true;
      btn.textContent = '探测中…';
      postJSON('devices', { address: address, name: name }).then(function (res) {
        var kind = (res.device && res.device.kind) || 'unknown';
        if (res.created) toast(kind === 'openwrt' ? '已添加，识别到 LuCI 管理后台' : '已添加（未识别到 LuCI，可能需登录）', 'ok');
        else toast('该地址已收藏过了', '');
        dialog.close();
        return loadSaved();
      }).catch(function (err) {
        toast(err.message, 'err');
      }).then(function () {
        btn.disabled = false;
        btn.textContent = '添加并探测';
      });
    });
  }

  /* ------------------------------------------------ 初始化 */

  function init() {
    applyTheme(state.theme, false);
    setMode(state.mode, true);
    $('#only-openwrt').checked = state.onlyOpenwrt;
    bind();
    api('config').then(function (cfg) {
      state.config = cfg;
      state.cidr = '';
      $('#ver').textContent = 'v' + (cfg.version || '1.0.0');
      renderNetInfo();
      renderChips();
    }).catch(function (err) {
      toast('读取配置失败：' + err.message, 'err');
    });

    loadIgnored().then(loadSaved).then(function () { return pollOnce(); }).then(function () {
      if (!(state.scan && state.scan.running)) {
        setTimeout(function () { startScan(''); }, 260);
      } else {
        state.timer = setInterval(pollOnce, 700);
      }
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
