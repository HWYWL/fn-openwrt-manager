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

  /* ------------------------------------------------ 应用内弹窗查看 */

  function viewerFrame() {
    return $('#viewer-frame');
  }

  function setChannel(text, isDirect) {
    var tag = $('#viewer-mode');
    tag.textContent = text;
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
    var seq = state.viewerSeq;
    state.viewerProxy = opts.proxy;
    $('#viewer-title').textContent = opts.title || '路由器';
    $('#viewer-addr').textContent = opts.addr || '';
    $('#viewer-loading').hidden = false;
    if (!dialog.open) dialog.showModal();

    if (state.mode === 'direct') {
      setChannel('直连', true);
      loadFrame(opts.direct, true);
      return;
    }
    if (state.mode === 'proxy') {
      setChannel('中转');
      loadFrame(opts.proxy, false);
      return;
    }

    // 自动：页面本身就在公网域名下（远程访问），浏览器肯定到不了内网，直接中转
    var target = hostOf(opts.direct);
    if (!pageIsLocal() || directRecentlyFailed(target)) {
      setChannel('中转');
      loadFrame(opts.proxy, false);
      return;
    }

    setChannel('自动');
    probeDirect(opts.direct).then(function (ok) {
      if (seq !== state.viewerSeq) return;
      if (ok) {
        setChannel('直连', true);
        loadFrame(opts.direct, true);
        return;
      }
      if (target) state.directFail[target] = Date.now();
      setChannel('中转');
      loadFrame(opts.proxy, false);
      toast('当前网络无法直连该设备，已通过 NAS 中转打开', '');
    });
  }

  function closeViewer() {
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

    var meta = ' data-title="' + esc(title) + '" data-addr="' + esc(address) + '"';
    var actions = '<button type="button" class="btn primary tiny js-open" data-direct="' + esc(direct) +
      '" data-proxy="' + esc(proxied) + '"' + meta + ' title="在弹窗中打开（Shift + 点击在新标签页打开）">' +
      ICONS.open + '打开' + (kind === 'openwrt' ? ' LuCI' : '页面') + '</button>';

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
    $('#viewer-reload').addEventListener('click', reloadFrame);
    $('#viewer-log').addEventListener('click', openDebug);
    $('#viewer-switch').addEventListener('click', function () {
      if (!state.viewerProxy) return;
      setChannel('中转');
      loadFrame(state.viewerProxy, false);
    });
    $('#viewer-tab').addEventListener('click', function () {
      if (state.viewerUrl) window.open(state.viewerUrl, '_blank', 'noopener');
    });
    viewer.addEventListener('close', function () {
      viewerFrame().src = 'about:blank';
      clearTimeout(state.frameTimer);
      clearTimeout(state.frameHintTimer);
      state.viewerUrl = '';
      $('#viewer-hint').hidden = true;
    });
    viewer.addEventListener('click', function (event) {
      if (event.target === viewer) closeViewer();
    });

    function openFrom(el, event) {
      var opts = {
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
