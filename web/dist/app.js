'use strict';
// nexa Web 面板 SPA：原生 JS，无框架依赖，5 页面对齐原 LuCI 视图 + 登录。

const API = (() => {
  const token = () => localStorage.getItem('nexa_token');
  async function req(path, opts = {}) {
    opts.headers = opts.headers || {};
    if (token()) opts.headers['Authorization'] = 'Bearer ' + token();
    if (opts.body && typeof opts.body !== 'string' && !(opts.body instanceof FormData)) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const r = await fetch(path, opts);
    if (r.status === 401) { location.hash = '#/login'; throw new Error('未授权'); }
    const ct = r.headers.get('Content-Type') || '';
    if (ct.includes('application/json')) return r.json();
    return r.text();
  }
  return {
    get: (p) => req(p),
    post: (p, b) => req(p, { method: 'POST', body: b }),
    put: (p, b) => req(p, { method: 'PUT', body: b }),
    del: (p) => req(p, { method: 'DELETE' }),
    raw: (p, opts = {}) => {
      opts.headers = opts.headers || {};
      const t = localStorage.getItem('nexa_token');
      if (t) opts.headers['Authorization'] = 'Bearer ' + t;
      return fetch(p, opts);
    }, // 用于下载等
  };
})();

const UI = {
  toast(msg, type = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2600);
  },
  el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const k in attrs) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'html') e.innerHTML = attrs[k];
      else if (k.startsWith('on')) e.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    }
    for (const c of children) {
      if (c == null) continue;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return e;
  },
  toggle(checked, onchange) {
    const i = UI.el('input', { type: 'checkbox' });
    if (checked) i.checked = true;
    if (onchange) i.addEventListener('change', () => onchange(i.checked));
    return UI.el('label', { class: 'toggle' }, i, UI.el('span', { class: 'slider' }));
  },
  field(label, inputEl, hint) {
    const f = UI.el('div', { class: 'field' });
    f.appendChild(UI.el('label', {}, label));
    f.appendChild(inputEl);
    if (hint) f.appendChild(UI.el('div', { class: 'hint' }, hint));
    return f;
  },
  input(type, val, placeholder) {
    return UI.el('input', { type, value: val || '', placeholder: placeholder || '' });
  },
};

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => UI.toast('已复制', 'ok')).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}
function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy') ? UI.toast('已复制', 'ok') : UI.toast('复制失败', 'err'); }
  catch (e) { UI.toast('复制失败', 'err'); }
  ta.remove();
}

// ── 路由 ─────────────────────────────
const routes = {};
function route(path, fn) { routes[path] = fn; }

const NAV = [
  { hash: '#/app',     name: '启动配置', icon: '◆' },
  { hash: '#/profile', name: '配置文件', icon: '▦' },
  { hash: '#/proxy',   name: '代理配置', icon: '◈' },
  { hash: '#/editor',  name: '编辑器',   icon: '✎' },
  { hash: '#/log',     name: '日志',     icon: '☰' },
  { hash: '#/settings', name: '设置',   icon: '⚙' },
];

function renderLayout() {
  const app = document.getElementById('app');
  app.innerHTML = '';
  const layout = UI.el('div', { class: 'layout' });
  const overlay = UI.el('div', { class: 'sidebar-overlay', onclick: () => { document.querySelector('.sidebar').classList.remove('open'); overlay.classList.remove('open'); } });
  const sidebar = UI.el('div', { class: 'sidebar' });
  sidebar.appendChild(UI.el('div', { class: 'logo' },
    UI.el('div', { class: 'dot' }, 'N'),
    UI.el('div', { class: 'name' }, 'Nexa')
  ));
  NAV.forEach(n => {
    const item = UI.el('div', {
      class: 'nav-item' + (location.hash === n.hash ? ' active' : ''),
      onclick: () => { location.hash = n.hash; document.querySelector('.sidebar').classList.remove('open'); overlay.classList.remove('open'); }
    }, UI.el('span', { class: 'ico' }, n.icon), n.name);
    sidebar.appendChild(item);
  });
  sidebar.appendChild(UI.el('div', { class: 'spacer' }));
  sidebar.appendChild(UI.el('div', { class: 'nav-item', onclick: () => {
    localStorage.removeItem('nexa_token'); location.hash = '#/login';
  } }, UI.el('span', { class: 'ico' }, '⏻'), '退出'));

  const main = UI.el('div', { class: 'main' });
  const menuBtn = UI.el('button', { class: 'btn btn-outline menu-btn', onclick: () => { document.querySelector('.sidebar').classList.toggle('open'); overlay.classList.toggle('open'); } }, '☰');
  const topbar = UI.el('div', { class: 'topbar' },
    UI.el('div', { class: 'title', id: 'page-title' }, 'Nexa'),
    UI.el('div', { class: 'right', id: 'topbar-right' })
  );
  topbar.insertBefore(menuBtn, topbar.firstChild);
  const content = UI.el('div', { class: 'content', id: 'content' });
  main.appendChild(topbar);
  main.appendChild(content);
  layout.appendChild(overlay);
  layout.appendChild(sidebar);
  layout.appendChild(main);
  app.appendChild(layout);
}

async function router() {
  if (!localStorage.getItem('nexa_token')) { location.hash = '#/login'; }
  const hash = location.hash || '#/app';
  if (hash === '#/login') {
    document.getElementById('app').innerHTML = '';
    renderLogin();
    return;
  }
  if (!document.querySelector('.layout')) renderLayout();
  const fn = routes[hash] || routes['#/app'];
  const navItem = NAV.find(n => n.hash === hash);
  const title = document.getElementById('page-title');
  if (title && navItem) title.textContent = navItem.name;
  // 高亮当前导航
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  try {
    await fn(document.getElementById('content'));
  } catch (e) {
    document.getElementById('content').innerHTML = '<div class="card">加载失败：' + (e.message || e) + '</div>';
  }
  // 顶部状态
  renderTopbar();
}

async function renderTopbar() {
  const right = document.getElementById('topbar-right');
  if (!right) return;
  right.innerHTML = '';
  try {
    const st = await API.get('/api/status');
    right.appendChild(UI.el('span', { class: 'status-pill ' + (st.running ? 'running' : 'stopped') },
      UI.el('span', { class: 'dot' }), st.running ? '运行中' : '未运行'));
  } catch (e) {
    right.appendChild(UI.el('span', { class: 'status-pill stopped' }, UI.el('span', { class: 'dot' }), '未知'));
  }
}

window.addEventListener('hashchange', router);

// ── 登录页 ───────────────────────────
function renderLogin() {
  const wrap = UI.el('div', { class: 'login-wrap' });
  const card = UI.el('div', { class: 'login-card' });
  card.appendChild(UI.el('div', { class: 'brand-dot' }, 'N'));
  card.appendChild(UI.el('h1', {}, 'Nexa'));
  card.appendChild(UI.el('div', { class: 'sub' }, '透明代理管理面板'));
  const userI = UI.input('text', 'admin', '用户名');
  const passI = UI.input('password', '', '密码');
  card.appendChild(UI.field('用户名', userI));
  card.appendChild(UI.field('密码', passI));
  const btn = UI.el('button', { class: 'btn btn-primary btn-block mt-16' }, '登录');
  btn.addEventListener('click', async () => {
    try {
      const r = await API.post('/api/auth/login', { username: userI.value, password: passI.value });
      localStorage.setItem('nexa_token', r.token);
      location.hash = '#/app';
    } catch (e) { UI.toast('用户名或密码错误', 'err'); }
  });
  passI.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); });
  card.appendChild(btn);
  wrap.appendChild(card);
  document.getElementById('app').appendChild(wrap);
}

// ── 工具：动态标签输入 ─────────────
// options: 可选下拉列表（字符串数组），传入时会渲染一个 select 供用户从系统已检测到的候选项中挑选。
function dynList(values, options) {
  const wrap = UI.el('div', { class: 'dyn-list' });
  const render = (vals) => {
    wrap.innerHTML = '';
    (vals || []).forEach((v, i) => {
      const chip = UI.el('span', { class: 'chip' }, v,
        UI.el('span', { class: 'x', onclick: () => { vals.splice(i, 1); render(vals); } }, '×'));
      wrap.appendChild(chip);
    });
    // 下拉候选项：已选中的不再出现在下拉中
    if (options && options.length) {
      const sel = UI.el('select', { class: 'chip-select' });
      sel.appendChild(UI.el('option', { value: '' }, '+ 从列表选择'));
      let avail = 0;
      options.forEach(opt => {
        if (!vals.includes(opt)) {
          sel.appendChild(UI.el('option', { value: opt }, opt));
          avail++;
        }
      });
      if (avail > 0) {
        sel.addEventListener('change', () => {
          if (sel.value) {
            vals.push(sel.value);
            render(vals);
          }
        });
        wrap.appendChild(sel);
      }
    }
    const addBtn = UI.el('button', { class: 'chip-add', onclick: () => {
      const v = prompt('输入值（逗号分隔多个）');
      if (!v) return;
      v.split(',').map(s => s.trim()).filter(Boolean).forEach(x => {
        if (!vals.includes(x)) vals.push(x);
      });
      render(vals);
    } }, '+ 添加');
    wrap.appendChild(addBtn);
  };
  render(values);
  return wrap;
}

// ── 工具：代码编辑器（语法高亮 + 行号 + Tab 缩进） ─────
// lang: 'json' | 'yaml' | 'text'
function detectLang(name) {
  const lower = (name || '').toLowerCase();
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml';
  // 无扩展名时尝试根据首字符检测
  return '';
}
function escapeHTML(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function highlight(code, lang) {
  const esc = escapeHTML(code);
  if (lang === 'json') return hlJSON(esc);
  if (lang === 'yaml') return hlYAML(esc);
  return esc;
}
// JSON 高亮：键名/字符串/数字/布尔/null
function hlJSON(s) {
  return s.replace(
    /"(?:\\.|[^"\\])*"(\s*:)?|(-?\b\d+\.?\d*(?:[eE][+-]?\d+)?\b)|\b(true|false|null)\b/g,
    (m, colon, num, kw) => {
      if (m[0] === '"') {
        if (colon) return '<span class="tok-key">' + m.replace(/\s*:$/, '') + '</span>' + colon;
        return '<span class="tok-str">' + m + '</span>';
      }
      if (num) return '<span class="tok-num">' + num + '</span>';
      if (kw) return '<span class="tok-kw">' + kw + '</span>';
      return m;
    }
  );
}
// YAML 高亮：注释/键名/字符串值/数字/布尔
function hlYAML(s) {
  return s.split('\n').map(line => {
    // 整行注释
    if (/^\s*#/.test(line)) return '<span class="tok-com">' + line + '</span>';
    // 匹配 "缩进 [- ] key: rest"
    const m = line.match(/^(\s*-?\s*)([^:\s#\n][^:\n]*?)(\s*:)(\s*)(.*)$/);
    if (m) {
      const indent = m[1], key = m[2], colon = m[3], sp = m[4], val = m[5];
      let valHTML;
      // 值中的注释
      const cmt = val.match(/\s#.*$/);
      let valMain = val, cmtHTML = '';
      if (cmt && val.indexOf('"') < 0) {
        valMain = val.slice(0, cmt.index);
        cmtHTML = '<span class="tok-com">' + cmt[0] + '</span>';
      }
      const trimmed = valMain.trim();
      if (/^-?\d+\.?\d*$/.test(trimmed)) {
        valHTML = '<span class="tok-num">' + valMain + '</span>';
      } else if (/^(true|false|null|yes|no|~)$/i.test(trimmed)) {
        valHTML = '<span class="tok-kw">' + valMain + '</span>';
      } else if (trimmed === '' || (trimmed[0] === '"' && trimmed[trimmed.length - 1] === '"') || (trimmed[0] === "'" && trimmed[trimmed.length - 1] === "'")) {
        valHTML = '<span class="tok-str">' + valMain + '</span>';
      } else {
        valHTML = '<span class="tok-str">' + valMain + '</span>';
      }
      return indent + '<span class="tok-key">' + key + '</span>' + colon + sp + valHTML + cmtHTML;
    }
    // 列表项 "- value"
    const lm = line.match(/^(\s*)(-)(\s+)(.*)$/);
    if (lm) {
      return lm[1] + '<span class="tok-kw">' + lm[2] + '</span>' + lm[3] + '<span class="tok-str">' + lm[4] + '</span>';
    }
    return line;
  }).join('\n');
}
function codeEditor(initialLang) {
  let lang = initialLang || 'text';
  const wrap = UI.el('div', { class: 'code-editor' });
  const gutter = UI.el('div', { class: 'code-gutter' });
  const area = UI.el('div', { class: 'code-area' });
  const pre = UI.el('pre', { class: 'code-highlight', 'aria-hidden': 'true' });
  const codeEl = UI.el('code', {});
  pre.appendChild(codeEl);
  const ta = UI.el('textarea', { class: 'code-input', spellcheck: 'false', wrap: 'off' });
  area.appendChild(pre);
  area.appendChild(ta);
  wrap.appendChild(gutter);
  wrap.appendChild(area);

  const update = () => {
    const v = ta.value || '';
    codeEl.innerHTML = highlight(v, lang) + '\n';
    const lines = v.split('\n').length;
    let gh = '';
    for (let i = 1; i <= lines; i++) gh += i + '\n';
    gutter.textContent = gh;
  };
  ta.addEventListener('input', update);
  ta.addEventListener('scroll', () => {
    pre.scrollTop = ta.scrollTop;
    pre.scrollLeft = ta.scrollLeft;
    // gutter overflow:hidden 无法用 scrollTop，用 transform 同步
    gutter.style.transform = 'translateY(' + (-ta.scrollTop) + 'px)';
  });
  // Tab 缩进（2 空格）
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const s = ta.selectionStart, ed = ta.selectionEnd;
      ta.value = ta.value.slice(0, s) + '  ' + ta.value.slice(ed);
      ta.selectionStart = ta.selectionEnd = s + 2;
      update();
    }
  });

  return {
    el: wrap,
    get: () => ta.value,
    set: (v) => { ta.value = v; update(); },
    setLang: (l) => { lang = l; update(); },
  };
}

// ── 页面：插件配置 (app.js) ─────────
route('#/app', async (c) => {
  const [cfg, profiles, ver] = await Promise.all([API.get('/api/config'), API.get('/api/profiles'), API.get('/api/version')]);
  const local = JSON.parse(JSON.stringify(cfg));

  c.innerHTML = '';
  // 状态卡片
  const statusCard = UI.el('div', { class: 'card' });
  statusCard.appendChild(UI.el('div', { class: 'card-title' }, '状态'));
  const sRow = UI.el('div', { class: 'grid-3' },
    UI.field('面板版本', UI.el('input', { value: '1.0.0', readonly: '' })),
    UI.field('运行状态', UI.el('div', { id: 'app-status-box' })),
    UI.field('操作', UI.el('div', { class: 'row-gap' },
      UI.el('button', { class: 'btn btn-outline btn-sm', onclick: async () => { await API.post('/api/restart-core'); UI.toast('已重启核心', 'ok'); } }, '重启核心'),
      UI.el('button', { class: 'btn btn-danger btn-sm', onclick: async () => { await API.post('/api/restart'); UI.toast('已重启', 'ok'); } }, '重启服务'),
      UI.el('button', { class: 'btn btn-success btn-sm', onclick: async () => {
        try {
          const full = await API.get('/api/config');
          const port = full.proxy.ui_port || '9090';
          const path = (full.proxy.ui_path || 'ui').replace(/^\/+|\/+$/g, '');
          const host = location.hostname;
          window.open('http://' + host + ':' + port + '/' + path + '/', '_blank');
        } catch (e) { UI.toast('获取配置失败', 'err'); }
      } }, '打开UI面板')
    ))
  );
  statusCard.appendChild(sRow);
  c.appendChild(statusCard);

  // 基本配置
  const basic = UI.el('div', { class: 'card' });
  basic.appendChild(UI.el('div', { class: 'card-title' }, '基本配置'));
  const profSel = UI.el('select', {});
  profSel.appendChild(UI.el('option', { value: '' }, '-- 请选择 --'));
  profiles.forEach(p => profSel.appendChild(UI.el('option', { value: p.name }, p.name)));
  profSel.value = local.config.profile || '';
  basic.appendChild(UI.field('启用', UI.toggle(local.config.enabled, v => local.config.enabled = v)));
  basic.appendChild(UI.field('选择配置文件', profSel, '从「配置文件」页面上传'));
  profSel.addEventListener('change', () => local.config.profile = profSel.value);
  const binI = UI.input('text', local.config.run_binary, '例：/usr/bin/sing-box');
  binI.addEventListener('input', () => local.config.run_binary = binI.value);
  basic.appendChild(UI.field('可执行文件路径', binI));
  const argsI = UI.input('text', local.config.run_args, '例：-D /etc/nexa/run run --disable-color');
  argsI.addEventListener('input', () => local.config.run_args = argsI.value);
  basic.appendChild(UI.field('启动参数', argsI));
  const delayI = UI.input('number', local.config.start_delay, '0');
  delayI.addEventListener('input', () => local.config.start_delay = +delayI.value || 0);
  basic.appendChild(UI.field('延迟启动（秒）', delayI));
  basic.appendChild(UI.field('定时重启', UI.toggle(local.config.scheduled_restart, v => local.config.scheduled_restart = v)));
  const cronI = UI.input('text', local.config.scheduled_restart_cron, '0 3 * * *');
  cronI.addEventListener('input', () => local.config.scheduled_restart_cron = cronI.value);
  basic.appendChild(UI.field('定时重启 Cron 表达式', cronI));
  c.appendChild(basic);

  // 保存按钮
  const saveBar = UI.el('div', { class: 'flex-between' });
  const actions = UI.el('div', { class: 'right-actions' });
  const saveOnlyBtn = UI.el('button', { class: 'btn btn-outline' }, '保存');
  saveOnlyBtn.addEventListener('click', async () => {
    saveOnlyBtn.disabled = true; saveOnlyBtn.textContent = '保存中...';
    try {
      await API.put('/api/config', local);
      UI.toast('已保存', 'ok');
    } catch (e) { UI.toast('保存失败：' + e.message, 'err'); }
    saveOnlyBtn.disabled = false; saveOnlyBtn.textContent = '保存';
  });
  const saveBtn = UI.el('button', { class: 'btn btn-primary' }, '保存并应用');
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true; saveBtn.textContent = '应用中...';
    try {
      await API.post('/api/config/apply', local);
      UI.toast('已保存并应用，正在刷新...', 'ok');
      setTimeout(() => location.reload(), 600);
    } catch (e) { UI.toast('保存失败：' + e.message, 'err'); saveBtn.disabled = false; saveBtn.textContent = '保存并应用'; }
  });
  actions.appendChild(saveOnlyBtn);
  actions.appendChild(saveBtn);
  saveBar.appendChild(actions);
  c.appendChild(saveBar);

  // 更新状态
  (async () => {
    const st = await API.get('/api/status');
    const box = document.getElementById('app-status-box');
    if (box) box.innerHTML = '';
    if (box) box.appendChild(UI.el('span', { class: 'status-pill ' + (st.running ? 'running' : 'stopped') },
      UI.el('span', { class: 'dot' }), st.running ? '运行中 (PID ' + st.pid + ')' : '未运行'));
  })();
});

// ── 页面：配置文件 (profile.js) ─────
route('#/profile', async (c) => {
  const profiles = await API.get('/api/profiles');
  c.innerHTML = '';
  const card = UI.el('div', { class: 'card' });
  card.appendChild(UI.el('div', { class: 'card-title' }, '配置文件列表'));
  if (!profiles.length) {
    card.appendChild(UI.el('div', { class: 'empty' }, '暂无配置文件，请上传'));
  } else {
    const tbl = UI.el('table', { class: 'table' });
    tbl.appendChild(UI.el('tr', {},
      UI.el('th', {}, '文件名'), UI.el('th', {}, '修改时间'), UI.el('th', {}, '大小'), UI.el('th', {}, '操作')));
    profiles.forEach(p => {
      const tr = UI.el('tr', {},
        UI.el('td', {}, p.name),
        UI.el('td', {}, new Date(p.mtime * 1000).toLocaleString('zh-CN')),
        UI.el('td', {}, (p.size / 1024).toFixed(1) + ' KB'),
        UI.el('td', { class: 'actions' },
          UI.el('button', { class: 'btn btn-outline btn-sm', onclick: async () => {
            const blob = await API.raw('/api/profiles/' + encodeURIComponent(p.name));
            const url = URL.createObjectURL(await blob.blob());
            const a = document.createElement('a');
            a.href = url; a.download = p.name; a.click();
            URL.revokeObjectURL(url);
          } }, '下载'),
          UI.el('button', { class: 'btn btn-danger btn-sm', onclick: async () => {
            if (!confirm('确定删除 ' + p.name + '？')) return;
            await API.del('/api/profiles/' + encodeURIComponent(p.name));
            UI.toast('已删除', 'ok'); router();
          } }, '删除')
        ));
      tbl.appendChild(tr);
    });
    card.appendChild(tbl);
  }
  c.appendChild(card);

  // 上传
  const up = UI.el('div', { class: 'card' });
  up.appendChild(UI.el('div', { class: 'card-title' }, '上传配置文件'));
  const fileI = UI.el('input', { type: 'file' });
  const upBtn = UI.el('button', { class: 'btn btn-primary' }, '上传');
  const status = UI.el('div', { class: 'muted mt-12' });
  upBtn.addEventListener('click', async () => {
    const f = fileI.files[0]; if (!f) { UI.toast('请选择文件', 'err'); return; }
    status.textContent = '上传中：' + f.name + ' ...';
    const r = await API.raw('/api/profiles?name=' + encodeURIComponent(f.name), { method: 'POST', body: f, headers: { Authorization: 'Bearer ' + localStorage.getItem('nexa_token') } });
    if (r.ok) { UI.toast('上传成功', 'ok'); router(); }
    else { status.textContent = '上传失败'; UI.toast('上传失败', 'err'); }
  });
  up.appendChild(fileI); up.appendChild(UI.el('div', { class: 'mt-12' }, upBtn)); up.appendChild(status);
  c.appendChild(up);
});

// ── 页面：代理配置 (proxy.js) ───────
route('#/proxy', async (c) => {
  // 并行加载：配置、本机标识符（用户/组/cgroup）、局域网主机（IP/IP6/MAC）
  const [cfg, ids, hostInfo] = await Promise.all([
    API.get('/api/config'),
    API.get('/api/identifiers'),
    API.get('/api/hosts').catch(() => ({ ip: [], ip6: [], mac: [], list: [] })),
  ]);
  const p = JSON.parse(JSON.stringify(cfg.proxy));
  const local = { proxy: p, router: cfg.router_access_controls || [], lan: cfg.lan_access_controls || [], routing: cfg.routing, log: cfg.log };
  const users = ids.users || [], groups = ids.groups || [], cgroups = ids.cgroups || [];
  const hostIPs = hostInfo.ip || [], hostIP6s = hostInfo.ip6 || [], hostMACs = hostInfo.mac || [];
  const osType = ids.os_type || 'linux';
  const cgroupHint = osType === 'openwrt' ? '例：services/dnsmasq' : '例：system.slice/sshd.service';

  c.innerHTML = '';
  const card = UI.el('div', { class: 'card' });
  const tabs = ['基本设置', '端口与设备', '本机代理', '局域网代理', '绕过'];
  let active = 0;
  const tabWrap = UI.el('div', { class: 'tabs' });
  const body = UI.el('div', { class: 'mt-16' });
  const renderTabs = () => {
    tabWrap.innerHTML = '';
    tabs.forEach((t, i) => tabWrap.appendChild(UI.el('div', { class: 'tab' + (i === active ? ' active' : ''), onclick: () => { active = i; renderTabs(); renderBody(); } }, t)));
  };
  const renderBody = () => {
    body.innerHTML = '';
    if (active === 0) renderBasic(body);
    else if (active === 1) renderPorts(body);
    else if (active === 2) renderRouter(body);
    else if (active === 3) renderLan(body);
    else if (active === 4) renderMisc(body);
  };
  card.appendChild(tabWrap); card.appendChild(body);
  c.appendChild(card);

  // 基本
  function renderBasic(b) {
    const mk = (label, key, hint) => {
      const t = UI.toggle(p[key], v => p[key] = v);
      return UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, label), t);
    };
    b.appendChild(mk('启用代理', 'enabled'));
    b.appendChild(mk('IPv4 DNS 劫持', 'ipv4_dns_hijack'));
    b.appendChild(mk('IPv6 DNS 劫持', 'ipv6_dns_hijack'));
    b.appendChild(mk('IPv4 代理', 'ipv4_proxy'));
    b.appendChild(mk('IPv6 代理', 'ipv6_proxy'));
    b.appendChild(mk('Fake-IP Ping 劫持', 'fake_ip_ping_hijack'));
    const tcpSel = UI.el('select', {});
    ['redirect', 'tproxy', 'tun'].forEach(m => tcpSel.appendChild(UI.el('option', { value: m }, m)));
    tcpSel.value = p.tcp_mode; tcpSel.addEventListener('change', () => p.tcp_mode = tcpSel.value);
    b.appendChild(UI.field('TCP 代理模式', tcpSel));
    const udpSel = UI.el('select', {});
    ['redirect', 'tproxy', 'tun'].forEach(m => udpSel.appendChild(UI.el('option', { value: m }, m)));
    udpSel.value = p.udp_mode; udpSel.addEventListener('change', () => p.udp_mode = udpSel.value);
    b.appendChild(UI.field('UDP 代理模式', udpSel));
  }
  // 端口
  function renderPorts(b) {
    const mk = (label, key, ph, hint) => {
      const i = UI.input('text', p[key], ph); i.addEventListener('input', () => p[key] = i.value);
      return UI.field(label, i, hint);
    };
    const g = UI.el('div', { class: 'grid-2' });
    g.appendChild(mk('DNS 监听端口', 'dns_port', '例：1053', '代理核心监听 DNS 请求的端口'));
    g.appendChild(mk('Redirect 端口', 'redir_port', '例：7892'));
    g.appendChild(mk('TPROXY 端口', 'tproxy_port', '例：7893'));
    g.appendChild(mk('TUN 设备名', 'tun_device', '例：tun0'));
    g.appendChild(mk('UI 端口', 'ui_port', '例：9090'));
    g.appendChild(mk('UI 路径', 'ui_path', '例：ui'));
    g.appendChild(mk('Fake-IP IPv4 地址段', 'fake_ip_range', '例：198.18.0.0/15'));
    g.appendChild(mk('Fake-IP IPv6 地址段', 'fake_ip6_range', '例：fc00::/18'));
    b.appendChild(g);
    const tto = UI.input('number', p.tun_timeout, '30'); tto.addEventListener('input', () => p.tun_timeout = +tto.value || 30);
    const tin = UI.input('number', p.tun_interval, '1'); tin.addEventListener('input', () => p.tun_interval = +tin.value || 1);
    b.appendChild(UI.el('div', { class: 'grid-2 mt-16' },
      UI.field('TUN 设备等待超时（秒）', tto), UI.field('TUN 等待检测间隔（秒）', tin)));
  }
  // 本机代理
  function renderRouter(b) {
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, '启用本机代理'),
      UI.toggle(p.router_proxy, v => p.router_proxy = v)));
    local.router.forEach((ac, idx) => b.appendChild(acCard(ac, 'router', idx, () => local.router.splice(idx, 1))));
    const addBtn = UI.el('button', { class: 'btn btn-outline btn-sm', onclick: () => {
      local.router.push({ id: 'r' + Date.now(), enabled: true, user: [], group: [], cgroup: [], dns: true, proxy: true });
      renderBody();
    } }, '+ 添加规则');
    b.appendChild(addBtn);
  }
  function acCard(ac, type, idx, ondel) {
    const card = UI.el('div', { class: 'ac-row' });
    card.appendChild(UI.el('div', { class: 'row-head' },
      UI.el('div', { class: 'row-gap' }, UI.toggle(ac.enabled, v => ac.enabled = v), UI.el('span', { class: 'label-txt' }, '启用')),
      UI.el('div', { class: 'row-gap' },
        UI.toggle(ac.dns, v => ac.dns = v), UI.el('span', { class: 'muted' }, 'DNS'),
        UI.toggle(ac.proxy, v => ac.proxy = v), UI.el('span', { class: 'muted' }, '代理'),
        UI.el('button', { class: 'btn btn-danger btn-sm', onclick: () => { ondel(); renderBody(); } }, '删除')
      )
    ));
    if (type === 'router') {
      card.appendChild(UI.el('div', { class: 'row-fields' },
        UI.el('div', {}, UI.el('label', {}, '用户'), dynList(ac.user, users)),
        UI.el('div', {}, UI.el('label', {}, '用户组'), dynList(ac.group, groups)),
        UI.el('div', {}, UI.el('label', {}, 'CGroup'), dynList(ac.cgroup, cgroups), UI.el('div', { class: 'hint' }, cgroupHint))
      ));
    } else {
      card.appendChild(UI.el('div', { class: 'row-fields' },
        UI.el('div', {}, UI.el('label', {}, 'IP'), dynList(ac.ip || (ac.ip = []), hostIPs)),
        UI.el('div', {}, UI.el('label', {}, 'IPv6'), dynList(ac.ip6 || (ac.ip6 = []), hostIP6s)),
        UI.el('div', {}, UI.el('label', {}, 'MAC'), dynList(ac.mac || (ac.mac = []), hostMACs))
      ));
    }
    return card;
  }
  // 局域网代理
  function renderLan(b) {
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, '启用局域网代理'),
      UI.toggle(p.lan_proxy, v => p.lan_proxy = v)));
    const ifaceWrap = UI.el('div', { class: 'field' });
    ifaceWrap.appendChild(UI.el('label', {}, '入站接口（设备名，如 br-lan）'));
    ifaceWrap.appendChild(dynList(p.lan_inbound_interface || (p.lan_inbound_interface = [])));
    b.appendChild(ifaceWrap);
    local.lan.forEach((ac, idx) => b.appendChild(acCard(ac, 'lan', idx, () => local.lan.splice(idx, 1))));
    b.appendChild(UI.el('button', { class: 'btn btn-outline btn-sm', onclick: () => {
      local.lan.push({ id: 'l' + Date.now(), enabled: true, ip: [], ip6: [], mac: [], dns: true, proxy: true });
      renderBody();
    } }, '+ 添加规则'));
  }
  // 绕过
  function renderMisc(b) {
    b.appendChild(UI.el('div', { class: 'section-title' }, '回环绕过'));
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, 'CGroup 绕过'), UI.toggle(p.bypass_cgroup, v => p.bypass_cgroup = v)));
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, 'GID 绕过'), UI.toggle(p.bypass_gid, v => p.bypass_gid = v)));
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, 'Mark 绕过'), UI.toggle(p.bypass_mark, v => p.bypass_mark = v)));
    if (p.bypass_mark) {
      b.appendChild(UI.el('div', { class: 'field' }, UI.el('label', {}, 'Mark 值（支持多个，如 0x1/0xff）'), dynList(p.bypass_mark_values || (p.bypass_mark_values = []))));
    }
    b.appendChild(UI.el('div', { class: 'section-title mt-20' }, '地址绕过'));
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, '绕过中国大陆 IPv4'),
      UI.toggle(p.bypass_china_mainland_ip, v => p.bypass_china_mainland_ip = v)));
    b.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, '绕过中国大陆 IPv6'),
      UI.toggle(p.bypass_china_mainland_ip6, v => p.bypass_china_mainland_ip6 = v)));
    b.appendChild(UI.el('div', { class: 'field' }, UI.el('label', {}, '保留 IPv4 地址段'), dynList(p.reserved_ip || (p.reserved_ip = []))));
    b.appendChild(UI.el('div', { class: 'field' }, UI.el('label', {}, '保留 IPv6 地址段'), dynList(p.reserved_ip6 || (p.reserved_ip6 = []))));
    b.appendChild(UI.el('div', { class: 'section-title mt-20' }, '端口与标记绕过'));
    const g = UI.el('div', { class: 'grid-2' });
    const tcp = UI.input('text', p.proxy_tcp_dport, '0-65535'); tcp.addEventListener('input', () => p.proxy_tcp_dport = tcp.value);
    const udp = UI.input('text', p.proxy_udp_dport, '0-65535'); udp.addEventListener('input', () => p.proxy_udp_dport = udp.value);
    g.appendChild(UI.field('代理 TCP 目标端口范围', tcp));
    g.appendChild(UI.field('代理 UDP 目标端口范围', udp));
    b.appendChild(g);
    b.appendChild(UI.el('div', { class: 'field' }, UI.el('label', {}, '绕过 DSCP 标记'), dynList(p.bypass_dscp || (p.bypass_dscp = []))));
    b.appendChild(UI.el('div', { class: 'field' }, UI.el('label', {}, '绕过 Fwmark 标记'), dynList(p.bypass_fwmark || (p.bypass_fwmark = []))));
  }

  renderTabs(); renderBody();

  // 保存
  const saveBar = UI.el('div', { class: 'flex-between mt-20' });
  const actions = UI.el('div', { class: 'right-actions' });
  const saveOnlyBtn = UI.el('button', { class: 'btn btn-outline' }, '保存');
  saveOnlyBtn.addEventListener('click', async () => {
    saveOnlyBtn.disabled = true; saveOnlyBtn.textContent = '保存中...';
    try {
      const full = await API.get('/api/config');
      full.proxy = local.proxy;
      full.router_access_controls = local.router;
      full.lan_access_controls = local.lan;
      full.routing = local.routing;
      full.log = local.log;
      await API.put('/api/config', full);
      UI.toast('已保存', 'ok');
    } catch (e) { UI.toast('保存失败：' + e.message, 'err'); }
    saveOnlyBtn.disabled = false; saveOnlyBtn.textContent = '保存';
  });
  const saveBtn = UI.el('button', { class: 'btn btn-primary' }, '保存并应用');
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true; saveBtn.textContent = '应用中...';
    try {
      const full = await API.get('/api/config');
      full.proxy = local.proxy;
      full.router_access_controls = local.router;
      full.lan_access_controls = local.lan;
      full.routing = local.routing;
      full.log = local.log;
      await API.post('/api/config/apply', full);
      UI.toast('已保存并应用，正在刷新...', 'ok');
      setTimeout(() => location.reload(), 600);
    } catch (e) { UI.toast('保存失败：' + e.message, 'err'); saveBtn.disabled = false; saveBtn.textContent = '保存并应用'; }
  });
  actions.appendChild(saveOnlyBtn);
  actions.appendChild(saveBtn);
  saveBar.appendChild(actions);
  c.appendChild(saveBar);
});

// ── 页面：编辑器 (editor.js) ────────
route('#/editor', async (c) => {
  const profiles = await API.get('/api/profiles');
  c.innerHTML = '';
  const card = UI.el('div', { class: 'card' });
  card.appendChild(UI.el('div', { class: 'card-title' }, '配置文件编辑器'));
  const sel = UI.el('select', {});
  sel.appendChild(UI.el('option', { value: '' }, '-- 选择文件 --'));
  profiles.forEach(p => sel.appendChild(UI.el('option', { value: p.name }, p.name)));
  // 语言选择
  const langSel = UI.el('select', {});
  [['text', '纯文本'], ['json', 'JSON'], ['yaml', 'YAML']].forEach(([v, l]) => langSel.appendChild(UI.el('option', { value: v }, l)));
  const ed = codeEditor('text');
  let current = '';
  sel.addEventListener('change', async () => {
    current = sel.value; if (!current) { ed.set(''); return; }
    ed.set('加载中...');
    const r = await API.raw('/api/profiles/' + encodeURIComponent(current), { headers: { Authorization: 'Bearer ' + localStorage.getItem('nexa_token') } });
    const text = await r.text();
    // 根据扩展名自动选择语言
    let lang = detectLang(current);
    if (!lang) {
      const t = text.trim();
      if (t[0] === '{' || t[0] === '[') lang = 'json';
      else lang = 'yaml';
    }
    ed.setLang(lang);
    langSel.value = lang;
    ed.set(text);
  });
  langSel.addEventListener('change', () => ed.setLang(langSel.value));
  card.appendChild(UI.el('div', { class: 'grid-2' },
    UI.field('选择文件', sel), UI.field('语法高亮', langSel)));
  card.appendChild(ed.el);
  const bar = UI.el('div', { class: 'row-gap mt-16' });
  const saveBtn = UI.el('button', { class: 'btn btn-primary' }, '保存');
  saveBtn.addEventListener('click', async () => {
    if (!current) { UI.toast('请先选择文件', 'err'); return; }
    await API.put('/api/profiles/' + encodeURIComponent(current), ed.get());
    UI.toast('已保存', 'ok');
  });
  const applyBtn = UI.el('button', { class: 'btn btn-primary' }, '保存并应用');
  applyBtn.addEventListener('click', async () => {
    if (!current) return;
    applyBtn.disabled = true; applyBtn.textContent = '应用中...';
    try {
      await API.put('/api/profiles/' + encodeURIComponent(current), ed.get());
      await API.post('/api/config/apply', await API.get('/api/config'));
      UI.toast('已保存并应用，正在刷新...', 'ok');
      setTimeout(() => location.reload(), 600);
    } catch (e) { UI.toast('保存失败：' + e.message, 'err'); }
    applyBtn.disabled = false; applyBtn.textContent = '保存并应用';
  });
  bar.appendChild(saveBtn); bar.appendChild(applyBtn);
  card.appendChild(bar);
  c.appendChild(card);
});

// ── 页面：日志 (log.js) ─────────────
route('#/log', async (c) => {
  const cfg = await API.get('/api/config');
  const local = JSON.parse(JSON.stringify(cfg.log));
  c.innerHTML = '';

  // 日志配置
  const cfgCard = UI.el('div', { class: 'card' });
  cfgCard.appendChild(UI.el('div', { class: 'card-title' }, '日志配置'));
  cfgCard.appendChild(UI.el('div', { class: 'toggle-row' }, UI.el('span', { class: 'label-txt' }, '定时清理'),
    UI.toggle(local.scheduled_clear, v => local.scheduled_clear = v)));
  const cronI = UI.input('text', local.scheduled_clear_cron, '*/5 * * * *');
  cronI.addEventListener('input', () => local.scheduled_clear_cron = cronI.value);
  cfgCard.appendChild(UI.field('清理 Cron 表达式', cronI));
  const limitI = UI.input('number', local.scheduled_clear_size_limit, '1');
  limitI.addEventListener('input', () => local.scheduled_clear_size_limit = +limitI.value || 1);
  const unitSel = UI.el('select', {});
  ['KB', 'MB', 'GB'].forEach(u => unitSel.appendChild(UI.el('option', { value: u }, u)));
  unitSel.value = local.scheduled_clear_size_limit_unit;
  unitSel.addEventListener('change', () => local.scheduled_clear_size_limit_unit = unitSel.value);
  cfgCard.appendChild(UI.el('div', { class: 'grid-2' },
    UI.field('大小限制', limitI), UI.field('单位', unitSel)));
  const saveLogBtn = UI.el('button', { class: 'btn btn-primary btn-sm' }, '保存配置');
  saveLogBtn.addEventListener('click', async () => {
    const full = await API.get('/api/config'); full.log = local;
    await API.put('/api/config', full); UI.toast('已保存', 'ok');
  });
  cfgCard.appendChild(saveLogBtn);
  c.appendChild(cfgCard);

  // 面板日志
  const appCard = UI.el('div', { class: 'card' });
  appCard.appendChild(UI.el('div', { class: 'card-title' }, '面板日志',
    UI.el('div', { class: 'row-gap' },
      UI.el('button', { class: 'btn btn-outline btn-sm', onclick: () => {
        const b = document.getElementById('app-log');
        copyText(b.textContent);
      } }, '复制'),
      UI.el('button', { class: 'btn btn-danger btn-sm', onclick: async () => { await API.post('/api/logs/app/clear'); loadApp(); } }, '清空'),
      UI.el('button', { class: 'btn btn-outline btn-sm', onclick: () => { const b = document.getElementById('app-log'); b.scrollTop = b.scrollHeight; } }, '滚到底部')
    )));
  const appBox = UI.el('div', { class: 'log-box', id: 'app-log' });
  appCard.appendChild(appBox);
  c.appendChild(appCard);

  // 核心日志
  const coreCard = UI.el('div', { class: 'card' });
  coreCard.appendChild(UI.el('div', { class: 'card-title' }, '核心日志',
    UI.el('div', { class: 'row-gap' },
      UI.el('button', { class: 'btn btn-outline btn-sm', onclick: () => {
        const b = document.getElementById('core-log');
        copyText(b.textContent);
      } }, '复制'),
      UI.el('button', { class: 'btn btn-danger btn-sm', onclick: async () => { await API.post('/api/logs/core/clear'); loadCore(); } }, '清空'),
      UI.el('button', { class: 'btn btn-outline btn-sm', onclick: () => { const b = document.getElementById('core-log'); b.scrollTop = b.scrollHeight; } }, '滚到底部')
    )));
  const coreBox = UI.el('div', { class: 'log-box', id: 'core-log' });
  coreCard.appendChild(coreBox);
  c.appendChild(coreCard);

  async function loadApp() {
    const log = await API.get('/api/logs/app');
    appBox.textContent = typeof log === 'string' ? log : '';
    appBox.scrollTop = appBox.scrollHeight;
  }
  await loadApp();

  async function loadCore() {
    const log = await API.get('/api/logs/core');
    coreBox.textContent = typeof log === 'string' ? log : '';
    coreBox.scrollTop = coreBox.scrollHeight;
  }
  await loadCore();

  // 轮询日志
  const pollApp = setInterval(loadApp, 3000);
  const pollCore = setInterval(loadCore, 3000);

  // 离开页面时清理
  window.__logCleanup = () => { clearInterval(pollApp); clearInterval(pollCore); };
});

// ── 页面：设置 ─────────────────────
route('#/settings', async (c) => {
  c.innerHTML = '';
  const card = UI.el('div', { class: 'card' });
  card.appendChild(UI.el('div', { class: 'card-title' }, '用户设置'));
  card.appendChild(UI.el('div', { class: 'card-desc' }, '修改登录账号的用户名和密码'));

  const userI = UI.input('text', 'admin', '用户名');
  const passI = UI.input('password', '', '新密码');
  const pass2I = UI.input('password', '', '确认新密码');
  card.appendChild(UI.field('用户名', userI));
  card.appendChild(UI.field('新密码', passI, '留空则不修改密码'));
  card.appendChild(UI.field('确认新密码', pass2I));

  const saveBtn = UI.el('button', { class: 'btn btn-primary' }, '保存');
  saveBtn.addEventListener('click', async () => {
    if (!userI.value) { UI.toast('用户名不能为空', 'err'); return; }
    if (passI.value && passI.value !== pass2I.value) { UI.toast('两次密码不一致', 'err'); return; }
    if (!passI.value) { UI.toast('请输入新密码', 'err'); return; }
    saveBtn.disabled = true; saveBtn.textContent = '保存中...';
    try {
      await API.put('/api/auth/password', { username: userI.value, password: passI.value });
      UI.toast('用户数据已保存，请重新登录', 'ok');
      setTimeout(() => { localStorage.removeItem('nexa_token'); location.hash = '#/login'; }, 800);
    } catch (e) { UI.toast('保存失败：' + e.message, 'err'); }
    saveBtn.disabled = false; saveBtn.textContent = '保存';
  });
  card.appendChild(UI.el('div', { class: 'mt-20' }, saveBtn));
  c.appendChild(card);
});

// 每次路由前清理上一页的资源
let lastHash = null;
window.addEventListener('hashchange', () => {
  if (window.__logCleanup && lastHash === '#/log') { window.__logCleanup(); window.__logCleanup = null; }
  lastHash = location.hash;
});

router();
