'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require uci';

const callGetStatus = rpc.declare({
    object: 'luci.nexa',
    method: 'get_status',
    expect: { '': {} }
});

return view.extend({
    load: function() {
        return uci.load('nexa');
    },

    render: function() {
        let m, s, o;
        m = new form.Map('nexa', 'Nexa', 'Nexa 代理服务管理');

        // ── 状态栏 ────────────────────────────────────────
        const statusSection = m.section(form.TypedSection);
        statusSection.render = function() {
            const statusEl = E('span', {
                'style': 'font-style:italic; font-weight:bold;'
            }, '检查中...');

            const openBtn = E('button', {
                'class': 'btn cbi-button',
                'style': 'margin-left:12px; padding:2px 12px; font-size:13px;',
                'click': function() {
                    const port = uci.get('nexa', 'main', 'port') || '9990';
                    window.open('http://' + window.location.hostname + ':' + port, '_blank');
                }
            }, '打开 Web 界面');

            poll.add(function() {
                return callGetStatus().then(function(res) {
                    const running = res && res.running;
                    statusEl.innerHTML = running
                        ? '<span style="color:#27ae60; font-style:italic; font-weight:bold;">Nexa 运行中</span>'
                        : '<span style="color:#e74c3c; font-style:italic; font-weight:bold;">Nexa 未运行</span>';
                });
            }, 5);

            return E('div', { 'class': 'cbi-section', 'style': 'padding:8px 0;' }, [
                E('div', { 'style': 'display:flex; align-items:center;' }, [
                    statusEl,
                    openBtn
                ])
            ]);
        };

        // ── 基本设置 ──────────────────────────────────────
        s = m.section(form.NamedSection, 'main', 'nexa', '基本设置');
        s.anonymous = true;
        s.addremove = false;

        o = s.option(form.Flag, 'enabled', '启用');
        o.default = o.disabled;
        o.rmempty = false;

        o = s.option(form.Value, 'port', '监听端口');
        o.datatype = 'port';
        o.placeholder = '9990';
        o.default = '9990';
        o.rmempty = false;

        return m.render();
    }
});
