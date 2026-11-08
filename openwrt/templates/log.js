'use strict';
'require view';
'require rpc';
'require poll';

const callGetLog = rpc.declare({
    object: 'luci.nexa',
    method: 'get_log',
    expect: { '': {} }
});

return view.extend({
    render: function() {
        const logArea = E('pre', {
            'style': 'background:#fff; color:#333; padding:12px; ' +
                     'border:1px solid #ddd; border-radius:4px; ' +
                     'height:500px; overflow-y:auto; ' +
                     'font-size:12px; white-space:pre-wrap; word-break:break-all;'
        }, '加载中...');

        const clearBtn = E('button', {
            'class': 'btn cbi-button cbi-button-remove',
            'style': 'margin-bottom:8px;',
            'click': function() {
                logArea.textContent = '暂无日志';
            }
        }, '清空显示');

        poll.add(function() {
            return callGetLog().then(function(res) {
                logArea.textContent = (res && res.log) ? res.log.trim() : '暂无日志';
                logArea.scrollTop = logArea.scrollHeight;
            });
        }, 5);

        return E('div', { 'class': 'cbi-map' }, [
            E('div', { 'class': 'cbi-section' }, [
                E('div', { 'style': 'display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;' }, [
                    E('h3', { 'style': 'margin:0;' }, '运行日志'),
                    clearBtn
                ]),
                logArea
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
