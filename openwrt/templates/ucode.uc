#!/usr/bin/ucode
'use strict';

import { popen } from 'fs';

const methods = {
    get_status: {
        call: function() {
            const fd = popen('pidof nexa >/dev/null 2>&1; echo $?');
            const ret = fd ? trim(fd.read('all')) : '1';
            if (fd) fd.close();
            return { running: ret === '0' };
        }
    },

    get_log: {
        call: function() {
            const fd = popen('logread 2>/dev/null | grep -i nexa | tail -200');
            const log = fd ? (fd.read('all') || '') : '';
            if (fd) fd.close();
            return { log };
        }
    }
};

return { 'luci.nexa': methods };
