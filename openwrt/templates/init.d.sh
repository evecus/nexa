#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=10

CONF="nexa"
PROG="/usr/bin/nexa"

start_service() {
    config_load "$CONF"

    local enabled
    config_get_bool enabled main enabled 0
    [ "$enabled" = "0" ] && return 0

    [ ! -x "$PROG" ] && logger -t nexa "binary not found: $PROG" && return 1

    local port
    config_get port main port '9990'

    procd_open_instance "$CONF"
    procd_set_param command "$PROG" -addr ":${port}"
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    return 0
}

service_triggers() {
    procd_add_reload_trigger "$CONF"
}
