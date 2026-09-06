#!/bin/sh
/etc/init.d/nexa enable
/etc/init.d/nexa start
sleep 1
/etc/init.d/rpcd reload
exit 0
