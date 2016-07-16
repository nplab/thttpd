#!/bin/sh
#
# thttpd.sh - startup script for thttpd on FreeBSD 3.x
#
# This goes in /usr/local/etc/rc.d and gets run at boot-time.

if [ -x /usr/local/sbin/thttpd_wrapper ] ; then
    echo -n " thttpd"
    /usr/local/sbin/thttpd_wrapper &
fi
