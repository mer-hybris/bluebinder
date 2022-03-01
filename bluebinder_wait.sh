#!/bin/sh

while true
do
    bt_status=$(/usr/bin/getprop |grep "init.svc.*bluetooth\|init.svc.*bluetooth-1-0" | grep -o "\[running\]" | uniq)
    if [ "$bt_status" = "[running]" ] ; then
        echo "Bluetooth service running"
        exit 0
    fi
    echo "Waiting for bluetooth service"
    sleep 1
done
exit 1
