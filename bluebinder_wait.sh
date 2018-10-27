#!/bin/sh

while true
do
    bt_status=$(/usr/bin/getprop init.svc.bluetooth-1-0)
    if [ "$bt_status" = "running" ] ; then
        exit 0
    fi
    echo "Waiting for bluetooth service"
    sleep 1
done
exit 1
