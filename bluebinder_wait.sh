#!/bin/sh

# needed on some devices to get bluetooth functional
setprop persist.vendor.service.bdroid.sibs 0

while true
do
    bt_status=$(/usr/bin/getprop |grep "init.svc.*bluetooth" |grep -o "\[running\]")
    if [ "$bt_status" = "[running]" ] ; then
        # If the bluetooth address is provided by another script use that
        if [ -f /var/lib/bluetooth/board-address ] ; then
            exit 0
        fi
        # Getting address file from getprop
        bt_addr_file=$(/usr/bin/getprop ro.bt.bdaddr_path)
        if [ "$bt_addr_file" != "" ]; then
            mkdir -p /var/lib/bluetooth
            if ! cp $bt_addr_file /var/lib/bluetooth/board-address; then
                echo "Failed to copy $bt_addr_file."
                exit 1
            fi
            chown root:root /var/lib/bluetooth/board-address
            chmod 644 /var/lib/bluetooth/board-address
            exit 0
        else
            echo "Failed to get bluetooth address."
            exit 1
        fi
    fi
    echo "Waiting for bluetooth service"
    sleep 1
done
exit 1
