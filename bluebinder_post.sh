#!/bin/sh

# Check for port provided script to populate the bluetooth address
if [ -x /usr/bin/droid/droid-get-bt-address.sh ] ; then
    /usr/bin/droid/droid-get-bt-address.sh
fi

# If the bluetooth address is provided by another script use that
if [ -f /var/lib/bluetooth/board-address ] ; then
    exit 0
fi

mkdir -p /var/lib/bluetooth

# Getting address file from properties
bt_addr_file=$(/usr/bin/getprop ro.bt.bdaddr_path)
if [ "$bt_addr_file" != "" ]; then
    if ! cp $bt_addr_file /var/lib/bluetooth/board-address; then
        echo "Failed to copy $bt_addr_file."
        exit 1
    fi
elif [ "$(getprop persist.vendor.service.bdroid.bdaddr)" != "" ]; then
    echo $(getprop persist.vendor.service.bdroid.bdaddr |awk -F: '{do printf "%s"(NF>1?FS:RS),$NF;while(--NF)}') > /var/lib/bluetooth/board-address
    if [ ! -f /var/lib/bluetooth/board-address ]; then
        echo "Failed to set bluetooth address."
        exit 1
    fi
else
    echo "Failed to get bluetooth address!"
    exit 1
fi

# Set proper permissions
chown root:root /var/lib/bluetooth/board-address
chmod 644 /var/lib/bluetooth/board-address
exit 0
