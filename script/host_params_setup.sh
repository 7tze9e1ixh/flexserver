#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: sudo $0 <interface>"
    exit 1
fi

interface=$1

# At Server
python3 ./script/dpdk-hugepages.py -p 2M --setup 64G
ifconfig ${interface} 10.0.30.110/24 up
sysctl -w net.ipv4.tcp_congestion_control="reno"
sysctl -w net.ipv4.tcp_no_metrics_save=0
#sysctl -w net.core.wmem_default=3145728
#sysctl -w net.core.wmem_max=3145728
sysctl -w net.core.wmem_default=10485760 #3145728 #6291456
sysctl -w net.core.wmem_max=10485760 #3145728 #6291456
sysctl -w net.ipv4.ip_local_port_range="1500 65535"
sysctl -p
ethtool -G ${interface} rx 8192
ethtool -G ${interface} tx 8192
