#!/bin/bash

# At Server
python3 ./script/dpdk-hugepages.py -p 2M --setup 64G
ifconfig ens5f0np0 10.0.30.110/24 up
ifconfig ens5f1np1 10.0.31.110/24 up
sysctl -w net.ipv4.tcp_congestion_control="reno"
sysctl -w net.ipv4.tcp_no_metrics_save=0
#sysctl -w net.core.wmem_default=3145728
#sysctl -w net.core.wmem_max=3145728
sysctl -w net.core.wmem_default=6291456
sysctl -w net.core.wmem_max=6291456
sysctl -w net.ipv4.ip_local_port_range="1500 65535"
sysctl -p
ethtool -G ens5f0np0 rx 8192
ethtool -G ens5f0np0 tx 8192
ethtool -G ens5f1np1 rx 8192
ethtool -G ens5f1np1 tx 8192
