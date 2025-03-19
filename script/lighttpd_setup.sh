#!/bin/bash

# At Server
ifconfig ens5f0np0 10.0.30.110/24 up
sysctl -w net.ipv4.tcp_congestion_control="reno"
sysctl -w net.ipv4.tcp_no_metrics_save=0
#sysctl -w net.core.wmem_default=3145728
#sysctl -w net.core.wmem_max=3145728
sysctl -w net.core.wmem_default=10485760 #3145728 #6291456
sysctl -w net.core.wmem_max=10485760 #3145728 #6291456
sysctl -w net.ipv4.ip_local_port_range="1500 65535"
sysctl -p
ethtool -G ens5f0np0 rx 8192
ethtool -G ens5f0np0 tx 8192
