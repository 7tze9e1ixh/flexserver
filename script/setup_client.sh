# At Client

if [ -z "$1" ]; then
    echo "Usage: sudo $0 <interface>"
    exit 1
fi

interface=$1

python3 ./script/dpdk-hugepages.py -p 1G --setup 96G
ifconfig ${interface} 10.0.30.120/24 up
sysctl -w net.core.netdev_max_backlog=250000000
sysctl -w net.core.rmem_default=10485760
sysctl -w net.core.rmem_max=10485760
sysctl -w net.ipv4.tcp_rmem=10485760
sysctl -w net.ipv4.udp_rmem_min=10485760
sysctl -w net.ipv4.ip_local_port_range="1500 65535"
sysctl -p
ethtool -G ${interface} rx 8192
ethtool -G ${interface} tx 8192
ethtool -K ${interface} lro on
#ulimit -n 65000 #for wrk

tc qdisc add dev ${interface} root netem delay 30ms limit 1800000000 
