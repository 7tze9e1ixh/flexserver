#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: sudo $0 <interface>"
    exit 1
fi

interface=$1

sudo python3 ./script/dpdk-hugepages.py -p 2M --setup 16G
sudo ifconfig ${interface} 10.0.30.118/24 up
