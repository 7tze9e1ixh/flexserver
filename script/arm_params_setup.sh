#!/bin/bash
sudo python3 ./script/dpdk-hugepages.py -p 2M --setup 16G
sudo ifconfig p0 10.0.30.118/24 up
