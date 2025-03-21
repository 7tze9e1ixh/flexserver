# Flexserver
Flexserver is a high performance content server which supports 400 Gbps NIC.
It combines an user level TCP stack mTCP with io_uring and it utilize host and smartnic memory as caches.

## Table of Contents

1. [Structure](#Structure-of-Flexserver)
2. [Installation](#Installation)
3. [How to Build](#How-to-Build)
4. [Configurations](#Configurations)
5. [Run Flexserver](#Run-Flexserver)
6. [Run Client](#Run-Client)


## Structure of Flexserver

<details>
<summary> Structure of flexserver (click to expand) </summary>

```sh
flexserver/
│
├── apps/
│   └── lighttpd-1.4.32/src
│       ├── server.c
│       ├── network_mtcp_sendfile.c
│       └── config/
│           ├── arp.conf
│           ├── route.conf
│           ├── dpu_macaddr.conf
│           ├── mtcp.conf
│           ├── m-lighttpd.conf
│           └── control_plane.cfg
│
├── mtcp/src
│   ├── api.c
│   ├── core.c          // mtcp main loop
│   ├── flex_buffer.c
│   ├── nic_cache.c
│   ├── frd_liburing.c
│   └── dpdk_module.c 
│
├── control_plane/src
│   ├── core.c
│   └── cache.c
│
├── data_plane/
│   ├── dataplane.c     // dataplane main loop
│   ├── dpdk_io.c
│   ├── frd_offload.c
│   └── dataplane.cfg
│
└── README.md
```

</details>

- mtcp
    - mtcp runs on the host. Network processes, file reads, and flow management are handled here.

- Control plane
    - Control plane runs on the host that controls the cache. It finds where the data is(disk, host memory, or smartnic memory). It also selects which data will be offloaded or evicted on the cache.

- Data plane
    - Data plane runs on the smartnic. It receives the file url and method(OFFLOAD, EVICT, TX_CACHE, or TX_DISK) from the host.

## Installation
```sh
git clone <flexserver-repo>
```

### Host Installation
- System settings
    - We recommand you to use linux 5.13. Below is our experimental environment.
    ```sh
    Ubuntu 20.04
    Linux 5.13.0-52-generic
    DPDK 22.11.10 
    DOCA 2.5.2
    OFED.23.10.2
    ```
    - install OFED with --with-nvmf flag to use nvme-of.

- Control Plane
    - We used xxHash_082
    ```sh
    git clone https://github.com/Cyan4973/xxHash.git
    cd <cloned-dir>
    make -j
    sudo make install
    ```

- IO-uring
    - We used liburing_2.6 both host and SmartNIC
    ```sh
    git clone https://github.com/axboe/liburing.git
	cd <cloned-dir>
	make -j
	sudo make install
    ```

### NIC Installation
- System setting
    ```sh
    DOCA 2.8
    Using DPDK included at DOCA 2.8
    ```

- IO-uring
    - We used liburing_2.6 both host and SmartNIC
    ```sh
    git clone https://github.com/axboe/liburing.git
    cd <cloned-dir>
    make -j
    make install
    ```

- Mode of DPU
	- We need to use separated host mode.
	```sh
	(host)
	sudo mst start
	sudo mlxconfig -d /dev/mst/<device> s INTERNAL_CPU_MODEL=0
	sudo shutdown -h now
	(dpu)
	sudo ovs-vsctl list-br | xargs -r -l ovs-vsctl del-br
	```

## How to Build
### Host side
- mtcp
	- If you are having trouble building mTCP, please refer to [this](https://github.com/mtcp-stack/mtcp).
    ```sh
	sudo apt install libgmp3-dev libnuma-dev
	cp control_plane/include/control_plane.h mtcp/src/include
    cd mtcp/src
	change the line 133 of Makefile with your local path.
    make -j
    ```

- control plane
    ```sh
    cd control_plane
    meson setup build --optimization=3
    cd build
    sudo ninja install
    ```

- Lighttpd
    ```sh
    cd apps/lighttpd-1.4.32
    ./configure --without-bzip2 CFLAGS="-g -msse3" \
        --with-libmtcp=<flexserver-dir>/mtcp \
        --with-libdpdk=yes \ 
        --with-libcpclnt=<flexserver-dir>/control_plane
    cd src
    make -j
    ```

### NIC side
- dataplane
    ```sh
    cd data_plane
    meson setup build
    cd build
    ninja
    ```

## Configurations
### Madatory configurations
You should complete this configuration if you first run the flexserver

- Lighttpd, mtcp configuration : in lighttps src directory
    - DPU ARM MAC Address : `config/dpu_macaddr.conf`
    - Client Address
        - `config/arp.conf`
        - `config/route.conf`
    - Cache configuration : `config/control_plane.cfg`
        - `max nic cache memory size(GB)` : L1\_Cache size
        - `l2cache size` : L2\_Cache size
        - `dir_path` : Monitored directory path
    - mtcp, lighttpd
        - `config/mtcp.conf`
        - `config/m-lighttpd.conf`

- control_plane.cfg
    1. `number of cpus`: the number of cpu cores for control plane, not for mtcp, we use 1 core.
    2. `max nic cache memory size (GB)`: if you set this 0.5, 0.5GB of memory will be used for nic(L1) cache.
    3. `max number of items`: size of item mempool (RTE_CACHE_LINE_SIZE * max_nb_items)
    4. `number of requests to optimize cache`: the cache is optimized every set number of requests.
    5. `number of offloaded items`: how many items to offload at one time?
    6. `hash power`: hash table bucket size. 14 means 1 << 14 buckets in hash table.
    7. `lcore id`: lcore_id of the cache optimizing thread
    8. `l2cache size (GB)`: size of host memory for L2 cache.

- dataplane configuration: dataplane.cfg in build directory
    - `total cache memory size (GB)` : ARM memory size for cache
    - `total number of cores` : ARM cores for dataplane
    - `host mac address` : Host mac address

### Optional Configurations
This is optional, and you should rebuild flexserver when you change these options.
- Using file read offloading
    It enables smartnic to read files from disks. You can use the smartnic cache without this feature.
    ```sh
    (arm) ENABLE_FRD_OFFLOAD=1        //meson.build
    (host) DISABLE_FRD_OFFLOAD 0      //nic_cache.h
    (host) FOC_LOG_FRD_OFFLOAD TRUE   //frd_offload_ctrl.h
    turn on command batching and turn off reply batching
    (arm) ENABLE_APP_HDR_BATCH TRUE   //dataplane.h if you want snic cache
    ```

- Using command batching
    If you want to batch the requests offloaded to smartnic by using this option.
    ```sh
    (host) ENABLE_META_BATCH=1        //Makefile
    (host) ENABLE_META_TX_QUEUE TRUE  //mtcp.h
    (host) ENABLE_APP_HDR_BATCH TRUE  //mtcp.h
    ```

- Using reply batching
    If you want to batch the response from smartNIC to host by using this option.
    ```sh
    (arm) ENABLE_REPLY_BATCH=1        //meson.build
    (arm) ENABLE_APP_HDR_BATCH TRUE   //dataplane.h
    ```

- Change the mode of I/O
    - SQ Poll mode
		- Default mode of io-uring is interrupt mode. You can use the sq poll mode of io-uring.
        ```sh
        (host) KERNEL_POLL_MODE TRUE      //frd_liburing.h
        ```
    - Posix read
        ```
        (host) frd_liburing.c -> frd_posix_read.c //Makefile
        ```


## Run Flexserver
### Environment setup
We provide scripts for network and nvme settings.
- Setting network interfaces and hugepages.
    ```sh
    (host) sudo ./script/host_params_setup.sh <interface>
    (snic) sudo ./script/arm_params_setup.sh <interface>

	(example) sudo ./script/host_params_setup.sh ens5f0np0
	(example) sudo ./script/arm_params_setup.sh p0
    ```

- NVMe-oF
    - We are using nvme-of-rdma. Show details in [HowTo Configure NVMe over Fabrics](https://enterprise-support.nvidia.com/s/article/howto-configure-nvme-over-fabrics#jive_content_id_NVME_Target_Configuration)
    ```sh
    (host) sudo ./script/nvme_of_host_setup.sh
    (snic) sudo ./script/nvme_of_arm_setup.sh
    ```

    ```sh
    (host) sudo ./script/host_mount.sh
    (snic) sudo ./script/arm_mount.sh
    ```

- Client Machine setup
    This is for benchmark
    ```sh
    sudo ./script/setup_client.sh <interface>
    ```

- run with snic cache
    ```sh
    (arm) cd build
    (arm) sudo ./dataplane

    (host) cd apps/lighttpd-1.4.32/src
    (host) sudo ./lighttpd -f config/m-lighttpd.conf -n <number of CPUs> -D
    # Wait until all cached files are offloaded.
    ```

- run without snic cache
    ```sh
    (host) cd apps/lighttpd-1.4.32/src
    (host) sudo ./lighttpd -f config/m-lighttpd.conf -n <number of CPUs> -D
    ```


## Run Client
We used dperf as a client to evaluate performance of Flexserver.
Install
```sh
git clone https://github.com/baidu/dperf.git
make -j
```

modify test/http/client_cps.conf in dperf directory.
Our setting is 
```sh
cpu 0-7
cps 0
cc=1000
keepalive 0ms
rss
fast_close
```

You need to change tcp_new_packet function in src/tcp.c if you want to request multiple files.

Run
```sh
sudo build/dperf -c test/http/client_cps.conf
```
