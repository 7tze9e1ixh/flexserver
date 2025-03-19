modprobe -r nvme_rdma
modprobe -r nvme_fabrics
modprobe -r nvmet_rdma
modprobe -r nvmet
modprobe -r nvme_core
modprobe -r nvme

modprobe nvme num_p2p_queues=10

modprobe nvmet
modprobe nvmet-rdma


mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/attr_allow_any_host
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/attr_offload

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/1
echo -n /dev/nvme0n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/1/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/1/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/2
echo -n /dev/nvme1n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/2/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/2/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/3
echo -n /dev/nvme2n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/3/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/3/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/4
echo -n /dev/nvme3n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/4/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/4/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/5
echo -n /dev/nvme4n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/5/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/5/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/6
echo -n /dev/nvme5n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/6/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/6/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/7
echo -n /dev/nvme6n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/7/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/7/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/8
echo -n /dev/nvme7n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/8/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/8/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/9
echo -n /dev/nvme8n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/9/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/9/enable

mkdir /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/10
echo -n /dev/nvme9n1 >  /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/10/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/testsubsystem/namespaces/10/enable

mkdir /sys/kernel/config/nvmet/ports/1
echo 4420 > /sys/kernel/config/nvmet/ports/1/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/1/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/1/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/1/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/1/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/2
echo 4421 > /sys/kernel/config/nvmet/ports/2/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/2/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/2/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/2/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/2/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/3
echo 4422 > /sys/kernel/config/nvmet/ports/3/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/3/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/3/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/3/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/3/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/4
echo 4423 > /sys/kernel/config/nvmet/ports/4/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/4/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/4/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/4/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/4/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/5
echo 4424 > /sys/kernel/config/nvmet/ports/5/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/5/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/5/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/5/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/5/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/6
echo 4425 > /sys/kernel/config/nvmet/ports/6/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/6/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/6/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/6/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/6/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/7
echo 4426 > /sys/kernel/config/nvmet/ports/7/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/7/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/7/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/7/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/7/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/8
echo 4427 > /sys/kernel/config/nvmet/ports/8/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/8/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/8/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/8/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/8/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/9
echo 4428 > /sys/kernel/config/nvmet/ports/9/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/9/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/9/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/9/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/9/subsystems/testsubsystem

mkdir /sys/kernel/config/nvmet/ports/10
echo 4429 > /sys/kernel/config/nvmet/ports/10/addr_trsvcid
echo 10.0.30.110 > /sys/kernel/config/nvmet/ports/10/addr_traddr
echo "rdma" > /sys/kernel/config/nvmet/ports/10/addr_trtype
echo "ipv4" > /sys/kernel/config/nvmet/ports/10/addr_adrfam
ln -s /sys/kernel/config/nvmet/subsystems/testsubsystem/ /sys/kernel/config/nvmet/ports/10/subsystems/testsubsystem

