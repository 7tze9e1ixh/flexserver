#!/bin/bash
modprobe nvme
modprobe nvme-rdma

nvme discover -t rdma -a 10.0.31.111 -s 4420
nvme discover -t rdma -a 10.0.31.111 -s 4421
nvme discover -t rdma -a 10.0.31.111 -s 4422
nvme discover -t rdma -a 10.0.31.111 -s 4423
nvme discover -t rdma -a 10.0.31.111 -s 4424
nvme discover -t rdma -a 10.0.31.111 -s 4425
nvme discover -t rdma -a 10.0.31.111 -s 4426
nvme discover -t rdma -a 10.0.31.111 -s 4427
nvme discover -t rdma -a 10.0.31.111 -s 4428
nvme discover -t rdma -a 10.0.31.111 -s 4429

nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4420
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4421
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4422
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4423
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4424
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4425
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4426
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4427
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4428
nvme connect -t rdma -n testsubsystem -a 10.0.31.111 -s 4429
