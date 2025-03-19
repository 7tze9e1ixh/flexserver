#!/bin/bash
mkdir -p /srv/nvme0
mkdir -p /srv/nvme1
mkdir -p /srv/nvme2
mkdir -p /srv/nvme3
mkdir -p /srv/nvme4
mkdir -p /srv/nvme5
mkdir -p /srv/nvme6
mkdir -p /srv/nvme7
mkdir -p /srv/nvme8
mkdir -p /srv/nvme9

mount /dev/nvme1n1 /srv/nvme0/
mount /dev/nvme1n2 /srv/nvme1/
mount /dev/nvme1n3 /srv/nvme2/
mount /dev/nvme1n4 /srv/nvme3/
mount /dev/nvme1n5 /srv/nvme4/
mount /dev/nvme1n6 /srv/nvme5/
mount /dev/nvme1n7 /srv/nvme6/
mount /dev/nvme1n8 /srv/nvme7/
mount /dev/nvme1n9 /srv/nvme8/
mount /dev/nvme1n10 /srv/nvme9/
