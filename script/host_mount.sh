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

mount /dev/nvme0n1 /srv/nvme0/
mount /dev/nvme1n1 /srv/nvme1/
mount /dev/nvme2n1 /srv/nvme2/
mount /dev/nvme3n1 /srv/nvme3/
mount /dev/nvme4n1 /srv/nvme4/
mount /dev/nvme5n1 /srv/nvme5/
mount /dev/nvme6n1 /srv/nvme6/
mount /dev/nvme7n1 /srv/nvme7/
mount /dev/nvme8n1 /srv/nvme8/
mount /dev/nvme9n1 /srv/nvme9/
