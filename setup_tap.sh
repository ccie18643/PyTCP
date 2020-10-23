#!/bin/bash

ip tuntap add name tap7 mode tap
ip link set dev tap7 up
brctl addbr br0
brctl addif br0 tap7
