#!/bin/bash

ip tuntap add name tap7 mode tap
brctl addbr br0
brctl addif br0 tap7
