#!/usr/bin/env python3

from pytun import TunTapDevice, IFF_TAP

tap = TunTapDevice(flags=IFF_TAP)

tap.up()

print(tap.read(tap.mtu))
