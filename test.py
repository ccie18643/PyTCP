#!/usr/bin/env python3

from time import time

from ip_helper import inet_cksum, inet_cksum_fast

with open("sample.1500", mode="rb") as _:
    packet = _.read()

plen = 20

print(f"0x{inet_cksum(packet[:plen]):04X}")
print(f"0x{inet_cksum_fast(packet, 0, plen):04X}")


s = time()
for _ in range(10000):
    inet_cksum(packet[:plen])
print(time() - s)

s = time()
for _ in range(10000):
    inet_cksum_fast(packet, 0, plen)
print(time() - s)
