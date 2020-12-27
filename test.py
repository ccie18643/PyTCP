#!/usr/bin/env python3

from time import time
from ip_helper import inet_cksum, inet_cksum_fast, inet_cksum_fast_2


with open("sample.1500", mode="rb") as _:
    packet = _.read()


print(f"0x{inet_cksum(packet[:1500]):04X}")
print(f"0x{inet_cksum_fast(packet, 0, 1500):04X}")
print(f"0x{inet_cksum_fast_2(packet, 0, 1500):04X}")


s = time()
for _ in range(10000):
    inet_cksum(packet[:1500])
print(time() - s)

s = time()
for _ in range(10000):
    inet_cksum_fast(packet, 0, 1500)
print(time() - s)

s = time()
for _ in range(10000):
    inet_cksum_fast_2(packet, 0, 1500)
print(time() - s)
