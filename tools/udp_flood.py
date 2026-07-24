#!/usr/bin/env python3
################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
UDP flood load-generator — sends raw datagrams as fast as
'socket.sendto' returns, with no per-datagram print loop and no
peer protocol negotiation. Pair it with PyTCP's UDP echo service
('examples/udp_echo_server__async.py' on port 7) to stress-test the
RX -> handler -> TX path.

Run (no root required for UDP):

    python3.14 tools/udp_flood.py 192.168.1.145 7

Optional third arg = payload size in bytes (default 100, matching
'iperf3 -l 100' for cross-comparison).

Prints throughput every 50k packets sent. Ctrl-C for final stats.
This is NOT an iperf3 server peer — iperf3 negotiates over TCP
first, so 'iperf3 -u -c <pytcp>' fails because PyTCP has no
iperf3 server. Use this script instead.

tools/udp_flood.py

ver 3.0.9
"""

import socket
import sys
import time


def main() -> int:
    """
    Parse args and run the flood loop.
    """

    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.145"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    payload_size = int(sys.argv[3]) if len(sys.argv) > 3 else 100

    payload = b"x" * payload_size
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Flooding UDP {target}:{port} with {payload_size}-byte payloads. " "Ctrl-C to stop.")

    sent = 0
    start = time.perf_counter()
    try:
        while True:
            sock.sendto(payload, (target, port))
            sent += 1
            if sent % 50000 == 0:
                elapsed = time.perf_counter() - start
                print(f"  sent {sent} in {elapsed:.1f}s = {sent / elapsed:,.0f} pps")
    except KeyboardInterrupt:
        elapsed = time.perf_counter() - start
        print(f"\nFinal: {sent:,} packets in {elapsed:.1f}s = " f"{sent / elapsed:,.0f} pps")
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
