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
This module contains an unprivileged ping (ICMP Echo) tool written against
the standard 'socket' API.

Unlike the raw-socket 'ping.py', this uses the Linux unprivileged ICMP
datagram socket -- 'socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)' -- which
needs no root / CAP_NET_RAW. The kernel owns the ICMP id and demuxes
replies by it, so every datagram read on the socket is one of our replies;
each 'recvmsg' returns the ICMP message only (no IP header), and the
reply's TTL arrives as an 'IP_TTL' control message once 'IP_RECVTTL' is
enabled.

The body uses only the official BSD socket interface, so the same program
runs on the Python standard-library stack or on a PyTCP daemon -- the only
backend-specific line is the 'socket' import below. It defaults to PyTCP;
change that one line to 'import socket' to run on the kernel stack.

Stdlib mode needs the destination to be within the
'net.ipv4.ping_group_range' sysctl (default: no groups, so run as root or
widen the range). PyTCP mode needs a running daemon (it owns the TAP
interface), e.g.:

    sudo make tap7 && sudo make bridge
    pytcp stack start -i tap7

Usage:

    examples/ping_unprivileged.py [-c COUNT] [-i INTERVAL] [-W TIMEOUT] [-s SIZE] DESTINATION

IPv4 only.

examples/ping_unprivileged.py

ver 3.0.8
"""

import argparse
import struct
import time

import pytcp.socket as socket  # PyTCP drop-in; change to 'import socket' for the kernel stack

ICMP__ECHO_REQUEST: int = 8
ICMP__ECHO_REPLY: int = 0
ICMP__HEADER__STRUCT: str = "!BBHHH"
TIMESTAMP__STRUCT: str = "!d"
TIMESTAMP__LEN: int = 8


def _checksum(data: bytes, /) -> int:
    """
    Compute the 16-bit one's-complement Internet checksum (RFC 1071).
    """

    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _build_echo_request(*, sequence: int, size: int) -> bytes:
    """
    Build an ICMP Echo Request: the 8-byte header followed by an 8-byte
    send timestamp and a filler pattern up to 'size' payload bytes. The id
    field is left zero -- the kernel assigns the ping socket's own id.
    """

    payload = struct.pack(TIMESTAMP__STRUCT, time.monotonic()) + bytes(
        index & 0xFF for index in range(size - TIMESTAMP__LEN)
    )
    checksum = _checksum(struct.pack(ICMP__HEADER__STRUCT, ICMP__ECHO_REQUEST, 0, 0, 0, sequence) + payload)
    header = struct.pack(ICMP__HEADER__STRUCT, ICMP__ECHO_REQUEST, 0, checksum, 0, sequence)
    return header + payload


def _ttl_from_ancdata(ancdata: list[tuple[int, int, bytes]], /) -> int | None:
    """
    Extract the reply's TTL from an 'IP_TTL' control message, or 'None'
    when none was delivered. The cmsg value is an int in host byte order;
    its low byte carries the TTL (always <= 255).
    """

    for level, kind, data in ancdata:
        if level == socket.IPPROTO_IP and kind == socket.IP_TTL and data:
            return data[0]
    return None


def _parse_echo_reply(icmp: bytes, /) -> tuple[int, float] | None:
    """
    Parse the ICMP message a ping socket delivers (no IP header). Return
    '(sequence, send_time)' when it is an Echo Reply, otherwise 'None'.
    """

    if len(icmp) < 8 + TIMESTAMP__LEN:
        return None
    icmp_type, _, _, _, sequence = struct.unpack(ICMP__HEADER__STRUCT, icmp[:8])
    if icmp_type != ICMP__ECHO_REPLY:
        return None
    (send_time,) = struct.unpack(TIMESTAMP__STRUCT, icmp[8 : 8 + TIMESTAMP__LEN])
    return sequence, send_time


def main() -> None:
    """
    Send ICMP Echo Requests to a destination over an unprivileged ping
    socket and report the replies, in the style of the 'ping' utility.
    """

    parser = argparse.ArgumentParser(description="Unprivileged ICMP Echo (ping) over the official socket API.")
    parser.add_argument("destination", help="IPv4 address or hostname to ping.")
    parser.add_argument(
        "-c", "--count", type=int, default=None, help="Stop after COUNT requests (default: until interrupted)."
    )
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Seconds between requests (default: 1.0).")
    parser.add_argument("-W", "--timeout", type=float, default=1.0, help="Seconds to wait per reply (default: 1.0).")
    parser.add_argument("-s", "--size", type=int, default=56, help="Payload size in bytes, >= 8 (default: 56).")
    args = parser.parse_args()

    if args.size < TIMESTAMP__LEN:
        parser.error(f"--size must be at least {TIMESTAMP__LEN} (room for the send timestamp).")

    address = socket.gethostbyname(args.destination)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)

    transmitted = 0
    received = 0
    round_trips: list[float] = []

    print(f"PING {args.destination} ({address}): {args.size} data bytes")
    try:
        sequence = 0
        while args.count is None or sequence < args.count:
            sequence += 1
            sock.sendto(_build_echo_request(sequence=sequence, size=args.size), (address, 0))
            transmitted += 1

            # Read replies until ours (matched by sequence) arrives or the
            # per-reply timeout elapses; the kernel demuxes by id, so every
            # datagram here is an Echo Reply for this socket.
            reply: tuple[int, float] | None = None
            ttl: int | None = None
            deadline = time.monotonic() + args.timeout
            while (remaining := deadline - time.monotonic()) > 0:
                sock.settimeout(remaining)
                try:
                    icmp, ancdata, _flags, _address = sock.recvmsg(2048, 256)
                except TimeoutError:
                    break
                if (parsed := _parse_echo_reply(icmp)) is not None and parsed[0] == sequence:
                    reply = parsed
                    ttl = _ttl_from_ancdata(ancdata)
                    break

            if reply is None:
                print(f"Request timeout for icmp_seq {sequence}")
            else:
                reply_sequence, send_time = reply
                round_trip_ms = (time.monotonic() - send_time) * 1000.0
                received += 1
                round_trips.append(round_trip_ms)
                ttl_text = "?" if ttl is None else str(ttl)
                print(
                    f"{args.size + 8} bytes from {address}: "
                    f"icmp_seq={reply_sequence} ttl={ttl_text} time={round_trip_ms:.2f} ms"
                )

            if args.count is None or sequence < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()

    print(f"\n--- {args.destination} ping statistics ---")
    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    print(f"{transmitted} packets transmitted, {received} received, {loss:.0f}% packet loss")
    if round_trips:
        average = sum(round_trips) / len(round_trips)
        print(f"rtt min/avg/max = {min(round_trips):.2f}/{average:.2f}/{max(round_trips):.2f} ms")


if __name__ == "__main__":
    main()
