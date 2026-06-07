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
This module contains a ping (ICMP Echo) tool written against the standard
'socket' API.

The destination's IP version is auto-detected through 'getaddrinfo', so
the same invocation pings an IPv4 or IPv6 address / hostname (ICMPv4 Echo
8/0 or ICMPv6 Echo 128/129). By default it uses a raw ICMP socket (the
classic mechanism); the '-U' / '--unprivileged' flag switches to the
Linux unprivileged ICMP datagram socket ('socket(AF_INET*, SOCK_DGRAM,
IPPROTO_ICMP*)'), where the kernel owns the ICMP id, demuxes replies by
it, hands back the ICMP message only (no IP header), and reports the reply
TTL / Hop Limit through an 'IP_TTL' / 'IPV6_HOPLIMIT' control message.

The body uses only the official BSD socket interface, so the same program
runs on the Python standard-library stack or on a PyTCP daemon -- the only
backend-specific line is the 'socket' import below. It defaults to PyTCP;
change that one line to 'import socket' to run on the kernel stack.

Stdlib mode: the default raw socket needs root (CAP_NET_RAW); the '-U'
datagram socket needs the destination within 'net.ipv4.ping_group_range'
(default: no groups, so run as root or widen the range). PyTCP mode needs
a running daemon (it owns the TAP interface), e.g.:

    sudo make tap7 && sudo make bridge
    pytcp stack start -i tap7

Usage:

    examples/ping.py [-U] [-c COUNT] [-i INTERVAL] [-W TIMEOUT] [-s SIZE] DESTINATION

examples/ping.py

ver 3.0.8
"""

import argparse
import os
import struct
import time
from typing import NamedTuple

import pytcp.socket as socket  # PyTCP drop-in; change to 'import socket' for the kernel stack

ICMP__HEADER__STRUCT: str = "!BBHHH"
TIMESTAMP__STRUCT: str = "!d"
TIMESTAMP__LEN: int = 8


class _IcmpProfile(NamedTuple):
    """
    The per-IP-version wire-format values that drive an ICMP Echo
    exchange. These are plain integers / booleans; the stack-specific
    socket-construction constants (family / proto / setsockopt level) stay
    in 'main' so they keep their native 'pytcp' / stdlib types. The cmsg
    level / type are stored as plain 'int' because the control message the
    stack delivers carries them as integers.
    """

    echo_request: int  # ICMPv4 8 / ICMPv6 128
    echo_reply: int  # ICMPv4 0 / ICMPv6 129
    compute_checksum: bool  # v4: build it; v6: the stack fills the ICMPv6 checksum
    ttl_cmsg_level: int  # IPPROTO_IP / IPPROTO_IPV6, as the cmsg carries it
    ttl_cmsg_type: int  # IP_TTL / IPV6_HOPLIMIT, as the cmsg carries it


def _profile_for(is_ipv6: bool, /) -> _IcmpProfile:
    """
    Build the ICMP Echo wire-format profile for the resolved IP version.
    """

    if is_ipv6:
        return _IcmpProfile(
            echo_request=128,
            echo_reply=129,
            compute_checksum=False,
            ttl_cmsg_level=int(socket.IPPROTO_IPV6),
            ttl_cmsg_type=int(socket.IPV6_HOPLIMIT),
        )
    return _IcmpProfile(
        echo_request=8,
        echo_reply=0,
        compute_checksum=True,
        ttl_cmsg_level=int(socket.IPPROTO_IP),
        ttl_cmsg_type=int(socket.IP_TTL),
    )


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


def _build_echo_request(profile: _IcmpProfile, /, *, identifier: int, sequence: int, size: int) -> bytes:
    """
    Build an ICMP Echo Request: the 8-byte header followed by an 8-byte
    send timestamp and a filler pattern up to 'size' payload bytes. The
    ICMPv6 checksum covers a pseudo-header the application cannot see, so
    it is left zero for the stack to fill; in unprivileged mode the kernel
    overwrites the id, so passing 'identifier' here is harmless.
    """

    payload = struct.pack(TIMESTAMP__STRUCT, time.monotonic()) + bytes(
        index & 0xFF for index in range(size - TIMESTAMP__LEN)
    )
    body = struct.pack(ICMP__HEADER__STRUCT, profile.echo_request, 0, 0, identifier, sequence) + payload
    checksum = _checksum(body) if profile.compute_checksum else 0
    header = struct.pack(ICMP__HEADER__STRUCT, profile.echo_request, 0, checksum, identifier, sequence)
    return header + payload


def _parse_reply(
    data: bytes,
    /,
    *,
    echo_reply: int,
    ip_header_in_payload: bool,
    match_identifier: int | None,
) -> tuple[int, int | None, float] | None:
    """
    Parse a received datagram into '(sequence, ttl, send_time)' when it is
    our Echo Reply, otherwise 'None'. A v4 raw socket prepends the IPv4
    header (TTL read from it); every other path delivers the ICMP message
    at offset 0 (TTL unknown here, supplied by a control message instead).
    When 'match_identifier' is set the reply id must match it (raw mode);
    in ping mode the kernel owns the id, so it is left unchecked.
    """

    if ip_header_in_payload:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        ttl: int | None = data[8]
        icmp = data[ihl:]
    else:
        ttl = None
        icmp = data
    if len(icmp) < 8 + TIMESTAMP__LEN:
        return None
    icmp_type, _, _, reply_identifier, sequence = struct.unpack(ICMP__HEADER__STRUCT, icmp[:8])
    if icmp_type != echo_reply:
        return None
    if match_identifier is not None and reply_identifier != match_identifier:
        return None
    (send_time,) = struct.unpack(TIMESTAMP__STRUCT, icmp[8 : 8 + TIMESTAMP__LEN])
    return sequence, ttl, send_time


def _ttl_from_ancdata(ancdata: list[tuple[int, int, bytes]], /, *, level: int, kind: int) -> int | None:
    """
    Extract the reply's TTL / Hop Limit from its control message, or 'None'
    when none was delivered. The cmsg value is an int in host byte order;
    its low byte carries the value (always <= 255).
    """

    for cmsg_level, cmsg_type, payload in ancdata:
        if cmsg_level == level and cmsg_type == kind and payload:
            return payload[0]
    return None


def _recv_one_reply(
    sock: socket.Socket,
    profile: _IcmpProfile,
    /,
    *,
    use_cmsg: bool,
    match_identifier: int | None,
    sequence: int,
    timeout: float,
) -> tuple[int | None, float] | None:
    """
    Wait up to 'timeout' seconds for our Echo Reply to 'sequence',
    ignoring unrelated traffic. 'use_cmsg' selects the ICMP-only recvmsg
    path (TTL from the IP_TTL / IPV6_HOPLIMIT cmsg) over the v4-raw
    recvfrom path (TTL from the prepended IP header). 'match_identifier'
    filters by reply id in raw mode (None in ping mode, where the kernel
    owns the id). Return '(ttl, send_time)' on a match (ttl is 'None' when
    the stack delivered no TTL), or 'None' on timeout.
    """

    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        sock.settimeout(remaining)
        try:
            if use_cmsg:
                icmp, ancdata, _flags, _address = sock.recvmsg(2048, 256)
                parsed = _parse_reply(
                    icmp, echo_reply=profile.echo_reply, ip_header_in_payload=False, match_identifier=match_identifier
                )
                if parsed is not None and parsed[0] == sequence:
                    ttl = _ttl_from_ancdata(ancdata, level=profile.ttl_cmsg_level, kind=profile.ttl_cmsg_type)
                    return ttl, parsed[2]
            else:
                packet, _ = sock.recvfrom(2048)
                parsed = _parse_reply(
                    packet, echo_reply=profile.echo_reply, ip_header_in_payload=True, match_identifier=match_identifier
                )
                if parsed is not None and parsed[0] == sequence:
                    return parsed[1], parsed[2]
        except TimeoutError:
            break
    return None


def main() -> None:
    """
    Send ICMP Echo Requests to a destination and report the replies, in
    the style of the 'ping' utility.
    """

    parser = argparse.ArgumentParser(description="ICMP Echo (ping) over the official socket API.")
    parser.add_argument("destination", help="IPv4 / IPv6 address or hostname to ping.")
    parser.add_argument(
        "-U",
        "--unprivileged",
        action="store_true",
        help="Use the unprivileged ICMP datagram ('ping') socket instead of a raw socket.",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=None, help="Stop after COUNT requests (default: until interrupted)."
    )
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Seconds between requests (default: 1.0).")
    parser.add_argument("-W", "--timeout", type=float, default=1.0, help="Seconds to wait per reply (default: 1.0).")
    parser.add_argument("-s", "--size", type=int, default=56, help="Payload size in bytes, >= 8 (default: 56).")
    args = parser.parse_args()

    if args.size < TIMESTAMP__LEN:
        parser.error(f"--size must be at least {TIMESTAMP__LEN} (room for the send timestamp).")

    # Auto-detect the IP version from the destination via 'getaddrinfo'.
    family, _type, _proto, _canon, sockaddr = socket.getaddrinfo(args.destination, None)[0]
    address = sockaddr[0]
    is_ipv6 = family == socket.AF_INET6
    profile = _profile_for(is_ipv6)

    proto = socket.IPPROTO_ICMPV6 if is_ipv6 else socket.IPPROTO_ICMP
    identifier = os.getpid() & 0xFFFF

    # A v4 raw socket reads the TTL from the prepended IP header; every
    # other path (v4 ping, and v6 either way — a v6 raw socket carries no
    # IP header) reads it from an IP_TTL / IPV6_HOPLIMIT control message.
    use_cmsg = args.unprivileged or is_ipv6
    # Raw sockets see all matching ICMP traffic, so filter replies by our
    # id; a ping socket is demuxed by the kernel, which owns the id.
    match_identifier = None if args.unprivileged else identifier

    sock = socket.socket(family, socket.SOCK_DGRAM if args.unprivileged else socket.SOCK_RAW, proto)
    if use_cmsg:
        recv_ttl_level = socket.IPPROTO_IPV6 if is_ipv6 else socket.IPPROTO_IP
        recv_ttl_opt = socket.IPV6_RECVHOPLIMIT if is_ipv6 else socket.IP_RECVTTL
        sock.setsockopt(recv_ttl_level, recv_ttl_opt, 1)

    transmitted = 0
    received = 0
    round_trips: list[float] = []

    print(f"PING {args.destination} ({address}): {args.size} data bytes")
    try:
        sequence = 0
        while args.count is None or sequence < args.count:
            sequence += 1
            request = _build_echo_request(profile, identifier=identifier, sequence=sequence, size=args.size)
            sock.sendto(request, (address, 0))
            transmitted += 1

            reply = _recv_one_reply(
                sock,
                profile,
                use_cmsg=use_cmsg,
                match_identifier=match_identifier,
                sequence=sequence,
                timeout=args.timeout,
            )

            if reply is None:
                print(f"Request timeout for icmp_seq {sequence}")
            else:
                ttl, send_time = reply
                round_trip_ms = (time.monotonic() - send_time) * 1000.0
                received += 1
                round_trips.append(round_trip_ms)
                ttl_text = "?" if ttl is None else str(ttl)
                print(
                    f"{args.size + 8} bytes from {address}: "
                    f"icmp_seq={sequence} ttl={ttl_text} time={round_trip_ms:.2f} ms"
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
