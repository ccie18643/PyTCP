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
This module contains the ICMP traceroute engine behind the 'pytcp
traceroute' CLI subcommand, built on the daemon-backed 'pytcp.socket'
drop-in and the shared ICMP Echo helpers from 'cli__ping'.

It mirrors 'traceroute -I' / Windows 'tracert': it sends ICMP Echo
Requests with an increasing IP TTL / IPv6 Hop Limit; each intermediate
router answers with an ICMP Time Exceeded (its source address is the
hop), and the destination answers with an Echo Reply (the trace ends).
Both directions ride a single raw ICMP socket — the same 'raw_local
_deliver' path 'ping' uses for its raw fallback — so no daemon control
op is needed.

The engine is split so its wire logic is unit-testable without a
daemon: 'traceroute_profile', 'build_probe', 'parse_probe_response',
and 'format_hop_line' are pure functions, and 'run_traceroute' drives a
*caller-supplied* socket and yields one 'HopResult' per TTL (so a fake
socket exercises it). 'open_traceroute_socket' is the only
daemon-touching helper.

packages/pytcp/pytcp/cli/cli__traceroute.py

ver 3.0.8
"""

import struct
import time
from collections.abc import Callable, Iterator
from typing import NamedTuple

from pytcp import socket
from pytcp.cli.cli__ping import ICMP__HEADER__STRUCT, icmp_checksum

TRACEROUTE__DEFAULT_MAX_HOPS: int = 30
TRACEROUTE__DEFAULT_PROBES: int = 3
TRACEROUTE__DEFAULT_TIMEOUT__SEC: float = 3.0
TRACEROUTE__RECV_LEN: int = 2048

# Embedded-original offsets inside an ICMP Time Exceeded body: the
# 8-octet Time Exceeded header is followed by the IP packet that
# triggered it. The embedded IPv6 header is a fixed 40 octets; the
# embedded IPv4 header length is read from its IHL nibble.
_TIME_EXCEEDED__HEADER_LEN: int = 8
_IP6__HEADER_LEN: int = 40


class TracerouteProfile(NamedTuple):
    """
    The per-IP-version wire-format values that drive a traceroute.
    """

    is_ipv6: bool
    echo_request: int  # ICMPv4 8 / ICMPv6 128
    echo_reply: int  # ICMPv4 0 / ICMPv6 129
    time_exceeded: int  # ICMPv4 11 / ICMPv6 3
    compute_checksum: bool  # v4: build it; v6: the stack fills the ICMPv6 checksum
    ttl_level: int  # IPPROTO_IP / IPPROTO_IPV6 (setsockopt level)
    ttl_optname: int  # IP_TTL / IPV6_UNICAST_HOPS (setsockopt optname)
    ip_header_included: bool  # v4 raw delivers the IP header; v6 raw delivers only the ICMPv6 message


class ProbeResult(NamedTuple):
    """
    The result of one probe: the responding hop and round-trip time, or
    '(None, None)' on timeout.
    """

    hop: str | None
    rtt_ms: float | None


class HopResult(NamedTuple):
    """
    The result for one TTL: its probe results and whether the
    destination's Echo Reply arrived (the trace is complete).
    """

    ttl: int
    probes: tuple[ProbeResult, ...]
    reached: bool


def traceroute_profile(*, is_ipv6: bool) -> TracerouteProfile:
    """
    Build the traceroute wire-format profile for the resolved IP version.
    """

    if is_ipv6:
        return TracerouteProfile(
            is_ipv6=True,
            echo_request=128,
            echo_reply=129,
            time_exceeded=3,
            compute_checksum=False,
            ttl_level=int(socket.IPPROTO_IPV6),
            ttl_optname=int(socket.IPV6_UNICAST_HOPS),
            ip_header_included=False,
        )
    return TracerouteProfile(
        is_ipv6=False,
        echo_request=8,
        echo_reply=0,
        time_exceeded=11,
        compute_checksum=True,
        ttl_level=int(socket.IPPROTO_IP),
        ttl_optname=int(socket.IP_TTL),
        ip_header_included=True,
    )


def build_probe(profile: TracerouteProfile, /, *, identifier: int, sequence: int) -> bytes:
    """
    Build a minimal 8-byte ICMP Echo Request probe carrying 'identifier'
    and 'sequence'. The ICMPv6 checksum covers a pseudo-header the
    application cannot see, so it is left zero for the stack to fill.
    """

    body = struct.pack(ICMP__HEADER__STRUCT, profile.echo_request, 0, 0, identifier, sequence)
    checksum = icmp_checksum(body) if profile.compute_checksum else 0
    return struct.pack(ICMP__HEADER__STRUCT, profile.echo_request, 0, checksum, identifier, sequence)


def _echo_id_seq(buffer: bytes, offset: int, /) -> tuple[int, int] | None:
    """
    Read the ICMP Echo '(identifier, sequence)' at 'offset', or None when
    the buffer is too short.
    """

    if len(buffer) < offset + 8:
        return None
    _type, _code, _cksum, identifier, sequence = struct.unpack_from(ICMP__HEADER__STRUCT, buffer, offset)
    return identifier, sequence


def parse_probe_response(
    data: bytes,
    /,
    *,
    profile: TracerouteProfile,
    identifier: int,
    sequence: int,
) -> str | None:
    """
    Classify a received raw-socket datagram against our outstanding
    probe: return 'reply' for our Echo Reply (destination reached),
    'time_exceeded' for a Time Exceeded carrying our embedded Echo
    Request (an intermediate hop), or None for any unrelated message. A
    v4 raw socket prepends the IPv4 header (skipped via its IHL); a v6
    raw socket delivers the ICMPv6 message at offset 0.
    """

    icmp = ((data[0] & 0x0F) * 4) if profile.ip_header_included and data else 0
    if len(data) < icmp + 8:
        return None
    icmp_type = data[icmp]

    if icmp_type == profile.echo_reply:
        if _echo_id_seq(data, icmp) == (identifier, sequence):
            return "reply"
        return None

    if icmp_type == profile.time_exceeded:
        embedded = icmp + _TIME_EXCEEDED__HEADER_LEN
        if len(data) <= embedded:
            return None
        if profile.ip_header_included:
            embedded_icmp = embedded + (data[embedded] & 0x0F) * 4
        else:
            embedded_icmp = embedded + _IP6__HEADER_LEN
        if _echo_id_seq(data, embedded_icmp) == (identifier, sequence):
            return "time_exceeded"

    return None


def open_traceroute_socket(*, is_ipv6: bool) -> socket.Socket:
    """
    Open the raw ICMP socket the trace rides — the same 'raw_local
    _deliver' path that delivers inbound Time Exceeded and Echo Reply
    messages to a matching raw socket.
    """

    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    proto = socket.IPPROTO_ICMPV6 if is_ipv6 else socket.IPPROTO_ICMP
    return socket.socket(family, socket.SOCK_RAW, proto)


def _await_probe(
    sock: socket.Socket,
    /,
    *,
    profile: TracerouteProfile,
    identifier: int,
    sequence: int,
    timeout: float,
    start: float,
    time_fn: Callable[[], float],
) -> ProbeResult:
    """
    Wait up to 'timeout' seconds for the response to one probe, ignoring
    unrelated ICMP traffic. Return the responding hop and round-trip
    time, or '(None, None)' on timeout.
    """

    deadline = start + timeout
    while (remaining := deadline - time_fn()) > 0:
        sock.settimeout(remaining)
        try:
            data, address = sock.recvfrom(TRACEROUTE__RECV_LEN)
        except TimeoutError:
            break
        kind = parse_probe_response(data, profile=profile, identifier=identifier, sequence=sequence)
        if kind is None:
            continue
        return ProbeResult(hop=address[0], rtt_ms=(time_fn() - start) * 1000.0)
    return ProbeResult(hop=None, rtt_ms=None)


def run_traceroute(
    sock: socket.Socket,
    /,
    *,
    dest_address: str,
    profile: TracerouteProfile,
    identifier: int,
    max_hops: int,
    probes_per_hop: int,
    timeout: float,
    time_fn: Callable[[], float] = time.monotonic,
) -> Iterator[HopResult]:
    """
    Drive 'sock' through the TTL ladder against 'dest_address', yielding
    one 'HopResult' per TTL until the destination's Echo Reply arrives or
    'max_hops' is reached. The caller owns socket construction, teardown,
    and output formatting; this generator owns the per-probe TTL set,
    send, and bounded wait. 'time_fn' is a zero-argument clock (injected
    in tests).
    """

    sequence = 0
    for ttl in range(1, max_hops + 1):
        sock.setsockopt(profile.ttl_level, profile.ttl_optname, ttl)
        results: list[ProbeResult] = []
        reached = False
        for _ in range(probes_per_hop):
            sequence += 1
            probe = build_probe(profile, identifier=identifier, sequence=sequence)
            start = time_fn()
            try:
                sock.sendto(probe, (dest_address, 0))
            except OSError:
                results.append(ProbeResult(hop=None, rtt_ms=None))
                continue
            result = _await_probe(
                sock,
                profile=profile,
                identifier=identifier,
                sequence=sequence,
                timeout=timeout,
                start=start,
                time_fn=time_fn,
            )
            results.append(result)
            if result.hop == dest_address:
                reached = True
        yield HopResult(ttl=ttl, probes=tuple(results), reached=reached)
        if reached:
            return


def format_hop_line(hop: HopResult, /) -> str:
    """
    Render a 'HopResult' as a Linux-'traceroute'-style hop row: the TTL,
    then per probe either the hop address (printed once per distinct
    address) followed by its RTT, or '*' on timeout.
    """

    parts = [f"{hop.ttl:2d} "]
    last_hop: str | None = None
    for probe in hop.probes:
        if probe.hop is None:
            parts.append(" *")
            continue
        if probe.hop != last_hop:
            parts.append(f"  {probe.hop}")
            last_hop = probe.hop
        parts.append(f"  {probe.rtt_ms:.3f} ms")
    return "".join(parts)
