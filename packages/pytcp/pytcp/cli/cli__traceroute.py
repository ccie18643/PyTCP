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
This module contains the traceroute engine behind the 'pytcp
traceroute' CLI subcommand, built on the daemon-backed 'pytcp.socket'
drop-in and the shared ICMP Echo helpers from 'cli__ping'.

It mirrors the classic Linux 'traceroute': probes are sent with an
increasing IP TTL / IPv6 Hop Limit, each intermediate router answers
with an ICMP Time Exceeded (its source address is the hop), and the
destination answers in a way that ends the trace. Two modes share the
TTL ladder:

  - UDP (default): a UDP datagram is sent to an unlikely high port that
    increments per probe; the destination answers with an ICMP
    Destination Unreachable (Port). A UDP send socket carries the
    probes; a separate raw ICMP socket receives the errors.
  - ICMP ('-I'): an ICMP Echo Request is sent; the destination answers
    with an Echo Reply. A single raw ICMP socket both sends and
    receives.

Both ride the 'raw_local_deliver' path 'ping' uses for its raw
fallback (every inbound ICMP packet is cloned to a matching raw
socket), so no daemon control op is needed.

The engine is split so its wire logic is unit-testable without a
daemon: 'traceroute_profile', 'build_probe', 'parse_probe_response',
'classify_icmp', 'classify_udp', and 'format_hop_line' are pure
functions, and 'run_traceroute' drives caller-supplied sockets plus a
probe / classify pair (so socket doubles exercise it).
'open_icmp_socket' / 'open_udp_socket' are the only daemon-touching
helpers.

packages/pytcp/pytcp/cli/cli__traceroute.py

ver 3.0.10
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
# RFC-era traceroute base UDP port; each probe adds its sequence so the
# embedded destination port uniquely identifies the probe a returned
# ICMP error refers to.
TRACEROUTE__UDP_BASE_PORT: int = 33434

# Embedded-original offsets inside an ICMP error body: the 8-octet
# Time Exceeded / Destination Unreachable header is followed by the IP
# packet that triggered it. The embedded IPv6 header is a fixed 40
# octets; the embedded IPv4 header length is read from its IHL nibble.
_ICMP_ERROR__HEADER_LEN: int = 8
_IP6__HEADER_LEN: int = 40

type ProbeFactory = Callable[[int], tuple[bytes, tuple[str, int]]]
type ProbeClassifier = Callable[[bytes, int], str | None]


class TracerouteProfile(NamedTuple):
    """
    The per-IP-version wire-format values that drive a traceroute.
    """

    is_ipv6: bool
    echo_request: int  # ICMPv4 8 / ICMPv6 128
    echo_reply: int  # ICMPv4 0 / ICMPv6 129
    time_exceeded: int  # ICMPv4 11 / ICMPv6 3
    dest_unreachable: int  # ICMPv4 3 / ICMPv6 1
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
    destination answered (the trace is complete).
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
            dest_unreachable=1,
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
        dest_unreachable=3,
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


def _icmp_offset(data: bytes, profile: TracerouteProfile, /) -> int:
    """
    Return the offset of the ICMP message within a raw-socket datagram —
    past the IPv4 header (its IHL) for v4, or zero for v6.
    """

    return ((data[0] & 0x0F) * 4) if profile.ip_header_included and data else 0


def _echo_id_seq(buffer: bytes, offset: int, /) -> tuple[int, int] | None:
    """
    Read the ICMP Echo '(identifier, sequence)' at 'offset', or None when
    the buffer is too short.
    """

    if len(buffer) < offset + 8:
        return None
    _type, _code, _cksum, identifier, sequence = struct.unpack_from(ICMP__HEADER__STRUCT, buffer, offset)
    return identifier, sequence


def _embedded_l4_offset(data: bytes, profile: TracerouteProfile, icmp: int, /) -> int | None:
    """
    Return the offset of the embedded transport header inside an ICMP
    error: past the 8-octet error header and the embedded IP header (v4
    IHL / v6 fixed 40), or None when the buffer is too short.
    """

    embedded = icmp + _ICMP_ERROR__HEADER_LEN
    if len(data) <= embedded:
        return None
    if profile.ip_header_included:
        return embedded + (data[embedded] & 0x0F) * 4
    return embedded + _IP6__HEADER_LEN


def parse_probe_response(
    data: bytes,
    /,
    *,
    profile: TracerouteProfile,
    identifier: int,
    sequence: int,
) -> str | None:
    """
    Classify an ICMP-mode datagram against our outstanding probe: return
    'reply' for our Echo Reply (destination reached), 'time_exceeded'
    for a Time Exceeded carrying our embedded Echo Request (an
    intermediate hop), or None for any unrelated message.
    """

    icmp = _icmp_offset(data, profile)
    if len(data) < icmp + 8:
        return None
    icmp_type = data[icmp]

    if icmp_type == profile.echo_reply:
        return "reply" if _echo_id_seq(data, icmp) == (identifier, sequence) else None

    if icmp_type == profile.time_exceeded:
        embedded_icmp = _embedded_l4_offset(data, profile, icmp)
        if embedded_icmp is not None and _echo_id_seq(data, embedded_icmp) == (identifier, sequence):
            return "time_exceeded"

    return None


def classify_icmp(
    data: bytes,
    /,
    *,
    profile: TracerouteProfile,
    identifier: int,
    sequence: int,
) -> str | None:
    """
    Classify an ICMP-mode datagram as 'reached' (our Echo Reply), 'hop'
    (a Time Exceeded for our probe), or None (unrelated).
    """

    match parse_probe_response(data, profile=profile, identifier=identifier, sequence=sequence):
        case "reply":
            return "reached"
        case "time_exceeded":
            return "hop"
        case _:
            return None


def classify_udp(
    data: bytes,
    /,
    *,
    profile: TracerouteProfile,
    local_port: int,
    dest_port: int,
) -> str | None:
    """
    Classify a UDP-mode datagram as 'reached' (a Destination Unreachable
    for our probe), 'hop' (a Time Exceeded for our probe), or None. The
    embedded original UDP header's source / destination ports must match
    our probe (the destination port increments per probe, so it pins the
    exact probe a returned error refers to).
    """

    icmp = _icmp_offset(data, profile)
    if len(data) < icmp + 8:
        return None
    icmp_type = data[icmp]
    if icmp_type not in (profile.time_exceeded, profile.dest_unreachable):
        return None

    embedded_udp = _embedded_l4_offset(data, profile, icmp)
    if embedded_udp is None or len(data) < embedded_udp + 4:
        return None
    src_port, dst_port = struct.unpack_from("!HH", data, embedded_udp)
    if src_port != local_port or dst_port != dest_port:
        return None

    return "reached" if icmp_type == profile.dest_unreachable else "hop"


def open_icmp_socket(*, is_ipv6: bool) -> socket.Socket:
    """
    Open the raw ICMP socket the trace receives on (and, in ICMP mode,
    sends on) — the 'raw_local_deliver' path that clones every inbound
    ICMP packet to a matching raw socket.
    """

    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    proto = socket.IPPROTO_ICMPV6 if is_ipv6 else socket.IPPROTO_ICMP
    return socket.socket(family, socket.SOCK_RAW, proto)


def open_udp_socket(*, is_ipv6: bool) -> socket.Socket:
    """
    Open and bind a UDP socket for sending TTL-laddered UDP probes; the
    bound local port pins the embedded source port the returned ICMP
    errors must carry.
    """

    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(("::" if is_ipv6 else "0.0.0.0", 0))
    return sock


def _await_probe(
    recv_sock: socket.Socket,
    /,
    *,
    classify: ProbeClassifier,
    sequence: int,
    timeout: float,
    start: float,
    time_fn: Callable[[], float],
) -> tuple[ProbeResult, bool]:
    """
    Wait up to 'timeout' seconds for the response to one probe, ignoring
    unrelated ICMP traffic. Return the '(result, reached)' pair — the
    responding hop and round-trip time (or '(None, None)' on timeout),
    and whether the response ended the trace.
    """

    deadline = start + timeout
    while (remaining := deadline - time_fn()) > 0:
        recv_sock.settimeout(remaining)
        try:
            data, address = recv_sock.recvfrom(TRACEROUTE__RECV_LEN)
        except TimeoutError:
            break
        kind = classify(data, sequence)
        if kind is None:
            continue
        return ProbeResult(hop=address[0], rtt_ms=(time_fn() - start) * 1000.0), kind == "reached"
    return ProbeResult(hop=None, rtt_ms=None), False


def run_traceroute(
    send_sock: socket.Socket,
    recv_sock: socket.Socket,
    /,
    *,
    ttl_level: int,
    ttl_optname: int,
    max_hops: int,
    probes_per_hop: int,
    timeout: float,
    make_probe: ProbeFactory,
    classify: ProbeClassifier,
    time_fn: Callable[[], float] = time.monotonic,
) -> Iterator[HopResult]:
    """
    Drive the TTL ladder, yielding one 'HopResult' per TTL until the
    destination answers or 'max_hops' is reached. 'make_probe(sequence)'
    returns the '(payload, target)' to send; 'classify(data, sequence)'
    maps a received datagram to 'reached' / 'hop' / None. The TTL is set
    on the send socket; responses are read on the receive socket (the
    same object in ICMP mode). The caller owns socket construction and
    teardown.
    """

    sequence = 0
    for ttl in range(1, max_hops + 1):
        send_sock.setsockopt(ttl_level, ttl_optname, ttl)
        results: list[ProbeResult] = []
        reached = False
        for _ in range(probes_per_hop):
            sequence += 1
            payload, target = make_probe(sequence)
            start = time_fn()
            try:
                send_sock.sendto(payload, target)
            except OSError:
                results.append(ProbeResult(hop=None, rtt_ms=None))
                continue
            result, hit = _await_probe(
                recv_sock,
                classify=classify,
                sequence=sequence,
                timeout=timeout,
                start=start,
                time_fn=time_fn,
            )
            results.append(result)
            reached = reached or hit
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
