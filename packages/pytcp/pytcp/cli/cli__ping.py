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
This module contains the ICMP Echo ('ping') engine shared by the
'pytcp ping' CLI subcommand and the 'examples/ping.py' tool. It is
built on the daemon-backed 'pytcp.socket' drop-in and 'net_addr'.

The engine is split so its wire logic is unit-testable without a
daemon: 'icmp_checksum' / 'build_echo_request' / 'parse_echo_reply'
/ 'icmp_echo_profile' are pure functions, and 'run_ping' drives a
*caller-supplied* socket and yields one 'PingOutcome' per sequence
(reply or timeout), so a fake socket exercises it. Socket
construction ('open_icmp_socket') and name resolution
('resolve_destination') are the only daemon-touching helpers; the
two pure formatters render an outcome / summary as plain text.

The destination may be an IPv4 / IPv6 literal — classified directly
via 'net_addr' — or a hostname resolved through the daemon's DNS
resolver; the IP version drives ICMPv4 (Echo 8/0) vs ICMPv6 (Echo
128/129). Socket selection mirrors Linux 'ping': the unprivileged
ICMP datagram socket by default, falling back to a raw socket if it
is refused; a custom identifier forces a raw socket (the kernel owns
the id on a ping socket).

packages/pytcp/pytcp/cli/cli__ping.py

ver 3.0.9
"""

import os
import struct
import time
from collections.abc import Iterator
from typing import NamedTuple

from net_addr import Ip4Address, Ip4AddressFormatError, Ip6Address, Ip6AddressFormatError
from pytcp import socket

ICMP__HEADER__STRUCT: str = "!BBHHH"
TIMESTAMP__STRUCT: str = "!d"
TIMESTAMP__LEN: int = 8


class IcmpEchoProfile(NamedTuple):
    """
    The per-IP-version wire-format values that drive an ICMP Echo
    exchange.
    """

    echo_request: int  # ICMPv4 8 / ICMPv6 128
    echo_reply: int  # ICMPv4 0 / ICMPv6 129
    compute_checksum: bool  # v4: build it; v6: the stack fills the ICMPv6 checksum
    ttl_cmsg_level: int  # IPPROTO_IP / IPPROTO_IPV6, as the cmsg carries it
    ttl_cmsg_type: int  # IP_TTL / IPV6_HOPLIMIT, as the cmsg carries it


class PingOutcome(NamedTuple):
    """
    The result of a single Echo Request / Reply round: either a
    received reply ('timed_out' False, 'rtt_ms' set) or a timeout
    ('timed_out' True, 'rtt_ms' / 'ttl' None).
    """

    sequence: int
    ttl: int | None
    rtt_ms: float | None
    timed_out: bool


def icmp_echo_profile(*, is_ipv6: bool) -> IcmpEchoProfile:
    """
    Build the ICMP Echo wire-format profile for the resolved IP version.
    """

    if is_ipv6:
        return IcmpEchoProfile(
            echo_request=128,
            echo_reply=129,
            compute_checksum=False,
            ttl_cmsg_level=int(socket.IPPROTO_IPV6),
            ttl_cmsg_type=int(socket.IPV6_HOPLIMIT),
        )
    return IcmpEchoProfile(
        echo_request=8,
        echo_reply=0,
        compute_checksum=True,
        ttl_cmsg_level=int(socket.IPPROTO_IP),
        ttl_cmsg_type=int(socket.IP_TTL),
    )


def icmp_checksum(data: bytes, /) -> int:
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


def build_echo_request(profile: IcmpEchoProfile, /, *, identifier: int, sequence: int, size: int) -> bytes:
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
    checksum = icmp_checksum(body) if profile.compute_checksum else 0
    header = struct.pack(ICMP__HEADER__STRUCT, profile.echo_request, 0, checksum, identifier, sequence)
    return header + payload


def parse_echo_reply(
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


def ttl_from_ancdata(ancdata: list[tuple[int, int, bytes]], /, *, level: int, kind: int) -> int | None:
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
    profile: IcmpEchoProfile,
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
                parsed = parse_echo_reply(
                    icmp, echo_reply=profile.echo_reply, ip_header_in_payload=False, match_identifier=match_identifier
                )
                if parsed is not None and parsed[0] == sequence:
                    ttl = ttl_from_ancdata(ancdata, level=profile.ttl_cmsg_level, kind=profile.ttl_cmsg_type)
                    return ttl, parsed[2]
            else:
                packet, _ = sock.recvfrom(2048)
                parsed = parse_echo_reply(
                    packet, echo_reply=profile.echo_reply, ip_header_in_payload=True, match_identifier=match_identifier
                )
                if parsed is not None and parsed[0] == sequence:
                    return parsed[1], parsed[2]
        except TimeoutError:
            break
    return None


def open_icmp_socket(family: int, /, *, is_ipv6: bool, force_raw: bool) -> tuple[socket.Socket, bool]:
    """
    Open the ICMP socket the way Linux 'ping' does: prefer the
    unprivileged 'SOCK_DGRAM' ping socket, falling back to a 'SOCK_RAW'
    socket. A custom identifier forces 'SOCK_RAW', since the kernel owns
    the id on a ping socket. Returns the socket and whether it is the
    datagram flavour.
    """

    proto = socket.IPPROTO_ICMPV6 if is_ipv6 else socket.IPPROTO_ICMP
    if not force_raw:
        try:
            return socket.socket(family, socket.SOCK_DGRAM, proto), True
        except OSError:
            pass  # fall back to raw, exactly as 'ping' does
    return socket.socket(family, socket.SOCK_RAW, proto), False


def open_ping_socket(*, is_ipv6: bool, force_raw: bool, identifier: int) -> tuple[socket.Socket, bool, int | None]:
    """
    Open and configure the ICMP Echo socket for a ping session, returning
    '(socket, use_cmsg, match_identifier)'. 'use_cmsg' is True when the
    reply TTL / Hop Limit arrives via an IP_TTL / IPV6_RECVHOPLIMIT
    control message (every path except a v4 raw socket, which prepends the
    IP header) — the corresponding receive option is enabled here.
    'match_identifier' is the id to filter replies by on a raw socket
    (None on a datagram ping socket, where the kernel owns the id).
    """

    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock, is_dgram = open_icmp_socket(int(family), is_ipv6=is_ipv6, force_raw=force_raw)
    use_cmsg = is_dgram or is_ipv6
    if use_cmsg:
        level = socket.IPPROTO_IPV6 if is_ipv6 else socket.IPPROTO_IP
        option = socket.IPV6_RECVHOPLIMIT if is_ipv6 else socket.IP_RECVTTL
        sock.setsockopt(level, option, 1)
    return sock, use_cmsg, (None if is_dgram else identifier)


def resolve_destination(destination: str, /) -> tuple[bool, str]:
    """
    Classify 'destination' and resolve it to '(is_ipv6, ip_address)'. An
    IP literal is recognised directly via 'net_addr' (no DNS round trip);
    anything else is treated as a hostname and resolved through
    'getaddrinfo' (the daemon's DNS resolver).
    """

    try:
        return True, str(Ip6Address(destination))
    except Ip6AddressFormatError:
        pass
    try:
        return False, str(Ip4Address(destination))
    except Ip4AddressFormatError:
        pass
    family, _type, _proto, _canon, sockaddr = socket.getaddrinfo(destination, None)[0]
    return family == socket.AF_INET6, sockaddr[0]


def run_ping(
    sock: socket.Socket,
    profile: IcmpEchoProfile,
    /,
    *,
    address: str,
    identifier: int,
    count: int | None,
    interval: float,
    timeout: float,
    size: int,
    use_cmsg: bool,
    match_identifier: int | None,
) -> Iterator[PingOutcome]:
    """
    Drive 'sock' through the Echo Request / Reply loop against 'address',
    yielding one 'PingOutcome' per sequence number until 'count' is
    reached (or forever when 'count' is None). The caller owns socket
    construction, teardown, and output formatting; this generator owns the
    request build, the bounded wait, and the inter-request pacing.
    """

    sequence = 0
    while count is None or sequence < count:
        sequence += 1
        request = build_echo_request(profile, identifier=identifier, sequence=sequence, size=size)
        sock.sendto(request, (address, 0))

        reply = _recv_one_reply(
            sock,
            profile,
            use_cmsg=use_cmsg,
            match_identifier=match_identifier,
            sequence=sequence,
            timeout=timeout,
        )

        if reply is None:
            yield PingOutcome(sequence=sequence, ttl=None, rtt_ms=None, timed_out=True)
        else:
            ttl, send_time = reply
            yield PingOutcome(
                sequence=sequence,
                ttl=ttl,
                rtt_ms=(time.monotonic() - send_time) * 1000.0,
                timed_out=False,
            )

        if count is None or sequence < count:
            time.sleep(interval)


def format_ping_line(outcome: PingOutcome, /, *, address: str, size: int) -> str:
    """
    Render a single 'PingOutcome' as a Linux-'ping'-style reply or
    timeout line.
    """

    if outcome.timed_out:
        return f"Request timeout for icmp_seq {outcome.sequence}"
    ttl_text = "?" if outcome.ttl is None else str(outcome.ttl)
    return (
        f"{size + 8} bytes from {address}: " f"icmp_seq={outcome.sequence} ttl={ttl_text} time={outcome.rtt_ms:.2f} ms"
    )


def format_ping_summary(destination: str, outcomes: list[PingOutcome], /) -> str:
    """
    Render the closing Linux-'ping'-style statistics block from the
    collected outcomes.
    """

    transmitted = len(outcomes)
    round_trips = [outcome.rtt_ms for outcome in outcomes if outcome.rtt_ms is not None]
    received = len(round_trips)
    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    lines = [
        f"--- {destination} ping statistics ---",
        f"{transmitted} packets transmitted, {received} received, {loss:.0f}% packet loss",
    ]
    if round_trips:
        average = sum(round_trips) / len(round_trips)
        lines.append(f"rtt min/avg/max = {min(round_trips):.2f}/{average:.2f}/{max(round_trips):.2f} ms")
    return "\n".join(lines)


def default_identifier(identifier: int | None, /) -> int:
    """
    Resolve the ICMP identifier: an explicit value, or the low 16 bits of
    the process id (Linux 'ping' default), used when the kernel does not
    own the id (raw mode).
    """

    return identifier if identifier is not None else (os.getpid() & 0xFFFF)
