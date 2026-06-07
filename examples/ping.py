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
This module contains a ping (ICMP Echo) tool for the PyTCP daemon, built
on the daemon-backed 'pytcp.socket' drop-in, 'net_addr', and Click.

The destination may be an IPv4 / IPv6 address — classified directly via
'net_addr' — or a hostname, resolved through the daemon's DNS resolver;
the IP version drives ICMPv4 (Echo 8/0) vs ICMPv6 (Echo 128/129). Socket
selection mirrors Linux 'ping': by default it uses the unprivileged ICMP
datagram socket and falls back to a raw socket if that is refused;
'-e IDENTIFIER' forces a raw socket (a custom id needs SOCK_RAW, since the
kernel owns the id on a ping socket). On the datagram socket the kernel
owns the ICMP id, demuxes replies by it, hands back the ICMP message only
(no IP header), and reports the reply TTL / Hop Limit through an 'IP_TTL'
/ 'IPV6_HOPLIMIT' control message.

Needs a running daemon (it owns the TAP interface), e.g.:

    sudo make tap7 && sudo make bridge
    pytcp stack start -i tap7

examples/ping.py

ver 3.0.8
"""

import os
import struct
import time
from typing import NamedTuple, override

import click

from net_addr import Ip4Address, Ip4AddressFormatError, Ip6Address, Ip6AddressFormatError
from pytcp import socket

ICMP__HEADER__STRUCT: str = "!BBHHH"
TIMESTAMP__STRUCT: str = "!d"
TIMESTAMP__LEN: int = 8

BANNER: str = "PyTCP ping tool — ICMP Echo (ping) over the PyTCP daemon"


class _BannerCommand(click.Command):
    """
    A Click command whose '--help' is framed by a leading blank line, a
    bright-green banner, and a trailing blank line.
    """

    @override
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        formatter.write("\n")
        formatter.write(click.style(BANNER, fg="bright_green", bold=True))
        formatter.write("\n\n")
        super().format_help(ctx, formatter)

    @override
    def get_help(self, ctx: click.Context) -> str:
        # Click rstrips trailing newlines from the help, so append one
        # here for the trailing blank line ('echo' adds the final newline).
        return super().get_help(ctx) + "\n"


class _IcmpProfile(NamedTuple):
    """
    The per-IP-version wire-format values that drive an ICMP Echo
    exchange. These are plain integers / booleans; the stack-specific
    socket-construction constants (family / proto / setsockopt level) stay
    in the command body so they keep their native 'pytcp' types. The cmsg
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


def _open_icmp_socket(family: int, /, *, is_ipv6: bool, force_raw: bool) -> tuple[socket.Socket, bool]:
    """
    Open the ICMP socket the way Linux 'ping' does: prefer the
    unprivileged 'SOCK_DGRAM' ping socket (no elevated privilege when the
    destination is within 'net.ipv4.ping_group_range'), falling back to a
    'SOCK_RAW' socket. A custom identifier ('-e') forces 'SOCK_RAW', since
    the kernel owns the id on a ping socket. Returns the socket and whether
    it is the datagram flavour.
    """

    proto = socket.IPPROTO_ICMPV6 if is_ipv6 else socket.IPPROTO_ICMP
    if not force_raw:
        try:
            return socket.socket(family, socket.SOCK_DGRAM, proto), True
        except OSError:
            pass  # fall back to raw, exactly as 'ping' does
    return socket.socket(family, socket.SOCK_RAW, proto), False


def _resolve(destination: str, /) -> tuple[bool, str]:
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


@click.command(cls=_BannerCommand, context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("destination")
@click.option(
    "-e",
    "--identifier",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    metavar="ID",
    help="ICMP identifier; implies a raw (SOCK_RAW) socket.",
)
@click.option("-c", "--count", type=click.IntRange(min=1), default=None, help="Stop after COUNT requests.")
@click.option("-i", "--interval", type=float, default=1.0, show_default=True, help="Seconds between requests.")
@click.option("-W", "--timeout", type=float, default=1.0, show_default=True, help="Seconds to wait per reply.")
@click.option(
    "-s",
    "--size",
    type=click.IntRange(min=TIMESTAMP__LEN),
    default=56,
    show_default=True,
    help="Payload size in bytes.",
)
def ping(
    destination: str, identifier: int | None, count: int | None, interval: float, timeout: float, size: int
) -> None:
    """
    Send ICMP Echo Requests to DESTINATION (an IPv4 / IPv6 address or
    hostname) and report the replies, in the style of the 'ping' utility.
    """

    is_ipv6, address = _resolve(destination)
    profile = _profile_for(is_ipv6)

    # A custom identifier (-e) requires a raw socket, since the kernel owns
    # the id on a SOCK_DGRAM ping socket (Linux 'ping -e' implies SOCK_RAW).
    icmp_id = identifier if identifier is not None else (os.getpid() & 0xFFFF)
    sock, is_dgram = _open_icmp_socket(
        socket.AF_INET6 if is_ipv6 else socket.AF_INET, is_ipv6=is_ipv6, force_raw=identifier is not None
    )

    # A v4 raw socket reads the TTL from the prepended IP header; every
    # other path (the ping socket, and a v6 raw socket — which carries no
    # IP header) reads it from an IP_TTL / IPV6_HOPLIMIT control message.
    use_cmsg = is_dgram or is_ipv6
    # Raw sockets see all matching ICMP traffic, so filter replies by our
    # id; a ping socket is demuxed by the kernel, which owns the id.
    match_identifier = None if is_dgram else icmp_id

    if use_cmsg:
        recv_ttl_level = socket.IPPROTO_IPV6 if is_ipv6 else socket.IPPROTO_IP
        recv_ttl_opt = socket.IPV6_RECVHOPLIMIT if is_ipv6 else socket.IP_RECVTTL
        sock.setsockopt(recv_ttl_level, recv_ttl_opt, 1)

    transmitted = 0
    received = 0
    round_trips: list[float] = []

    click.echo(f"PING {destination} ({address}): {size} data bytes")
    try:
        sequence = 0
        while count is None or sequence < count:
            sequence += 1
            request = _build_echo_request(profile, identifier=icmp_id, sequence=sequence, size=size)
            sock.sendto(request, (address, 0))
            transmitted += 1

            reply = _recv_one_reply(
                sock,
                profile,
                use_cmsg=use_cmsg,
                match_identifier=match_identifier,
                sequence=sequence,
                timeout=timeout,
            )

            if reply is None:
                click.secho(f"Request timeout for icmp_seq {sequence}", fg="yellow")
            else:
                ttl, send_time = reply
                round_trip_ms = (time.monotonic() - send_time) * 1000.0
                received += 1
                round_trips.append(round_trip_ms)
                ttl_text = "?" if ttl is None else str(ttl)
                click.echo(
                    f"{size + 8} bytes from {address}: icmp_seq={sequence} ttl={ttl_text} time={round_trip_ms:.2f} ms"
                )

            if count is None or sequence < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        click.echo()
    finally:
        sock.close()

    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    click.echo(f"\n--- {destination} ping statistics ---")
    click.secho(
        f"{transmitted} packets transmitted, {received} received, {loss:.0f}% packet loss",
        fg="green" if loss == 0.0 else "red",
    )
    if round_trips:
        average = sum(round_trips) / len(round_trips)
        click.echo(f"rtt min/avg/max = {min(round_trips):.2f}/{average:.2f}/{max(round_trips):.2f} ms")


if __name__ == "__main__":
    ping()  # pylint: disable=no-value-for-parameter  # click injects the arguments
