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
This module contains the peer-side TCP segment builder used by the
TCP session integration tests to synthesize ingress frames.

pytcp/tests/lib/tcp_segment_factory.py

ver 3.0.8
"""

from collections.abc import Iterable

from net_addr import Buffer, Ip4Address, Ip6Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.tcp.options.tcp__option import TcpOption
from net_proto.protocols.tcp.options.tcp__option__accecn0 import TcpOptionAccecn0
from net_proto.protocols.tcp.options.tcp__option__fastopen import TcpOptionFastOpen
from net_proto.protocols.tcp.options.tcp__option__mss import TcpOptionMss
from net_proto.protocols.tcp.options.tcp__option__nop import TcpOptionNop
from net_proto.protocols.tcp.options.tcp__option__sack import (
    TcpOptionSack,
    TcpSackBlock,
)
from net_proto.protocols.tcp.options.tcp__option__sackperm import TcpOptionSackperm
from net_proto.protocols.tcp.options.tcp__option__timestamps import TcpOptionTimestamps
from net_proto.protocols.tcp.options.tcp__option__wscale import TcpOptionWscale
from net_proto.protocols.tcp.options.tcp__options import TcpOptions
from net_proto.protocols.tcp.tcp__assembler import TcpAssembler
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

TCP_FLAGS__VALID: frozenset[str] = frozenset({"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "NS"})


def _build_tcp_assembler(
    *,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: Iterable[str],
    win: int,
    mss: int | None,
    wscale: int | None,
    sackperm: bool,
    sack_blocks: Iterable[tuple[int, int]] | None,
    tsval: int | None,
    tsecr: int | None,
    fastopen_cookie: bytes | None,
    accecn0_counters: tuple[int | None, int | None, int | None] | None,
    payload: Buffer,
) -> TcpAssembler:
    """
    Build the inner 'TcpAssembler' carrying the requested header
    fields, options, and payload. Validates the 'flags' set against
    the supported names.
    """

    flag_set = frozenset(flags)
    unknown = flag_set - TCP_FLAGS__VALID
    assert not unknown, f"Unknown TCP flag name(s) {sorted(unknown)!r}; supported: {sorted(TCP_FLAGS__VALID)!r}"

    options = _build_options(
        mss=mss,
        wscale=wscale,
        sackperm=sackperm,
        sack_blocks=sack_blocks,
        tsval=tsval,
        tsecr=tsecr,
        fastopen_cookie=fastopen_cookie,
        accecn0_counters=accecn0_counters,
    )

    return TcpAssembler(
        tcp__sport=sport,
        tcp__dport=dport,
        tcp__seq=seq,
        tcp__ack=ack,
        tcp__flag_syn="SYN" in flag_set,
        tcp__flag_ack="ACK" in flag_set,
        tcp__flag_fin="FIN" in flag_set,
        tcp__flag_rst="RST" in flag_set,
        tcp__flag_psh="PSH" in flag_set,
        tcp__flag_urg="URG" in flag_set,
        tcp__flag_ece="ECE" in flag_set,
        tcp__flag_cwr="CWR" in flag_set,
        tcp__flag_ns="NS" in flag_set,
        tcp__win=win,
        tcp__options=options,
        tcp__payload=payload,
    )


def _build_options(
    *,
    mss: int | None,
    wscale: int | None,
    sackperm: bool,
    sack_blocks: Iterable[tuple[int, int]] | None,
    tsval: int | None,
    tsecr: int | None,
    fastopen_cookie: bytes | None,
    accecn0_counters: tuple[int | None, int | None, int | None] | None,
) -> TcpOptions:
    """
    Build a 'TcpOptions' container holding the requested MSS,
    WSCALE, SACK-permitted, SACK, Timestamps, and Fast Open
    options, padding with NOPs so the total option block length
    is a multiple of 4 bytes (TCP requires 4-byte alignment of
    the data offset). Timestamps requires both 'tsval' and
    'tsecr' to be supplied together (the wire option carries
    both fields).

    'fastopen_cookie' supplies the RFC 7413 §2 TFO option
    payload: 'None' omits the option, 'b""' emits the empty-
    cookie request form (Length=2), and a 4-16 byte value
    emits the cookie use/response form (Length=2+N).
    """

    options: list[TcpOption] = []

    if mss is not None:
        options.append(TcpOptionMss(mss=mss))

    if wscale is not None:
        options.append(TcpOptionWscale(wscale=wscale))

    if sackperm:
        options.append(TcpOptionSackperm())

    if sack_blocks is not None:
        options.append(TcpOptionSack(blocks=[TcpSackBlock(left, right) for left, right in sack_blocks]))

    if tsval is not None or tsecr is not None:
        assert tsval is not None and tsecr is not None, (
            "'tsval' and 'tsecr' MUST be supplied together; the "
            "Timestamps option is a single 10-byte option carrying "
            "both fields."
        )
        options.append(TcpOptionTimestamps(tsval=tsval, tsecr=tsecr))

    if fastopen_cookie is not None:
        options.append(TcpOptionFastOpen(cookie=fastopen_cookie))

    if accecn0_counters is not None:
        options.append(
            TcpOptionAccecn0(
                ee0b=accecn0_counters[0],
                eceb=accecn0_counters[1],
                ee1b=accecn0_counters[2],
            )
        )

    pad_count = (-sum(len(opt) for opt in options)) % 4
    options.extend(TcpOptionNop() for _ in range(pad_count))

    return TcpOptions(*options)


def build_tcp4(
    *,
    src_mac: MacAddress = HOST_A__MAC_ADDRESS,
    dst_mac: MacAddress = STACK__MAC_ADDRESS,
    src_ip: Ip4Address = HOST_A__IP4_ADDRESS,
    dst_ip: Ip4Address = STACK__IP4_HOST.address,
    ip_ecn: int = 0,
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: Iterable[str] = (),
    win: int = 65535,
    mss: int | None = None,
    wscale: int | None = None,
    sackperm: bool = False,
    sack_blocks: Iterable[tuple[int, int]] | None = None,
    tsval: int | None = None,
    tsecr: int | None = None,
    fastopen_cookie: bytes | None = None,
    accecn0_counters: tuple[int | None, int | None, int | None] | None = None,
    payload: Buffer = b"",
) -> bytes:
    """
    Build an Ethernet/IPv4/TCP frame with the supplied TCP fields and
    options and return it as raw bytes ready to feed into
    'PacketHandler._phrx_ethernet'.
    """

    tcp = _build_tcp_assembler(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        win=win,
        mss=mss,
        wscale=wscale,
        sackperm=sackperm,
        sack_blocks=sack_blocks,
        tsval=tsval,
        tsecr=tsecr,
        fastopen_cookie=fastopen_cookie,
        accecn0_counters=accecn0_counters,
        payload=payload,
    )

    ip4 = Ip4Assembler(
        ip4__src=src_ip,
        ip4__dst=dst_ip,
        ip4__ecn=ip_ecn,
        ip4__payload=tcp,
    )

    ethernet = EthernetAssembler(
        ethernet__src=src_mac,
        ethernet__dst=dst_mac,
        ethernet__payload=ip4,
    )

    buffers: list[Buffer] = []
    ethernet.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


def build_tcp6(
    *,
    src_mac: MacAddress = HOST_A__MAC_ADDRESS,
    dst_mac: MacAddress = STACK__MAC_ADDRESS,
    src_ip: Ip6Address = HOST_A__IP6_ADDRESS,
    dst_ip: Ip6Address = STACK__IP6_HOST.address,
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: Iterable[str] = (),
    win: int = 65535,
    mss: int | None = None,
    wscale: int | None = None,
    sackperm: bool = False,
    sack_blocks: Iterable[tuple[int, int]] | None = None,
    tsval: int | None = None,
    tsecr: int | None = None,
    fastopen_cookie: bytes | None = None,
    accecn0_counters: tuple[int | None, int | None, int | None] | None = None,
    payload: Buffer = b"",
) -> bytes:
    """
    Build an Ethernet/IPv6/TCP frame with the supplied TCP fields and
    options and return it as raw bytes ready to feed into
    'PacketHandler._phrx_ethernet'.
    """

    tcp = _build_tcp_assembler(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        win=win,
        mss=mss,
        wscale=wscale,
        sackperm=sackperm,
        sack_blocks=sack_blocks,
        tsval=tsval,
        tsecr=tsecr,
        fastopen_cookie=fastopen_cookie,
        accecn0_counters=accecn0_counters,
        payload=payload,
    )

    ip6 = Ip6Assembler(
        ip6__src=src_ip,
        ip6__dst=dst_ip,
        ip6__payload=tcp,
    )

    ethernet = EthernetAssembler(
        ethernet__src=src_mac,
        ethernet__dst=dst_mac,
        ethernet__payload=ip6,
    )

    buffers: list[Buffer] = []
    ethernet.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)
