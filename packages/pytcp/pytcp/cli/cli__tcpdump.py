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
This module contains the daemon-independent engine for the 'pytcp tcpdump'
capture command: a pure frame decoder ('describe_frame') that renders a
link-layer frame as a compact tcpdump-style summary, a direction-prefixed
line formatter ('format_capture_line'), and the 'run_tcpdump' loop that
streams decoded lines off a capture socket. The socket itself (an
AF_PACKET 'ClientPacketSocket') is opened by the CLI veneer; this module
only needs the small 'CaptureSocket' surface, so the decode / format logic
is unit-tested with crafted frames and no daemon.

pytcp/cli/cli__tcpdump.py

ver 3.0.8
"""

from collections.abc import Callable, Iterator
from typing import Protocol

from net_addr import IpAddress
from net_proto import (
    ArpOperation,
    EthernetParser,
    EtherType,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from net_proto.protocols.arp.arp__base import Arp
from net_proto.protocols.arp.arp__parser import ArpParser
from net_proto.protocols.icmp4.icmp4__parser import Icmp4Parser
from net_proto.protocols.icmp6.icmp6__parser import Icmp6Parser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.tcp.tcp__base import Tcp
from net_proto.protocols.tcp.tcp__parser import TcpParser
from net_proto.protocols.udp.udp__parser import UdpParser
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


class CaptureSocket(Protocol):
    """
    The minimal capture-socket surface 'run_tcpdump' consumes: a blocking
    'recvfrom' returning a '(frame, sockaddr_ll)' pair.
    """

    def recvfrom(self) -> tuple[bytes, SockAddrLl]: ...


def _tcp_flags(tcp: Tcp, /) -> str:
    """
    Render the set TCP control flags as a compact tcpdump-style block —
    'S' SYN, 'F' FIN, 'R' RST, 'P' PSH, '.' ACK, 'U' URG — or 'none'.
    """

    flags = "".join(
        char
        for char, is_set in (
            ("S", tcp.flag_syn),
            ("F", tcp.flag_fin),
            ("R", tcp.flag_rst),
            ("P", tcp.flag_psh),
            (".", tcp.flag_ack),
            ("U", tcp.flag_urg),
        )
        if is_set
    )
    return flags or "none"


def _describe_arp(arp: Arp, /) -> str:
    """
    Render an ARP message in tcpdump form: 'who-has ... tell ...' for a
    request, 'is-at' for a reply.
    """

    match arp.oper:
        case ArpOperation.REQUEST:
            return f"ARP, Request who-has {arp.tpa} tell {arp.spa}"
        case ArpOperation.REPLY:
            return f"ARP, Reply {arp.spa} is-at {arp.sha}"
        case _:
            return f"ARP, {arp.oper} {arp.spa} > {arp.tpa}"


def _describe_ip(packet_rx: PacketRx, /, *, is_ip6: bool) -> str:
    """
    Render the IPv4 / IPv6 payload as a compact endpoint summary: ports and
    flags / length for TCP and UDP, otherwise the next-protocol name and the
    IP payload length. The IP header has already been parsed onto
    'packet_rx'.
    """

    src: IpAddress
    dst: IpAddress
    if is_ip6:
        ip6 = packet_rx.ip6
        src, dst, proto = ip6.src, ip6.dst, ip6.next
    else:
        ip4 = packet_rx.ip4
        src, dst, proto = ip4.src, ip4.dst, ip4.proto

    if proto is IpProto.TCP:
        TcpParser(packet_rx)
        tcp = packet_rx.tcp
        return f"{src}.{tcp.sport} > {dst}.{tcp.dport}: Flags [{_tcp_flags(tcp)}], length {len(tcp.payload)}"

    if proto is IpProto.UDP:
        UdpParser(packet_rx)
        udp = packet_rx.udp
        return f"{src}.{udp.sport} > {dst}.{udp.dport}: UDP, length {len(udp.payload)}"

    if proto is IpProto.ICMP4:
        Icmp4Parser(packet_rx)
        return f"{src} > {dst}: {packet_rx.icmp4.message}"

    if proto is IpProto.ICMP6:
        Icmp6Parser(packet_rx)
        return f"{src} > {dst}: {packet_rx.icmp6.message}"

    return f"{src} > {dst}: {proto}, length {packet_rx.ip.payload_len}"


def describe_frame(frame: bytes, /) -> str:
    """
    Decode a complete link-layer frame into a compact, tcpdump-style
    one-line summary. Never raises: a frame the parsers reject yields a
    length-tagged fallback so a capture loop cannot die on a bad frame.
    """

    packet_rx = PacketRx(frame)
    try:
        EthernetParser(packet_rx)
    except PacketValidationError:
        return f"(unparsable frame, length {len(frame)})"

    ethertype = packet_rx.ethernet.type
    try:
        match ethertype:
            case EtherType.ARP:
                ArpParser(packet_rx)
                return _describe_arp(packet_rx.arp)
            case EtherType.IP4:
                Ip4Parser(packet_rx)
                return "IP " + _describe_ip(packet_rx, is_ip6=False)
            case EtherType.IP6:
                Ip6Parser(packet_rx)
                return "IP6 " + _describe_ip(packet_rx, is_ip6=True)
            case _:
                return f"{ethertype}, length {len(frame)}"
    except PacketValidationError:
        return f"{ethertype}, length {len(frame)} (truncated)"


def format_capture_line(*, pkttype: PacketType, frame: bytes, timestamp: float | None = None) -> str:
    """
    Format one capture line: an optional fixed-width relative-seconds
    timestamp column, then a direction tag — 'Out' for an egress frame
    (pkttype PACKET_OUTGOING, the direction the AF_PACKET TX tap makes
    visible), 'In' otherwise — followed by the decoded frame summary.
    """

    direction = "Out" if pkttype is PacketType.PACKET_OUTGOING else "In"
    stamp = "" if timestamp is None else f"{timestamp:9.6f} "
    return f"{stamp}{direction} {describe_frame(frame)}"


def run_tcpdump(
    sock: CaptureSocket,
    /,
    *,
    count: int | None = None,
    clock: Callable[[], float] | None = None,
) -> Iterator[str]:
    """
    Stream decoded capture lines off 'sock' until 'count' frames have been
    emitted (or forever when 'count' is None). A read that times out is
    retried so a timeout-armed socket stays responsive to interruption. When
    'clock' is supplied, each line carries a relative-seconds timestamp
    rebased so the first captured frame reads 0.0 s.
    """

    emitted = 0
    epoch: float | None = None
    while count is None or emitted < count:
        try:
            frame, sockaddr_ll = sock.recvfrom()
        except BlockingIOError, TimeoutError:
            continue
        timestamp: float | None = None
        if clock is not None:
            now = clock()
            if epoch is None:
                epoch = now
            timestamp = now - epoch
        yield format_capture_line(pkttype=sockaddr_ll.pkttype, frame=frame, timestamp=timestamp)
        emitted += 1
