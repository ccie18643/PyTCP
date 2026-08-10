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

ver 3.0.9
"""

import shutil
import struct
import subprocess
import time
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
        # An IPv4 fragment (non-zero offset, or MF set on the first
        # fragment) carries no complete L4 header, so render it as a
        # fragment — id, this-fragment length, byte offset, '+' for more —
        # rather than mis-parsing a partial L4 header.
        if ip4.offset > 0 or ip4.flag_mf:
            more = "+" if ip4.flag_mf else ""
            return f"{src} > {dst}: {proto}, frag {ip4.id}:{ip4.payload_len}@{ip4.offset}{more}"

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


def _describe_raw_ip(frame: bytes, /) -> str:
    """
    Render a bare IP packet — a capture with no link-layer header, as the
    loopback interface delivers (DLT_RAW-style). The IP version nibble
    selects the parser. Falls back to a length-tagged line on anything
    that is not a parseable IPv4 / IPv6 packet.
    """

    packet_rx = PacketRx(frame)
    # A bare IP capture is loopback / DLT_RAW traffic, where a loopback
    # source address (127.0.0.1 / ::1) is legitimate; mark it so the IP
    # parser skips the wire-ingress loopback-source martian check.
    packet_rx.from_loopback = True
    try:
        match frame[0] >> 4 if frame else 0:
            case 4:
                Ip4Parser(packet_rx)
                return "IP " + _describe_ip(packet_rx, is_ip6=False)
            case 6:
                Ip6Parser(packet_rx)
                return "IP6 " + _describe_ip(packet_rx, is_ip6=True)
            case _:
                return f"(unparsable frame, length {len(frame)})"
    except PacketValidationError:
        return f"(unparsable frame, length {len(frame)})"


def describe_frame(frame: bytes, /) -> str:
    """
    Decode a captured frame into a compact, tcpdump-style one-line
    summary. Handles both Ethernet II frames and bare IP packets (the
    loopback interface has no link layer). Never raises: a frame the
    parsers reject yields a length-tagged fallback so a capture loop
    cannot die on a bad frame.
    """

    packet_rx = PacketRx(frame)
    try:
        EthernetParser(packet_rx)
    except PacketValidationError:
        # Not an Ethernet frame — decode it as a bare IP packet (loopback
        # / DLT_RAW capture), else a length-tagged fallback.
        return _describe_raw_ip(frame)

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
                # An unknown ethertype on a frame whose first nibble is an
                # IP version is a bare IP packet mis-read as Ethernet — a
                # loopback / DLT_RAW capture (no link layer). Decode it as
                # raw IP rather than as an opaque unknown-ethertype frame.
                if frame and frame[0] >> 4 in (4, 6):
                    return _describe_raw_ip(frame)
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


# --- tshark decode feed -------------------------------------------------
#
# 'pytcp tcpdump' captures frames the daemon sees (including stack-internal
# loopback, which no external tool can reach) and — when tshark is
# installed — pipes them to a 'tshark -r -' subprocess for its richer
# decode / output. The frames are wrapped in a classic little-endian
# libpcap stream: a 24-byte global header (EN10MB link type) then a
# 16-byte record header per frame. A bare IP packet (a loopback capture
# has no link layer) is wrapped in a zero-MAC Ethernet header so the
# single-link-type stream carries it, exactly as Linux presents 'lo'.

PCAP__MAGIC: int = 0xA1B2C3D4
PCAP__VERSION_MAJOR: int = 2
PCAP__VERSION_MINOR: int = 4
PCAP__SNAPLEN: int = 65535
PCAP__DLT_EN10MB: int = 1
PCAP__GLOBAL_HEADER__STRUCT: str = "<IHHiIII"
PCAP__RECORD_HEADER__STRUCT: str = "<IIII"


def pcap_global_header() -> bytes:
    """
    Build the classic little-endian libpcap global header declaring the
    EN10MB (Ethernet) link type — written once at the head of the stream
    fed to 'tshark -r -'.
    """

    return struct.pack(
        PCAP__GLOBAL_HEADER__STRUCT,
        PCAP__MAGIC,
        PCAP__VERSION_MAJOR,
        PCAP__VERSION_MINOR,
        0,
        0,
        PCAP__SNAPLEN,
        PCAP__DLT_EN10MB,
    )


def pcap_record(frame: bytes, /, *, seconds: int, micros: int) -> bytes:
    """
    Frame a captured packet as a libpcap record: a 16-byte header carrying
    the timestamp and the captured / original lengths, then the bytes.
    """

    return struct.pack(PCAP__RECORD_HEADER__STRUCT, seconds, micros, len(frame), len(frame)) + frame


def frame_for_pcap(frame: bytes, /) -> bytes:
    """
    Return the frame ready for the EN10MB pcap stream. An Ethernet frame is
    returned verbatim; a bare IP packet (a loopback capture has no link
    layer) is wrapped in a zero-MAC Ethernet header carrying the IP-version
    ethertype, so the single-link-type stream can carry it.
    """

    if not _looks_like_bare_ip(frame):
        return frame
    ethertype = EtherType.IP4 if frame[0] >> 4 == 4 else EtherType.IP6
    return bytes(6) + bytes(6) + int(ethertype).to_bytes(2) + frame


def _looks_like_bare_ip(frame: bytes, /) -> bool:
    """
    Report whether 'frame' is a bare IP packet (no link-layer header) — an
    Ethernet parse that fails, or succeeds only with an unknown ethertype,
    on a frame whose first nibble is an IP version. Mirrors the raw-IP
    detection in 'describe_frame'.
    """

    if not frame or frame[0] >> 4 not in (4, 6):
        return False
    packet_rx = PacketRx(frame)
    try:
        EthernetParser(packet_rx)
    except PacketValidationError:
        return True
    return packet_rx.ethernet.type not in (EtherType.ARP, EtherType.IP4, EtherType.IP6)


def tshark_available() -> bool:
    """
    Report whether the 'tshark' binary is on PATH (the richer decode path).
    """

    return shutil.which("tshark") is not None


def stream_via_tshark(sock: CaptureSocket, /, *, count: int | None = None) -> int:
    """
    Capture frames off 'sock' and stream them, pcap-framed, to a
    'tshark -r -' subprocess whose decoded output goes straight to this
    process's stdout. Returns the number of frames fed. The tshark process
    inherits stdout so its line-buffered ('-l') decode prints live; name
    resolution is off ('-n') so a capture never blocks on DNS.
    """

    proc = subprocess.Popen(
        ["tshark", "-r", "-", "-l", "-n"],
        stdin=subprocess.PIPE,
    )
    assert proc.stdin is not None
    fed = 0
    try:
        proc.stdin.write(pcap_global_header())
        proc.stdin.flush()
        while count is None or fed < count:
            try:
                frame, _sockaddr_ll = sock.recvfrom()
            except BlockingIOError, TimeoutError:
                continue
            now = time.time()
            record = pcap_record(frame_for_pcap(frame), seconds=int(now), micros=int(now % 1 * 1_000_000))
            try:
                proc.stdin.write(record)
                proc.stdin.flush()
            except BrokenPipeError:
                break
            fed += 1
    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass
        proc.wait()
    return fed
