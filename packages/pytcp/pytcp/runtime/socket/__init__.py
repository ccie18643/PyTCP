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
This package contains the PyTCP socket interface.

pytcp/runtime/socket/__init__.py

ver 3.0.8
"""

import errno
import os
import socket as _stdlib_socket
import struct
import sys
import threading
from abc import ABC
from collections.abc import Iterable
from enum import IntEnum
from types import TracebackType
from typing import Any, override

from net_addr import Buffer, Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import EtherType, IpProto
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN
from net_proto.protocols.ip4.options.ip4__options import (
    IP4__OPTIONS__MAX_LEN,
    Ip4Options,
)
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.lib.name_enum import NameEnum
from pytcp.runtime.socket.socket_id import SocketId

# BSD '<netinet/in.h>' default-protocol sentinel: socket(family,
# type, IPPROTO_IP) selects the kernel's default protocol for the
# requested socket type (TCP for STREAM, UDP for DGRAM). Decoupled
# from 'IpProto' because the IANA next-header value 0 is HOPOPT
# (IPv6 Hop-by-Hop, RFC 8200 §4.3), not "default IP".
IPPROTO_IP: int = 0

IPPROTO_IPIP = IpProto.IP4  # RFC 2003 IPv4-in-IPv4 (Linux: socket.IPPROTO_IPIP).
IPPROTO_ICMP = IpProto.ICMP4
IPPROTO_ICMP4 = IpProto.ICMP4
IPPROTO_TCP = IpProto.TCP
IPPROTO_UDP = IpProto.UDP
IPPROTO_IPV6 = IpProto.IP6
IPPROTO_IP6 = IpProto.IP6
IPPROTO_ICMPV6 = IpProto.ICMP6
IPPROTO_ICMP6 = IpProto.ICMP6
IPPROTO_RAW = IpProto.RAW


class SolLevel(IntEnum):
    """
    BSD setsockopt 'level' values for the socket-option levels that
    are not IP-protocol numbers (Linux 'SOL_*').
    """

    # Socket-level options (Linux number, matching stdlib
    # 'socket.SOL_SOCKET'). The TCP- / IP- / IPv6-level option
    # counterparts reuse 'IPPROTO_TCP' / 'IPPROTO_IP' /
    # 'IPPROTO_IPV6' as their level, keeping the existing surface.
    SOL_SOCKET = 1

    # UDP-level options (Linux number from <netinet/udp.h>, matching
    # stdlib 'socket.SOL_UDP' / 'socket.IPPROTO_UDP'). Used as the
    # 'level' for 'UDP_NO_CHECK6_TX' / 'UDP_NO_CHECK6_RX' (RFC 6935
    # §5 zero-cksum opt-in for tunnel encapsulations).
    SOL_UDP = 17


# Bare module-level aliases — match the Python stdlib socket module
# surface so 'from pytcp.runtime.socket import SOL_SOCKET' works exactly like
# 'from socket import SOL_SOCKET' (enums.md §2.2 stdlib parity).
SOL_SOCKET = SolLevel.SOL_SOCKET
SOL_UDP = SolLevel.SOL_UDP


class SocketOption(IntEnum):
    """
    BSD setsockopt 'optname' parameter values, by integer number
    matching Linux. Setsockopt validates the (level, optname)
    pair: socket-level options use 'SOL_SOCKET' as level, TCP-
    level options use 'IPPROTO_TCP'. SOL_SOCKET-level options
    that share an integer value with an IPPROTO_TCP-level option
    (e.g. SO_BROADCAST=6 vs TCP_KEEPCNT=6) live as plain ints
    below the enum to avoid IntEnum aliasing.
    """

    TCP_MAXSEG = 2  # level=IPPROTO_TCP; int: clamp negotiated SMSS (RFC 6691)
    TCP_NODELAY = 1  # level=IPPROTO_TCP; bool: disable Nagle (RFC 1122 §4.2.3.4)
    TCP_KEEPIDLE = 4  # level=IPPROTO_TCP; int seconds: per-conn idle override
    TCP_KEEPINTVL = 5  # level=IPPROTO_TCP; int seconds: per-conn probe interval override
    TCP_KEEPCNT = 6  # level=IPPROTO_TCP; int count: per-conn max probes override
    SO_KEEPALIVE = 9  # level=SOL_SOCKET; bool: enable keep-alive (RFC 1122 §4.2.3.6)
    TCP_INFO = 11  # level=IPPROTO_TCP; bytes: read-only struct tcp_info snapshot
    TCP_CONGESTION = 13  # level=IPPROTO_TCP; str: per-conn CC algorithm name (RFC 9438)
    TCP_USER_TIMEOUT = 18  # level=IPPROTO_TCP; int ms: per-conn data-unacked abort budget
    TCP_FASTOPEN = 23  # level=IPPROTO_TCP; int qlen: TFO accept-queue depth (RFC 7413)


TCP_MAXSEG = SocketOption.TCP_MAXSEG
TCP_NODELAY = SocketOption.TCP_NODELAY
SO_KEEPALIVE = SocketOption.SO_KEEPALIVE
TCP_KEEPIDLE = SocketOption.TCP_KEEPIDLE
TCP_KEEPINTVL = SocketOption.TCP_KEEPINTVL
TCP_KEEPCNT = SocketOption.TCP_KEEPCNT
TCP_INFO = SocketOption.TCP_INFO
TCP_CONGESTION = SocketOption.TCP_CONGESTION
TCP_USER_TIMEOUT = SocketOption.TCP_USER_TIMEOUT
TCP_FASTOPEN = SocketOption.TCP_FASTOPEN


class SolSocketOption(IntEnum):
    """
    SOL_SOCKET-level setsockopt 'optname' values that share
    integer space with IPPROTO_TCP-level options (Linux
    numbers from <sys/socket.h>; disambiguated by the
    'level' parameter of setsockopt, not by the optname
    value itself). The 'TCP_*' family lives on
    'SocketOption' above; this enum holds the rest of the
    socket-level surface that PyTCP supports.
    """

    SO_REUSEADDR = 2  # bool: bypass "address in use" on rebind
    SO_ERROR = 4  # int: pending socket error, read-and-clear (getsockopt only; non-blocking connect SO_ERROR edge)
    SO_BROADCAST = 6  # bool: allow UDP broadcast send
    SO_SNDBUF = 7  # int: send-buffer cap (storage only)
    SO_RCVBUF = 8  # int: recv-buffer cap (storage only)
    SO_OOBINLINE = 10  # bool: deliver TCP urgent in-band (PyTCP universally 1; RFC 6093 §6)
    SO_LINGER = 13  # struct linger {l_onoff, l_linger}: graceful / lingering / abortive close
    SO_REUSEPORT = 15  # bool: allow multiple sockets to bind the same (ip, port); load-balanced demux
    SO_RCVTIMEO = 20  # float seconds: persistent recv timeout
    SO_SNDTIMEO = 21  # float seconds: persistent send timeout
    SO_BINDTODEVICE = 25  # bytes: pin socket egress / RX to an interface by name


SO_REUSEADDR = SolSocketOption.SO_REUSEADDR
SO_ERROR = SolSocketOption.SO_ERROR
SO_BROADCAST = SolSocketOption.SO_BROADCAST
SO_SNDBUF = SolSocketOption.SO_SNDBUF
SO_RCVBUF = SolSocketOption.SO_RCVBUF
SO_OOBINLINE = SolSocketOption.SO_OOBINLINE
SO_LINGER = SolSocketOption.SO_LINGER
SO_REUSEPORT = SolSocketOption.SO_REUSEPORT
SO_RCVTIMEO = SolSocketOption.SO_RCVTIMEO
SO_SNDTIMEO = SolSocketOption.SO_SNDTIMEO
SO_BINDTODEVICE = SolSocketOption.SO_BINDTODEVICE


class IpOption(IntEnum):
    """
    IPPROTO_IP-level setsockopt 'optname' values (Linux
    numbers from <netinet/ip.h>; matches Python stdlib
    'socket.IP_*' module-level constants on Linux).
    """

    IP_TOS = 1  # int: 8-bit DSCP+ECN (RFC 2474)
    IP_TTL = 2  # int 1-255: per-socket TTL override
    IP_OPTIONS = 4  # bytes: 0-40 raw IPv4 options block (RFC 1122 §4.1.3.2)
    IP_RECVOPTS = 6  # int 0/1: enable IP_OPTIONS cmsg on recvmsg (RFC 1122 §4.1.3.2)
    IP_RETOPTS = 7  # int 0/1: deprecated alias of IP_RECVOPTS (Linux compat)
    IP_RECVERR = 11  # int 0/1: enable error queue (recvmsg MSG_ERRQUEUE — Linux ip(7))
    IP_RECVTTL = 12  # int 0/1: enable IP_TTL cmsg on recvmsg (Linux ip(7))
    IP_RECVTOS = 13  # int 0/1: enable IP_TOS cmsg on recvmsg (RFC 1122 §4.1.4 MAY)
    IP_MTU = 14  # int (getsockopt only): effective PMTU for connected peer (RFC 1122 §3.4 GET_MAXSIZES)
    IP_ADD_MEMBERSHIP = 35  # ip_mreq bytes: join an IPv4 multicast group (RFC 1112 / 3376)
    IP_DROP_MEMBERSHIP = 36  # ip_mreq bytes: leave an IPv4 multicast group (RFC 1112 / 3376)
    IP_UNBLOCK_SOURCE = 37  # ip_mreq_source bytes: unblock a source on an EXCLUDE-mode group (RFC 3376 / 3678)
    IP_BLOCK_SOURCE = 38  # ip_mreq_source bytes: block a source on an EXCLUDE-mode group (RFC 3376 / 3678)
    IP_ADD_SOURCE_MEMBERSHIP = 39  # ip_mreq_source bytes: join a group in INCLUDE mode for a source (RFC 3376 / 3678)
    IP_DROP_SOURCE_MEMBERSHIP = 40  # ip_mreq_source bytes: drop a source from an INCLUDE-mode group (RFC 3376 / 3678)


IP_TOS = IpOption.IP_TOS
IP_TTL = IpOption.IP_TTL
IP_OPTIONS = IpOption.IP_OPTIONS
IP_RECVOPTS = IpOption.IP_RECVOPTS
IP_RETOPTS = IpOption.IP_RETOPTS
IP_RECVERR = IpOption.IP_RECVERR
IP_RECVTTL = IpOption.IP_RECVTTL
IP_RECVTOS = IpOption.IP_RECVTOS
IP_MTU = IpOption.IP_MTU
IP_ADD_MEMBERSHIP = IpOption.IP_ADD_MEMBERSHIP
IP_DROP_MEMBERSHIP = IpOption.IP_DROP_MEMBERSHIP
IP_UNBLOCK_SOURCE = IpOption.IP_UNBLOCK_SOURCE
IP_BLOCK_SOURCE = IpOption.IP_BLOCK_SOURCE
IP_ADD_SOURCE_MEMBERSHIP = IpOption.IP_ADD_SOURCE_MEMBERSHIP
IP_DROP_SOURCE_MEMBERSHIP = IpOption.IP_DROP_SOURCE_MEMBERSHIP


class IpV6Option(IntEnum):
    """
    IPPROTO_IPV6-level setsockopt 'optname' values (Linux
    numbers from <netinet/in.h>; matches Python stdlib
    'socket.IPV6_*' module-level constants on Linux).
    """

    IPV6_UNICAST_HOPS = 16  # int 1-255: per-socket Hop-Limit override
    IPV6_JOIN_GROUP = 20  # ipv6_mreq bytes: join an IPv6 multicast group (RFC 3493 §5.2)
    IPV6_LEAVE_GROUP = 21  # ipv6_mreq bytes: leave an IPv6 multicast group (RFC 3493 §5.2)
    IPV6_MTU = 24  # int (getsockopt only): effective PMTU for connected peer
    IPV6_RECVERR = 25  # int 0/1: enable IPv6 error queue (recvmsg MSG_ERRQUEUE — Linux ipv6(7))
    IPV6_V6ONLY = 26  # int 0/1: AF_INET6 socket accepts IPv4-mapped peers when 0 (dual-stack)
    IPV6_RECVHOPLIMIT = 51  # int 0/1: enable IPV6_HOPLIMIT cmsg on recvmsg (RFC 3542 §6.3)
    IPV6_HOPLIMIT = 52  # int (cmsg only): received IPv6 Hop Limit (RFC 3542 §6.3)
    IPV6_RECVTCLASS = 66  # int 0/1: enable IPV6_TCLASS cmsg on recvmsg (RFC 3542 §6.5)
    IPV6_TCLASS = 67  # int: 8-bit Traffic Class (DSCP+ECN, RFC 2474)


IPV6_UNICAST_HOPS = IpV6Option.IPV6_UNICAST_HOPS
IPV6_JOIN_GROUP = IpV6Option.IPV6_JOIN_GROUP
IPV6_LEAVE_GROUP = IpV6Option.IPV6_LEAVE_GROUP
# Linux 'IPV6_ADD_MEMBERSHIP' / 'IPV6_DROP_MEMBERSHIP' are stdlib-
# socket aliases for the same integer values (20 / 21). Re-export
# both spellings so apps written for either API surface work
# unchanged.
IPV6_ADD_MEMBERSHIP = IpV6Option.IPV6_JOIN_GROUP
IPV6_DROP_MEMBERSHIP = IpV6Option.IPV6_LEAVE_GROUP
IPV6_MTU = IpV6Option.IPV6_MTU
IPV6_RECVERR = IpV6Option.IPV6_RECVERR
IPV6_V6ONLY = IpV6Option.IPV6_V6ONLY
IPV6_RECVHOPLIMIT = IpV6Option.IPV6_RECVHOPLIMIT
IPV6_HOPLIMIT = IpV6Option.IPV6_HOPLIMIT
IPV6_RECVTCLASS = IpV6Option.IPV6_RECVTCLASS
IPV6_TCLASS = IpV6Option.IPV6_TCLASS


class McastOption(IntEnum):
    """
    Protocol-independent multicast source-filter setsockopt 'optname'
    values (RFC 3678 / RFC 3810 §4.1), usable at both IPPROTO_IP and
    IPPROTO_IPV6 level with a 'group_source_req' struct. Linux numbers
    from <linux/in.h>; matches Python stdlib 'socket.MCAST_*' on
    platforms that expose them. PyTCP wires these at IPPROTO_IPV6 for
    IPv6 source-specific multicast; IPv4 uses the older 'IP_*_SOURCE_*'
    'ip_mreq_source' options.
    """

    MCAST_BLOCK_SOURCE = 43  # group_source_req: block a source on an EXCLUDE-mode group
    MCAST_UNBLOCK_SOURCE = 44  # group_source_req: unblock a source on an EXCLUDE-mode group
    MCAST_JOIN_SOURCE_GROUP = 46  # group_source_req: join a group in INCLUDE mode for a source
    MCAST_LEAVE_SOURCE_GROUP = 47  # group_source_req: drop a source from an INCLUDE-mode group


MCAST_BLOCK_SOURCE = McastOption.MCAST_BLOCK_SOURCE
MCAST_UNBLOCK_SOURCE = McastOption.MCAST_UNBLOCK_SOURCE
MCAST_JOIN_SOURCE_GROUP = McastOption.MCAST_JOIN_SOURCE_GROUP
MCAST_LEAVE_SOURCE_GROUP = McastOption.MCAST_LEAVE_SOURCE_GROUP


class UdpOption(IntEnum):
    """
    SOL_UDP-level setsockopt 'optname' values (Linux numbers
    from <linux/udp.h>; matches stdlib socket.UDP_* module-
    level constants on Linux). PyTCP currently supports the
    RFC 6935 §5 zero-cksum opt-in pair for tunnel
    encapsulations.
    """

    UDP_NO_CHECK6_TX = 101  # int 0/1: sender emits cksum=0 instead of computing
    UDP_NO_CHECK6_RX = 102  # int 0/1: receiver accepts inbound cksum=0 on this port


UDP_NO_CHECK6_TX = UdpOption.UDP_NO_CHECK6_TX
UDP_NO_CHECK6_RX = UdpOption.UDP_NO_CHECK6_RX


class MsgFlag(IntEnum):
    """
    MSG_* flag bits for recvmsg / recvfrom / sendmsg (Linux
    numbers from <sys/socket.h>; matches Python stdlib
    'socket.MSG_*' module-level constants on Linux). PyTCP
    currently honors MSG_ERRQUEUE only; other flags are
    reserved for future surface.
    """

    MSG_OOB = 0x0001  # Read 'out-of-band' urgent data. PyTCP universally inlines per RFC 6093 §6.
    MSG_ERRQUEUE = 0x2000


MSG_OOB = MsgFlag.MSG_OOB
MSG_ERRQUEUE = MsgFlag.MSG_ERRQUEUE

# 'struct sock_extended_err.ee_origin' values (Linux
# <linux/errqueue.h>) live as 'SoEeOrigin' members in
# 'pytcp.runtime.socket.error_queue'. The constant is PyTCP-
# internal — Python stdlib 'socket' does not expose
# SO_EE_ORIGIN_*, so applications either define their own
# bare-int constants for stdlib portability or import
# 'pytcp.runtime.socket.error_queue.SoEeOrigin' for the typed
# enum. Use 'SoEeOrigin.ICMP' / 'SoEeOrigin.ICMP6' at
# PyTCP-side call sites.


def _validate_ip4_options_bytes(value: bytes, /) -> bytes:
    """
    Validate a raw IPv4 options block supplied to
    setsockopt(IPPROTO_IP, IP_OPTIONS, value). The block must be
    no longer than IP4__OPTIONS__MAX_LEN, 4-byte aligned (RFC 791
    requires the IPv4 header length be a 32-bit-word count), and
    parseable as a sequence of IPv4 options. The validated bytes
    are returned for the caller to store. Raises 'OSError(EINVAL)'
    on any violation, matching Linux's setsockopt behaviour.
    """

    if len(value) > IP4__OPTIONS__MAX_LEN:
        raise OSError(
            errno.EINVAL,
            f"IP_OPTIONS block must be 0..{IP4__OPTIONS__MAX_LEN} bytes, got {len(value)}",
        )

    if len(value) % 4 != 0:
        raise OSError(
            errno.EINVAL,
            f"IP_OPTIONS block must be 4-byte aligned, got {len(value)} bytes",
        )

    if not value:
        return value

    # Pre-pad a synthetic IPv4 header so the integrity walker reads
    # at IP4__HEADER__LEN like a real packet would.
    synthetic_frame = bytes(IP4__HEADER__LEN) + value
    synthetic_hlen = IP4__HEADER__LEN + len(value)

    try:
        Ip4Options.validate_integrity(frame=synthetic_frame, hlen=synthetic_hlen)
        Ip4Options.from_buffer(value)
    except Ip4IntegrityError as error:
        raise OSError(errno.EINVAL, f"IP_OPTIONS block is malformed: {error}") from error

    return value


def _resolve_membership_ifindex(interface_address: Ip4Address, /) -> int | None:
    """
    Resolve the ifindex for an IP_ADD/DROP_MEMBERSHIP 'imr_interface'
    address. INADDR_ANY (0.0.0.0) selects the first interface that owns
    an IPv4 address (else the first registered interface); a specific
    address selects the interface that owns it. Returns 'None' when no
    interface matches.
    """

    import pytcp.stack as _stack

    if interface_address.is_unspecified:
        for ifindex, handler in _stack.interfaces.items():
            if handler.ip4_unicast:
                return ifindex
        for ifindex, _handler in _stack.interfaces.items():
            return ifindex
        return None

    for ifindex, handler in _stack.interfaces.items():
        if interface_address in handler.ip4_unicast:
            return ifindex

    return None


# 'struct group_source_req' (glibc, native layout): uint32 gsr_interface
# at offset 0; sockaddr_storage gsr_group at offset 8 (sockaddr_in6 ->
# ss_family at +0, sin6_addr at +8, so the group address is bytes[16:32]);
# sockaddr_storage gsr_source at offset 136 (source address bytes[144:160]).
GROUP_SOURCE_REQ__LEN: int = 264
# Linux OS-level AF_INET6 as it appears in a sockaddr wire struct — the
# same value 'error_queue._AF_INET6' packs, distinct from PyTCP's
# internal 'AddressFamily.INET6' socket-family enum value.
_AF_INET6__SOCKADDR: int = 10


def _parse_group_source_req(gsr: bytes, /) -> tuple[int, Ip6Address, Ip6Address]:
    """
    Parse a Linux 'struct group_source_req' (RFC 3678) into
    (ifindex, group, source). Validates the total length and that each
    embedded sockaddr's ss_family is AF_INET6. Raises 'OSError(EINVAL)'
    on a short buffer or a non-AF_INET6 sockaddr family.
    """

    if len(gsr) < GROUP_SOURCE_REQ__LEN:
        raise OSError(
            errno.EINVAL,
            f"group_source_req must be at least {GROUP_SOURCE_REQ__LEN} bytes, got {len(gsr)}",
        )

    ifindex = int.from_bytes(gsr[0:4], sys.byteorder)
    group_family = int.from_bytes(gsr[8:10], sys.byteorder)
    source_family = int.from_bytes(gsr[136:138], sys.byteorder)
    if group_family != _AF_INET6__SOCKADDR or source_family != _AF_INET6__SOCKADDR:
        raise OSError(errno.EINVAL, "group_source_req sockaddr family must be AF_INET6")

    group = Ip6Address(gsr[16:32])
    source = Ip6Address(gsr[144:160])
    return ifindex, group, source


class ShutdownHow(IntEnum):
    """
    BSD-socket 'shutdown(how)' values per POSIX (Linux-
    numbered, matching Python stdlib 'socket.SHUT_*'). RFC
    9293 §3.9.1 half-close support: SHUT_WR triggers FIN
    emission like CLOSE but leaves the read side open;
    SHUT_RD discards inbound data.
    """

    SHUT_RD = 0
    SHUT_WR = 1
    SHUT_RDWR = 2


SHUT_RD = ShutdownHow.SHUT_RD
SHUT_WR = ShutdownHow.SHUT_WR
SHUT_RDWR = ShutdownHow.SHUT_RDWR


class gaierror(OSError):
    """
    BSD Socket error for compatibility.
    """


class AddressFamily(NameEnum):
    """
    Address family identifier.
    """

    INET4 = 1
    INET6 = 2
    PACKET = 17  # Linux AF_PACKET (<bits/socket.h>): raw link-layer access.

    @staticmethod
    def from_ver(ver: IpVersion) -> AddressFamily:
        """
        Get the address family from an IP version.
        """

        match ver:
            case IpVersion.IP4:
                return AddressFamily.INET4
            case IpVersion.IP6:
                return AddressFamily.INET6


class SocketType(NameEnum):
    """
    Socket type identifier.
    """

    STREAM = 1
    DGRAM = 2
    RAW = 3


AF_INET = AddressFamily.INET4
AF_INET4 = AddressFamily.INET4
AF_INET6 = AddressFamily.INET6
AF_PACKET = AddressFamily.PACKET

SOCK_STREAM = SocketType.STREAM
SOCK_DGRAM = SocketType.DGRAM
SOCK_RAW = SocketType.RAW

# AF_PACKET ethertype protocol filter (Linux <linux/if_ether.h>;
# matches the stdlib 'socket.ETH_P_*' surface on Linux). The real
# ethertypes alias the 'EtherType' wire-codepoint members so the
# packet-socket filter shares one namespace with the parser layer;
# 'ETH_P_ALL' is the capture-all pseudo-ethertype sentinel (0x0003 is
# not a real wire ethertype, so it stays a plain int rather than an
# 'EtherType' member — analogous to the 'INADDR_*' sentinels).
ETH_P_ALL: int = 0x0003
ETH_P_IP = EtherType.IP4
ETH_P_ARP = EtherType.ARP
ETH_P_IPV6 = EtherType.IP6


class PacketType(IntEnum):
    """
    AF_PACKET 'struct sockaddr_ll.sll_pkttype' classification values
    (Linux <linux/if_packet.h>; matches the stdlib 'socket.PACKET_*'
    surface on Linux). Set on RX to describe how the frame was
    addressed relative to this host's interface.
    """

    PACKET_HOST = 0  # frame addressed to this host's unicast MAC
    PACKET_BROADCAST = 1  # frame addressed to the link broadcast MAC
    PACKET_MULTICAST = 2  # frame addressed to a multicast MAC this host joined
    PACKET_OTHERHOST = 3  # frame addressed to some other host (promiscuous)
    PACKET_OUTGOING = 4  # frame originated by this host (loopback of egress)


PACKET_HOST = PacketType.PACKET_HOST
PACKET_BROADCAST = PacketType.PACKET_BROADCAST
PACKET_MULTICAST = PacketType.PACKET_MULTICAST
PACKET_OTHERHOST = PacketType.PACKET_OTHERHOST
PACKET_OUTGOING = PacketType.PACKET_OUTGOING

# DNS / hostname resolution lives outside the TCP/IP stack scope:
# 'getaddrinfo' / 'gethostbyname' / 'getnameinfo' / 'getfqdn' are
# re-exported verbatim from CPython's stdlib 'socket' so application
# code calling 'pytcp.runtime.socket.getaddrinfo("example.com", 80)' gets
# real DNS resolution. The resulting numeric IP string then flows
# back into PyTCP's 'bind' / 'connect' / 'sendto'.
getaddrinfo = _stdlib_socket.getaddrinfo
gethostbyname = _stdlib_socket.gethostbyname
gethostbyname_ex = _stdlib_socket.gethostbyname_ex
gethostname = _stdlib_socket.gethostname
getnameinfo = _stdlib_socket.getnameinfo
getfqdn = _stdlib_socket.getfqdn

# BSD '<arpa/inet.h>' INADDR_* constants (re-exported as plain ints
# matching CPython's stdlib 'socket.INADDR_*'). Apps that pass
# 'INADDR_ANY' to 'bind()' instead of the empty string are common
# in code ported from C; expose the constants so the same idiom
# works.
INADDR_ANY: int = 0
INADDR_BROADCAST: int = 0xFFFFFFFF
INADDR_LOOPBACK: int = 0x7F000001
INADDR_NONE: int = 0xFFFFFFFF


class socket(ABC):
    """
    The BSD socket API base class.
    """

    _address_family: AddressFamily
    _socket_type: SocketType
    _ip_proto: IpProto
    _local_ip_address: Ip4Address | Ip6Address
    _remote_ip_address: Ip4Address | Ip6Address
    _local_port: int
    _remote_port: int
    _read_event_fd: int
    _blocking: bool
    _so_reuseaddr: bool
    _so_reuseport: bool
    _so_broadcast: bool
    _so_linger: tuple[int, int] | None
    _so_sndbuf: int | None
    _so_rcvbuf: int | None
    _so_rcvtimeo: float | None
    _so_sndtimeo: float | None
    _ip_ttl: int | None
    _ip_tos: int
    _ip_options: bytes
    _ip_recvopts: bool
    _ip_recvtos: bool
    _ip_recverr: bool
    _ipv6_unicast_hops: int | None
    _ipv6_tclass: int
    _ipv6_recvtclass: bool
    _ipv6_recverr: bool
    _ipv6_v6only: bool
    _dual_stack: bool
    # The IPv6 source filter (RFC 3810 §4.1) this socket holds per joined
    # (ifindex, group). 'IPV6_JOIN_GROUP' records an EXCLUDE{} any-source
    # filter; the 'MCAST_JOIN_SOURCE_GROUP' family builds INCLUDE /
    # EXCLUDE source lists. Presence of a key is the socket's membership;
    # the value is pushed to the interface merge via the IPv6 membership
    # API — per-socket refcounted, so one socket's leave does not tear
    # down a group another socket still holds.
    _ip6_source_filters: dict[tuple[int, Ip6Address], Ip6MulticastFilter]
    _lock__ip6_source_filters: threading.Lock
    # The source filter (RFC 3376 §3.1) this socket holds per joined
    # (ifindex, group). 'IP_ADD_MEMBERSHIP' records an EXCLUDE{}
    # any-source filter; the source options build INCLUDE / EXCLUDE
    # source lists. Presence of a key is the socket's membership; the
    # value is pushed to the interface merge via the membership API.
    _ip4_source_filters: dict[tuple[int, Ip4Address], Ip4MulticastFilter]
    _lock__ip4_source_filters: threading.Lock

    def __init__(
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | EtherType | int | None = None,
        **__: Any,
    ) -> None:
        """
        Allocate the OS-level eventfd backing 'fileno()'. The
        descriptor signals readability for select / poll / epoll /
        selectors when data lands in the socket's RX queue. Counter
        starts at 0 (not readable); EFD_NONBLOCK + EFD_CLOEXEC match
        the default Linux socket FD flags. The 'family' / 'type' /
        'protocol' parameters mirror the '__new__' factory triple so
        calls like 'socket(family=..., type=..., protocol=...)' bind
        cleanly; the base class itself does not act on them — concrete
        Tcp/Udp/Raw subclasses consume them in their own '__init__'.
        Blocking mode defaults to True per POSIX 'socket(2)'.
        """

        del family, type, protocol  # consumed by concrete-class __init__.
        self._read_event_fd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        # Close-during-delivery drain (Phase 5): '_closed' is set under
        # '_lock__io' by 'close()' (via '_mark_closed'); the RX-side
        # delivery methods ('process_*_packet') take the same lock and
        # drop the datagram when '_closed' so a packet is never queued
        # onto a socket the application has already torn down. TCP
        # delivery is instead serialized by 'TcpSession._lock__fsm'.
        self._closed = False
        self._lock__io = threading.Lock()
        self._blocking = True
        self._so_reuseaddr = False
        self._so_reuseport = False
        self._so_broadcast = False
        self._so_linger = None
        self._so_sndbuf = None
        self._so_rcvbuf = None
        self._so_rcvtimeo = None
        self._so_sndtimeo = None
        self._ip_ttl = None
        self._ip_tos = 0
        self._ip_options = bytes()
        self._ip_recvopts = False
        self._ip_recvtos = False
        self._ip_recverr = False
        self._ipv6_unicast_hops = None
        self._ipv6_tclass = 0
        self._ipv6_recvtclass = False
        self._ipv6_recverr = False
        # Linux 'IPV6_V6ONLY' — defaults to True (1) matching
        # Python 'socket.has_ipv6'-shaped behaviour and the
        # 'net.ipv6.bindv6only' kernel default. When False (0)
        # an AF_INET6 socket bound to '::' also accepts inbound
        # IPv4 peers; the dual-stack listener-fork (H3 Phase 3
        # of socket_linux_parity_audit.md) surfaces those peers
        # as IPv4-mapped IPv6 addresses on accept().
        self._ipv6_v6only = True

        # H3 Phase 3c presentation flag. Set on the accepted
        # child of an AF_INET6 V6ONLY=0 listener when the
        # accepted peer is IPv4 (the dual-stack accept scenario).
        # When True, the app-facing accessors ('local_ip_address'
        # / 'remote_ip_address' / 'family' / 'getsockname' /
        # 'getpeername') wrap the wire IPv4 addresses into the
        # IPv4-mapped IPv6 form so applications see Linux
        # dual-stack semantics; the wire attributes
        # ('_local_ip_address' / '_remote_ip_address' /
        # '_address_family' / 'socket_id') stay AF_INET4 so the
        # RX-path active-socket lookup keeps matching the
        # inbound IPv4 packets.
        self._dual_stack = False

        # Per-socket IPv6 multicast source filters keyed by (ifindex,
        # group). Empty on every fresh socket; populated by
        # 'setsockopt(IPV6_JOIN_GROUP)' / the 'MCAST_JOIN_SOURCE_GROUP'
        # family and drained by 'IPV6_LEAVE_GROUP' / close. The IPv6
        # analogue of '_ip4_source_filters'.
        self._ip6_source_filters = {}
        # Guards '_ip6_source_filters'. Same discipline as
        # '_lock__ip4_source_filters': acquired before the interface
        # multicast lock the membership API takes, never after.
        self._lock__ip6_source_filters = threading.Lock()
        # Per-socket IPv4 multicast holds (ifindex, group) for the
        # reference-counted IP_ADD/DROP_MEMBERSHIP path (R3).
        self._ip4_source_filters = {}
        # Guards '_ip4_source_filters'. The app thread mutates it via the
        # source-membership setsockopt RMW and close-time release; the RX
        # threads read it in the data-plane source-admit gate. Under
        # free-threaded CPython those would race (lost update / torn dict)
        # without this lock. Ordering: only ever acquired before the
        # interface multicast lock the membership API takes, never after.
        self._lock__ip4_source_filters = threading.Lock()
        # SO_BINDTODEVICE: when set, pins this socket's egress to one
        # interface by name (the resolved ifindex is the egress the
        # send path uses, bypassing FIB route selection). Empty / unset
        # means "any interface" (the default FIB-resolved egress).
        self._bound_interface_name: str | None = None
        self._egress_ifindex: int | None = None

    def _so_bindtodevice(self, value: int | bytes, /) -> None:
        """
        Apply SO_BINDTODEVICE (SOL_SOCKET): pin the socket's egress to
        the named interface, mirroring Linux's device-name binding. An
        empty name clears the binding. Raises 'OSError(ENODEV)' when no
        registered interface carries the given name.
        """

        import pytcp.stack as _stack

        name = value.decode() if isinstance(value, (bytes, bytearray)) else str(value)
        if not name:
            self._bound_interface_name = None
            self._egress_ifindex = None
            return

        for ifindex, handler in _stack.interfaces.items():
            if handler.interface_name == name:
                self._bound_interface_name = name
                self._egress_ifindex = ifindex
                return

        raise OSError(errno.ENODEV, f"SO_BINDTODEVICE: no such interface {name!r}")

    def _so_linger_set(self, value: int | bytes, /) -> None:
        """
        Apply SO_LINGER (SOL_SOCKET): decode the 'struct linger'
        {int l_onoff; int l_linger} pair from the bytes buffer and
        store it. The close-path behaviour it selects is TCP-only
        (see 'TcpSocket.close'); UDP / RAW store the value as a
        harmless no-op, matching Linux where linger is meaningless
        for a connectionless socket. A wrong-length buffer raises
        'OSError(EINVAL)' per 'setsockopt(2)'
        (optlen != sizeof(struct linger)).
        """

        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise OSError(errno.EINVAL, "SO_LINGER value must be a 'struct linger' bytes buffer")
        buffer = bytes(value)
        if len(buffer) != struct.calcsize("@ii"):
            raise OSError(
                errno.EINVAL,
                f"SO_LINGER value must be {struct.calcsize('@ii')} bytes (struct linger), got {len(buffer)}",
            )
        l_onoff, l_linger = struct.unpack("@ii", buffer)
        self._so_linger = (l_onoff, l_linger)

    def _so_linger_get(self) -> bytes:
        """
        Read SO_LINGER back as the packed 'struct linger' bytes; an
        unset option reads as '(l_onoff=0, l_linger=0)', matching the
        Linux default-disabled state.
        """

        l_onoff, l_linger = self._so_linger or (0, 0)
        return struct.pack("@ii", l_onoff, l_linger)

    def _sol_socket_setsockopt(self, optname: int, value: int, /) -> bool:
        """
        Apply a SOL_SOCKET-level setsockopt option; return True if
        handled or False if the optname is not a base-class option
        (subclasses then dispatch their TCP/UDP-specific options).
        """

        match optname:
            case _ if optname == SO_REUSEADDR:
                self._so_reuseaddr = bool(value)
                return True
            case _ if optname == SO_REUSEPORT:
                self._so_reuseport = bool(value)
                return True
            case _ if optname == SO_BROADCAST:
                self._so_broadcast = bool(value)
                return True
            case _ if optname == SO_SNDBUF:
                self._so_sndbuf = int(value)
                return True
            case _ if optname == SO_RCVBUF:
                self._so_rcvbuf = int(value)
                return True
            case _ if optname == SO_RCVTIMEO:
                self._so_rcvtimeo = float(value) if value else None
                return True
            case _ if optname == SO_SNDTIMEO:
                self._so_sndtimeo = float(value) if value else None
                return True
            case _ if optname == SO_OOBINLINE:
                # RFC 6093 §6 recommends universal inline delivery
                # of TCP urgent data; PyTCP's RFC 6093 adherence
                # record documents that the stack delivers ALL
                # inbound data inline regardless of URG. The
                # SO_OOBINLINE setsockopt accepts '1' as a no-op
                # confirming the universal-inline posture and
                # rejects '0' (which would opt INTO the
                # out-of-band delivery RFC 6093 §6 advises
                # against) — apps that try to disable it see
                # actionable feedback rather than a silent failure.
                if not value:
                    raise OSError(
                        errno.EINVAL,
                        "SO_OOBINLINE cannot be disabled — PyTCP universally inlines "
                        "TCP urgent data per RFC 6093 §6.",
                    )
                return True
        return False

    def _ipproto_ip_setsockopt(self, optname: int, value: int | bytes, /) -> bool:
        """
        Apply an IPPROTO_IP-level setsockopt option; return True if
        handled. Currently supports IP_TTL (1-255 per-socket
        override), IP_TOS (8-bit DSCP+ECN per-packet marking),
        IP_OPTIONS (0-40 raw IPv4 options block per RFC 1122
        §4.1.3.2), and IP_RECVOPTS / IP_RETOPTS (enable IP_OPTIONS
        cmsg on recvmsg).
        """

        match optname:
            case _ if optname == IP_TTL:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_TTL value must be int, got {type(value).__name__}")
                if not 0 < int(value) < 256:
                    raise OSError(errno.EINVAL, f"IP_TTL must be in 1..255, got {value!r}")
                self._ip_ttl = int(value)
                return True
            case _ if optname == IP_TOS:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_TOS value must be int, got {type(value).__name__}")
                self._ip_tos = int(value) & 0xFF
                return True
            case _ if optname == IP_OPTIONS:
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(errno.EINVAL, f"IP_OPTIONS value must be bytes, got {type(value).__name__}")
                self._ip_options = _validate_ip4_options_bytes(bytes(value))
                return True
            case _ if optname in (IP_RECVOPTS, IP_RETOPTS):
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_RECVOPTS value must be int, got {type(value).__name__}")
                self._ip_recvopts = bool(value)
                return True
            case _ if optname == IP_RECVTOS:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_RECVTOS value must be int, got {type(value).__name__}")
                self._ip_recvtos = bool(value)
                return True
            case _ if optname == IP_RECVERR:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_RECVERR value must be int, got {type(value).__name__}")
                self._ip_recverr = bool(value)
                return True
            case _ if optname in (IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP):
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(
                        errno.EINVAL,
                        f"IP_ADD/DROP_MEMBERSHIP value must be an ip_mreq bytes object, got {type(value).__name__}",
                    )
                self._ipproto_ip_membership(optname, bytes(value))
                return True
            case _ if optname in (
                IP_ADD_SOURCE_MEMBERSHIP,
                IP_DROP_SOURCE_MEMBERSHIP,
                IP_BLOCK_SOURCE,
                IP_UNBLOCK_SOURCE,
            ):
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(
                        errno.EINVAL,
                        f"IP source-membership value must be an ip_mreq_source bytes object, "
                        f"got {type(value).__name__}",
                    )
                self._ipproto_ip_source_membership(optname, bytes(value))
                return True
        return False

    def _resolve_membership_interface(self, interface_address: Ip4Address, imr_ifindex: int, /) -> int:
        """
        Resolve the interface a multicast-membership socket option
        targets. A non-zero 'imr_ifindex' (the 'ip_mreqn' form) selects
        the interface directly and takes precedence; otherwise the
        'imr_interface' in_addr selects it (0.0.0.0 / INADDR_ANY picks
        the first IPv4-capable interface, mirroring the Linux "let the
        kernel pick" behaviour). Raises 'OSError(EADDRNOTAVAIL)' when no
        interface matches.
        """

        import pytcp.stack as _stack

        if imr_ifindex != 0:
            if imr_ifindex not in _stack.interfaces:
                raise OSError(errno.EADDRNOTAVAIL, f"No interface with ifindex {imr_ifindex}")
            return imr_ifindex

        ifindex = _resolve_membership_ifindex(interface_address)
        if ifindex is None:
            raise OSError(errno.EADDRNOTAVAIL, f"No IPv4 interface matches imr_interface {interface_address}")
        return ifindex

    def _ipproto_ip_membership(self, optname: int, mreq: bytes, /) -> None:
        """
        Apply IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP — an any-source join
        / a full leave. Parses the 'ip_mreq' structure (4-byte
        imr_multiaddr + 4-byte imr_interface; the 12-byte 'ip_mreqn' form
        with a trailing host-order imr_ifindex is also accepted) and
        records the socket's filter for (ifindex, group) as EXCLUDE{}
        (any-source), pushing it to the interface merge via the stack
        membership API.

        Joining a group this socket already holds raises EADDRINUSE;
        dropping one it does not hold raises EADDRNOTAVAIL (Linux
        'ip_mc_join_group' / 'ip_mc_leave_group' parity). IP_DROP_MEMBERSHIP
        leaves the group regardless of the socket's filter mode.
        """

        import pytcp.stack as _stack
        from pytcp.stack.membership import MembershipLimitError

        if len(mreq) < 8:
            raise OSError(errno.EINVAL, f"ip_mreq must be at least 8 bytes, got {len(mreq)}")

        group = Ip4Address(mreq[0:4])
        if not group.is_multicast:
            raise OSError(errno.EINVAL, f"{group} is not a multicast group address")
        interface_address = Ip4Address(mreq[4:8])
        # 'ip_mreqn' carries a host-order C-int imr_ifindex after the
        # 8-byte 'ip_mreq' prefix; 0 (or absent) falls back to imr_address.
        imr_ifindex = int.from_bytes(mreq[8:12], sys.byteorder) if len(mreq) >= 12 else 0
        ifindex = self._resolve_membership_interface(interface_address, imr_ifindex)

        api = _stack.membership.interface(ifindex)
        key = (ifindex, group)
        try:
            with self._lock__ip4_source_filters:
                if optname == IP_ADD_MEMBERSHIP:
                    if key in self._ip4_source_filters:
                        raise OSError(errno.EADDRINUSE, f"Socket already a member of {group} on interface {ifindex}")
                    source_filter = Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE)
                    api.set_socket_filter(group=group, token=id(self), source_filter=source_filter)
                    self._ip4_source_filters[key] = source_filter
                else:
                    if key not in self._ip4_source_filters:
                        raise OSError(errno.EADDRNOTAVAIL, f"Socket is not a member of {group} on interface {ifindex}")
                    api.clear_socket_filter(group=group, token=id(self))
                    del self._ip4_source_filters[key]
        except MembershipLimitError as error:
            raise OSError(errno.ENOBUFS, str(error)) from error
        except ValueError as error:
            raise OSError(errno.EINVAL, str(error)) from error

    def _ipproto_ip_source_membership(self, optname: int, mreqs: bytes, /) -> None:
        """
        Apply the source-filter socket options (RFC 3678 / RFC 3376 §3.1)
        by parsing the 12-byte 'ip_mreq_source' structure (4-byte
        imr_multiaddr + 4-byte imr_sourceaddr + 4-byte imr_interface) and
        mutating this socket's per-(ifindex, group) filter, then pushing
        the result to the interface merge via the stack membership API:

        - IP_ADD_SOURCE_MEMBERSHIP: INCLUDE-mode; add the source.
        - IP_DROP_SOURCE_MEMBERSHIP: remove the source from the INCLUDE
          list (leave the group when it empties).
        - IP_BLOCK_SOURCE: EXCLUDE-mode; add the blocked source.
        - IP_UNBLOCK_SOURCE: remove a blocked source from the EXCLUDE list.

        A mode conflict (an INCLUDE op on an EXCLUDE membership or vice
        versa, and BLOCK / UNBLOCK with no prior any-source join) raises
        EINVAL, mirroring Linux 'ip_mc_source'.
        """

        import pytcp.stack as _stack
        from pytcp.stack.membership import MembershipLimitError

        if len(mreqs) < 12:
            raise OSError(errno.EINVAL, f"ip_mreq_source must be at least 12 bytes, got {len(mreqs)}")

        group = Ip4Address(mreqs[0:4])
        if not group.is_multicast:
            raise OSError(errno.EINVAL, f"{group} is not a multicast group address")
        source = Ip4Address(mreqs[4:8])
        interface_address = Ip4Address(mreqs[8:12])
        ifindex = self._resolve_membership_interface(interface_address, 0)

        key = (ifindex, group)
        api = _stack.membership.interface(ifindex)
        try:
            with self._lock__ip4_source_filters:
                # Compute the new socket filter (or None to leave the
                # group) inside the lock so the get/compute/store is one
                # atomic RMW and a mode-conflict OSError aborts cleanly.
                new_filter = self._apply_source_op(optname, self._ip4_source_filters.get(key), source)
                if new_filter is None:
                    api.clear_socket_filter(group=group, token=id(self))
                    self._ip4_source_filters.pop(key, None)
                else:
                    api.set_socket_filter(group=group, token=id(self), source_filter=new_filter)
                    self._ip4_source_filters[key] = new_filter
        except MembershipLimitError as error:
            raise OSError(errno.ENOBUFS, str(error)) from error
        except ValueError as error:
            raise OSError(errno.EINVAL, str(error)) from error

    @staticmethod
    def _apply_source_op(
        optname: int,
        current: Ip4MulticastFilter | None,
        source: Ip4Address,
        /,
    ) -> Ip4MulticastFilter | None:
        """
        Compute the new per-socket source filter for a source-filter
        socket option (RFC 3376 §3.1 / RFC 3678), or 'None' when the
        operation leaves the group. Raises 'OSError' with the Linux
        'ip_mc_source' errno for an invalid transition: EINVAL on a
        filter-mode conflict, EADDRNOTAVAIL on dropping / unblocking a
        source the socket does not hold. Adding a source already present
        is idempotent.
        """

        include = Ip4MulticastFilterMode.INCLUDE
        exclude = Ip4MulticastFilterMode.EXCLUDE

        match optname:
            case _ if optname == IP_ADD_SOURCE_MEMBERSHIP:
                if current is None:
                    return Ip4MulticastFilter(include, frozenset({source}))
                if current.mode is exclude:
                    raise OSError(errno.EINVAL, "IP_ADD_SOURCE_MEMBERSHIP on an EXCLUDE-mode group")
                return Ip4MulticastFilter(include, current.sources | {source})
            case _ if optname == IP_DROP_SOURCE_MEMBERSHIP:
                if current is None:
                    raise OSError(errno.EADDRNOTAVAIL, "Socket is not a member of the group")
                if current.mode is exclude:
                    raise OSError(errno.EINVAL, "IP_DROP_SOURCE_MEMBERSHIP on an EXCLUDE-mode group")
                if source not in current.sources:
                    raise OSError(errno.EADDRNOTAVAIL, f"Source {source} is not in the include list")
                remaining = current.sources - {source}
                return Ip4MulticastFilter(include, remaining) if remaining else None
            case _ if optname == IP_BLOCK_SOURCE:
                if current is None or current.mode is include:
                    raise OSError(errno.EINVAL, "IP_BLOCK_SOURCE requires an EXCLUDE-mode (any-source) membership")
                return Ip4MulticastFilter(exclude, current.sources | {source})
            case _ if optname == IP_UNBLOCK_SOURCE:
                if current is None or current.mode is include:
                    raise OSError(errno.EINVAL, "IP_UNBLOCK_SOURCE requires an EXCLUDE-mode (any-source) membership")
                if source not in current.sources:
                    raise OSError(errno.EADDRNOTAVAIL, f"Source {source} is not blocked")
                return Ip4MulticastFilter(exclude, current.sources - {source})

        raise OSError(errno.EINVAL, f"Unsupported source-membership option {optname}")

    def _ipproto_ip_getsockopt(self, optname: int, /) -> int | bytes | None:
        """
        Get an IPPROTO_IP-level option's stored value, or 'None' if
        the option is not handled here.
        """

        match optname:
            case _ if optname == IP_TTL:
                return self._ip_ttl or 0
            case _ if optname == IP_TOS:
                return self._ip_tos
            case _ if optname == IP_OPTIONS:
                return self._ip_options
            case _ if optname in (IP_RECVOPTS, IP_RETOPTS):
                return int(self._ip_recvopts)
            case _ if optname == IP_RECVTOS:
                return int(self._ip_recvtos)
            case _ if optname == IP_RECVERR:
                return int(self._ip_recverr)
            case _ if optname == IP_MTU:
                return self._effective_pmtu()
        return None

    def _ipproto_ipv6_setsockopt(self, optname: int, value: int | bytes, /) -> bool:
        """
        Apply an IPPROTO_IPV6-level setsockopt option; return True if
        handled. Currently supports IPV6_UNICAST_HOPS (1-255 per-socket
        override) and IPV6_TCLASS (8-bit Traffic Class).
        """

        match optname:
            case _ if optname == IPV6_UNICAST_HOPS:
                if not 0 < int(value) < 256:
                    raise OSError(errno.EINVAL, f"IPV6_UNICAST_HOPS must be in 1..255, got {value!r}")
                self._ipv6_unicast_hops = int(value)
                return True
            case _ if optname == IPV6_TCLASS:
                self._ipv6_tclass = int(value) & 0xFF
                return True
            case _ if optname == IPV6_RECVTCLASS:
                self._ipv6_recvtclass = bool(value)
                return True
            case _ if optname == IPV6_RECVERR:
                self._ipv6_recverr = bool(value)
                return True
            case _ if optname == IPV6_V6ONLY:
                self._ipv6_v6only = bool(value)
                return True
            case _ if optname in (IPV6_JOIN_GROUP, IPV6_LEAVE_GROUP):
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(
                        errno.EINVAL,
                        f"IPV6_JOIN/LEAVE_GROUP value must be an ipv6_mreq bytes object, "
                        f"got {type(value).__name__}",
                    )
                self._ipproto_ipv6_membership(optname, bytes(value))
                return True
            case _ if optname in (
                MCAST_JOIN_SOURCE_GROUP,
                MCAST_LEAVE_SOURCE_GROUP,
                MCAST_BLOCK_SOURCE,
                MCAST_UNBLOCK_SOURCE,
            ):
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(
                        errno.EINVAL,
                        f"MCAST source-membership value must be a group_source_req bytes object, "
                        f"got {type(value).__name__}",
                    )
                self._ipproto_ipv6_source_membership(optname, bytes(value))
                return True
        return False

    def _resolve_ipv6_membership_interface(self, mreq_ifindex: int, /) -> int:
        """
        Resolve the interface an IPv6 multicast-membership option
        targets. A non-zero 'ipv6mr_interface' selects the interface
        directly; ifindex=0 (the "let the kernel pick" sentinel)
        resolves to the first interface owning an IPv6 unicast address
        (Linux 'inet6_lookup_first_iface'). Raises
        'OSError(EADDRNOTAVAIL)' when no interface matches.
        """

        import pytcp.stack as _stack

        if mreq_ifindex == 0:
            for candidate_ifindex, handler in _stack.interfaces.items():
                if handler.ip6_unicast:
                    return candidate_ifindex
            raise OSError(errno.EADDRNOTAVAIL, "No IPv6-capable interface available")
        if mreq_ifindex not in _stack.interfaces:
            raise OSError(errno.EADDRNOTAVAIL, f"No interface with ifindex {mreq_ifindex}")
        return mreq_ifindex

    def _ipproto_ipv6_membership(self, optname: int, mreq: bytes, /) -> None:
        """
        Apply IPV6_JOIN_GROUP / IPV6_LEAVE_GROUP (RFC 3493 §5.2) — an
        any-source join / a full leave. Parses the 20-byte 'ipv6_mreq'
        structure (16-byte ipv6mr_multiaddr + 4-byte ipv6mr_interface in
        host byte order) and records the socket's filter for
        (ifindex, group) as EXCLUDE{} (any-source), pushing it to the
        interface merge via the IPv6 membership API. Joining wires the
        outbound MLDv2 Report automatically (the 'assign_ip6_multicast'
        handler emits it on the reception edge).

        Joining a group this socket already holds raises EADDRINUSE;
        dropping one it does not hold raises EADDRNOTAVAIL (Linux
        'ipv6_sock_mc_join' / 'ipv6_sock_mc_drop' parity). Per-socket
        refcounted: a leave by one socket keeps the group joined while
        another socket still holds it.
        """

        import pytcp.stack as _stack

        if len(mreq) < 20:
            raise OSError(errno.EINVAL, f"ipv6_mreq must be at least 20 bytes, got {len(mreq)}")

        group = Ip6Address(mreq[0:16])
        if not group.is_multicast:
            raise OSError(errno.EINVAL, f"{group} is not a multicast group address")
        mreq_ifindex = int.from_bytes(mreq[16:20], sys.byteorder)
        ifindex = self._resolve_ipv6_membership_interface(mreq_ifindex)

        api = _stack.membership6.interface(ifindex)
        key = (ifindex, group)
        try:
            with self._lock__ip6_source_filters:
                if optname == IPV6_JOIN_GROUP:
                    if key in self._ip6_source_filters:
                        raise OSError(errno.EADDRINUSE, f"Socket already a member of {group} on interface {ifindex}")
                    source_filter = Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE)
                    api.set_socket_filter(group=group, token=id(self), source_filter=source_filter)
                    self._ip6_source_filters[key] = source_filter
                else:
                    if key not in self._ip6_source_filters:
                        raise OSError(errno.EADDRNOTAVAIL, f"Socket is not a member of {group} on interface {ifindex}")
                    api.clear_socket_filter(group=group, token=id(self))
                    del self._ip6_source_filters[key]
        except ValueError as error:
            raise OSError(errno.EINVAL, str(error)) from error

    def _ipproto_ipv6_source_membership(self, optname: int, gsr: bytes, /) -> None:
        """
        Apply the IPv6 protocol-independent source-filter socket options
        (RFC 3678 / RFC 3810 §4.1) by parsing the 'group_source_req'
        structure and mutating this socket's per-(ifindex, group) filter,
        then pushing the result to the interface merge via the IPv6
        membership API:

        - MCAST_JOIN_SOURCE_GROUP: INCLUDE-mode; add the source.
        - MCAST_LEAVE_SOURCE_GROUP: remove the source from the INCLUDE
          list (leave the group when it empties).
        - MCAST_BLOCK_SOURCE: EXCLUDE-mode; add the blocked source.
        - MCAST_UNBLOCK_SOURCE: remove a blocked source from the EXCLUDE
          list.

        A mode conflict (an INCLUDE op on an EXCLUDE membership or vice
        versa, and BLOCK / UNBLOCK with no prior any-source join) raises
        EINVAL, mirroring Linux 'ip6_mc_source'. The IPv6 analogue of
        '_ipproto_ip_source_membership'.
        """

        import pytcp.stack as _stack

        mreq_ifindex, group, source = _parse_group_source_req(gsr)
        if not group.is_multicast:
            raise OSError(errno.EINVAL, f"{group} is not a multicast group address")
        ifindex = self._resolve_ipv6_membership_interface(mreq_ifindex)

        key = (ifindex, group)
        api = _stack.membership6.interface(ifindex)
        try:
            with self._lock__ip6_source_filters:
                # Compute the new socket filter (or None to leave the
                # group) inside the lock so the get/compute/store is one
                # atomic RMW and a mode-conflict OSError aborts cleanly.
                new_filter = self._apply_ip6_source_op(optname, self._ip6_source_filters.get(key), source)
                if new_filter is None:
                    api.clear_socket_filter(group=group, token=id(self))
                    self._ip6_source_filters.pop(key, None)
                else:
                    api.set_socket_filter(group=group, token=id(self), source_filter=new_filter)
                    self._ip6_source_filters[key] = new_filter
        except ValueError as error:
            raise OSError(errno.EINVAL, str(error)) from error

    @staticmethod
    def _apply_ip6_source_op(
        optname: int,
        current: Ip6MulticastFilter | None,
        source: Ip6Address,
        /,
    ) -> Ip6MulticastFilter | None:
        """
        Compute the new per-socket IPv6 source filter for a source-filter
        socket option (RFC 3810 §4.1 / RFC 3678), or 'None' when the
        operation leaves the group. Raises 'OSError' with the Linux
        'ip6_mc_source' errno for an invalid transition: EINVAL on a
        filter-mode conflict, EADDRNOTAVAIL on dropping / unblocking a
        source the socket does not hold. Adding a source already present
        is idempotent. The IPv6 analogue of '_apply_source_op'.
        """

        include = Ip6MulticastFilterMode.INCLUDE
        exclude = Ip6MulticastFilterMode.EXCLUDE

        match optname:
            case _ if optname == MCAST_JOIN_SOURCE_GROUP:
                if current is None:
                    return Ip6MulticastFilter(include, frozenset({source}))
                if current.mode is exclude:
                    raise OSError(errno.EINVAL, "MCAST_JOIN_SOURCE_GROUP on an EXCLUDE-mode group")
                return Ip6MulticastFilter(include, current.sources | {source})
            case _ if optname == MCAST_LEAVE_SOURCE_GROUP:
                if current is None:
                    raise OSError(errno.EADDRNOTAVAIL, "Socket is not a member of the group")
                if current.mode is exclude:
                    raise OSError(errno.EINVAL, "MCAST_LEAVE_SOURCE_GROUP on an EXCLUDE-mode group")
                if source not in current.sources:
                    raise OSError(errno.EADDRNOTAVAIL, f"Source {source} is not in the include list")
                remaining = current.sources - {source}
                return Ip6MulticastFilter(include, remaining) if remaining else None
            case _ if optname == MCAST_BLOCK_SOURCE:
                if current is None or current.mode is include:
                    raise OSError(errno.EINVAL, "MCAST_BLOCK_SOURCE requires an EXCLUDE-mode (any-source) membership")
                return Ip6MulticastFilter(exclude, current.sources | {source})
            case _ if optname == MCAST_UNBLOCK_SOURCE:
                if current is None or current.mode is include:
                    raise OSError(errno.EINVAL, "MCAST_UNBLOCK_SOURCE requires an EXCLUDE-mode (any-source) membership")
                if source not in current.sources:
                    raise OSError(errno.EADDRNOTAVAIL, f"Source {source} is not blocked")
                return Ip6MulticastFilter(exclude, current.sources - {source})

        raise OSError(errno.EINVAL, f"Unsupported source-membership option {optname}")

    def _ipproto_ipv6_getsockopt(self, optname: int, /) -> int | None:
        """
        Get an IPPROTO_IPV6-level option's stored value, or 'None' if
        the option is not handled here.
        """

        match optname:
            case _ if optname == IPV6_UNICAST_HOPS:
                return self._ipv6_unicast_hops or 0
            case _ if optname == IPV6_TCLASS:
                return self._ipv6_tclass
            case _ if optname == IPV6_RECVTCLASS:
                return int(self._ipv6_recvtclass)
            case _ if optname == IPV6_RECVERR:
                return int(self._ipv6_recverr)
            case _ if optname == IPV6_V6ONLY:
                return int(self._ipv6_v6only)
            case _ if optname == IPV6_MTU:
                return self._effective_pmtu()
        return None

    def _effective_ip_ttl(self, remote_ip_address: Ip4Address | Ip6Address, /) -> int | None:
        """
        Get the effective per-socket TTL (IPv4) or Hop-Limit (IPv6)
        override for a datagram to 'remote_ip_address', or 'None'
        when no override applies — in which case the packet
        handler's per-destination default (Hop-Limit / TTL = 1 for
        multicast, 64 for unicast) governs.

        IP_TTL / IPV6_UNICAST_HOPS bind unicast sends only; a
        multicast destination is never affected by them, matching
        Linux which keeps the unicast and multicast hop knobs
        separate (inet->uc_ttl vs inet->mc_ttl; np->hop_limit vs
        np->mcast_hops). A multicast destination therefore falls to
        the handler's multicast default here.
        """

        if remote_ip_address.is_multicast:
            return None
        if self._address_family is AddressFamily.INET6:
            return self._ipv6_unicast_hops
        return self._ip_ttl

    def _effective_ip_ecn(self) -> int:
        """
        Get the effective ECN bits (low 2 bits of IP_TOS / IPV6_TCLASS)
        based on the socket's address family. Apps that set the full
        TOS/Traffic-Class byte get the ECN portion automatically.
        """

        if self._address_family is AddressFamily.INET6:
            return self._ipv6_tclass & 0x03
        return self._ip_tos & 0x03

    def _effective_ip_dscp(self) -> int:
        """
        Get the effective DSCP value (high 6 bits of IP_TOS /
        IPV6_TCLASS) based on the socket's address family (RFC 2474
        §3). Apps that set the full TOS / Traffic-Class byte get the
        DSCP portion marked on every outbound packet automatically.
        """

        if self._address_family is AddressFamily.INET6:
            return (self._ipv6_tclass >> 2) & 0x3F
        return (self._ip_tos >> 2) & 0x3F

    def _effective_pmtu(self) -> int:
        """
        Get the effective Path-MTU for this socket's connected
        peer: the value reported by 'stack.current_pmtu()'
        (which prefers the active PLPMTUD engine state in
        'stack.pmtu_state' and falls back to the legacy
        classical-PMTUD scalar in 'stack.pmtu_cache') when
        present, otherwise the link MTU of the interface the FIB
        selects to egress toward the peer
        ('stack.egress_interface_mtu()') as a link-layer fallback
        (matching Linux's IP_MTU semantics).

        Raises 'OSError(ENOTCONN)' when the socket has no
        connected remote, mirroring Linux 'ip(7)' / 'ipv6(7)' —
        the MTU surface is defined per-destination, so an
        unconnected socket has no meaningful value to return.
        """

        # Import here to avoid a top-level circular cycle between
        # pytcp.runtime.socket and pytcp.stack at module load.
        from pytcp import stack as _stack

        if self._remote_ip_address.is_unspecified:
            raise OSError(errno.ENOTCONN, "Socket is not connected — IP_MTU/IPV6_MTU has no peer")
        current = _stack.current_pmtu(self._remote_ip_address)
        if current is not None:
            return current
        # No PMTU signal yet — report the egress interface's link MTU
        # (per-destination on a multi-homed host). Falls back to the
        # default link MTU when no egress can be resolved, preserving the
        # retired 'stack.interface_mtu' default value.
        return _stack.egress_interface_mtu(self._remote_ip_address) or _stack.INTERFACE__TAP__MTU

    def _effective_ip4_options(self) -> Ip4Options | None:
        """
        Get the per-socket IPv4 options object set via
        'setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)' for IPv4
        sockets, or 'None' for IPv6 sockets (IPv6 has no
        equivalent — extension headers are handled via a
        separate ancillary-data track, RFC 3542).
        """

        if self._address_family is not AddressFamily.INET4:
            return None
        if not self._ip_options:
            return None
        return Ip4Options.from_buffer(self._ip_options)

    def _sol_socket_getsockopt(self, optname: int, /) -> int | bytes | None:
        """
        Get a SOL_SOCKET-level option's stored value, or 'None' if
        the option is not a base-class option. Most options return an
        'int'; SO_LINGER returns the packed 'struct linger' bytes.
        """

        match optname:
            case _ if optname == SO_REUSEADDR:
                return int(self._so_reuseaddr)
            case _ if optname == SO_REUSEPORT:
                return int(self._so_reuseport)
            case _ if optname == SO_LINGER:
                return self._so_linger_get()
            case _ if optname == SO_BROADCAST:
                return int(self._so_broadcast)
            case _ if optname == SO_SNDBUF:
                return self._so_sndbuf or 0
            case _ if optname == SO_RCVBUF:
                return self._so_rcvbuf or 0
            case _ if optname == SO_RCVTIMEO:
                return int(self._so_rcvtimeo) if self._so_rcvtimeo else 0
            case _ if optname == SO_SNDTIMEO:
                return int(self._so_sndtimeo) if self._so_sndtimeo else 0
            case _ if optname == SO_OOBINLINE:
                # Always 1 — PyTCP's RFC 6093 §6 universal-inline
                # design (see the setsockopt comment above).
                return 1
        return None

    def __new__(
        cls,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | EtherType | int | None = None,
        **__: Any,
    ) -> socket:
        """
        Create appropriate socket class object.
        """

        if cls is socket:
            from pytcp.runtime.socket.packet__socket import PacketSocket
            from pytcp.runtime.socket.ping__socket import PingSocket
            from pytcp.runtime.socket.raw__socket import RawSocket
            from pytcp.runtime.socket.tcp__socket import TcpSocket
            from pytcp.runtime.socket.udp__socket import UdpSocket

            # Coerce the BSD 'IPPROTO_IP' (= 0) default-protocol
            # sentinel to None so STREAM/DGRAM dispatch picks the
            # canonical default and RAW falls into the explicit
            # EPROTONOSUPPORT branch.
            if protocol.__class__ is int and protocol == 0:
                protocol = None

            match family, type, protocol:
                case (AddressFamily.PACKET, SocketType.RAW, _):
                    return cls.__new__(PacketSocket)
                case (AddressFamily.PACKET, _, _):
                    raise ValueError(f"Invalid socket {family=}, {type=}, {protocol=} combination.")
                case _, SocketType.STREAM, IpProto.TCP | None:
                    return cls.__new__(TcpSocket)
                case _, SocketType.DGRAM, IpProto.UDP | None:
                    return cls.__new__(UdpSocket)
                case (
                    AddressFamily.INET6 | AddressFamily.INET4,
                    SocketType.DGRAM,
                    IpProto.ICMP4 | IpProto.ICMP6,
                ):
                    return cls.__new__(PingSocket)
                case _, SocketType.RAW, None:
                    raise OSError(errno.EPROTONOSUPPORT, os.strerror(errno.EPROTONOSUPPORT))
                case (AddressFamily.INET6 | AddressFamily.INET4, SocketType.RAW, IpProto()):
                    return cls.__new__(RawSocket)
                case _:
                    raise ValueError(f"Invalid socket {family=}, {type=}, {protocol=} combination.")

        return super().__new__(cls)

    def __enter__(self) -> socket:
        """
        Enter the socket runtime context.
        """

        return self

    def __exit__(
        self,
        exc_type: type[BaseException],
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Exit the socket runtime context.
        """

    @override
    def __str__(self) -> str:
        """
        Get socket log string.
        """

        proto = f"{self._address_family}/{self._socket_type}/{self._ip_proto}"
        local = f"{self._local_ip_address}/{self._local_port}"
        remote = f"{self._remote_ip_address}/{self._remote_port}"
        return f"{proto}/{local}/{remote}"

    @override
    def __repr__(self) -> str:
        """
        Get socket string representation.
        """

        return str(self)

    @property
    def socket_id(self) -> SocketId:
        """
        Get the socket ID.
        """

        return SocketId(
            address_family=self._address_family,
            socket_type=self._socket_type,
            local_address=self._local_ip_address,
            local_port=self._local_port,
            remote_address=self._remote_ip_address,
            remote_port=self._remote_port,
        )

    @property
    def address_family(self) -> AddressFamily:
        """
        Get the '_address_family' attribute.
        """

        return self._address_family

    @property
    def ipv6_v6only(self) -> bool:
        """
        Get the Linux 'IPV6_V6ONLY' flag. The TCP RX packet handler and
        the bind-conflict helper read this through the public surface to
        decide whether an AF_INET6 socket also accepts inbound IPv4
        peers (dual-stack).
        """

        return self._ipv6_v6only

    @property
    def socket_type(self) -> SocketType:
        """
        Get the '_socket_type' attribute.
        """

        return self._socket_type

    @property
    def ip_proto(self) -> IpProto:
        """
        Get the '_ip_proto' attribute.
        """

        return self._ip_proto

    @property
    def local_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the application-facing local IP address. On a dual-stack
        accepted child socket ('_dual_stack=True') the wire IPv4
        address is wrapped into its IPv4-mapped IPv6 form so apps
        see Linux dual-stack semantics; otherwise the wire address
        is returned verbatim.
        """

        if self._dual_stack and isinstance(self._local_ip_address, Ip4Address):
            return Ip6Address.from_ipv4_mapped(self._local_ip_address)
        return self._local_ip_address

    @property
    def remote_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the application-facing remote IP address. Wraps to the
        IPv4-mapped IPv6 form on a dual-stack accepted child, same
        as 'local_ip_address'.
        """

        if self._dual_stack and isinstance(self._remote_ip_address, Ip4Address):
            return Ip6Address.from_ipv4_mapped(self._remote_ip_address)
        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Get the '_local_port' attribute.
        """

        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Get the '_remote_port' attribute.
        """

        return self._remote_port

    @property
    def egress_ifindex(self) -> int | None:
        """
        Get the SO_BINDTODEVICE-pinned egress interface index, or
        'None' when the socket is not pinned to an interface. Read
        surface for the RX-path ingress demux ('SocketTable') and the
        send path; the '_egress_ifindex' attribute stays the storage.
        """

        return self._egress_ifindex

    ###############################
    ##  BSD socket API methods.  ##
    ###############################

    @property
    def family(self) -> AddressFamily:
        """
        Get the application-facing address family. On a dual-stack
        accepted child socket ('_dual_stack=True') the wire family
        is AF_INET4 but the application sees AF_INET6 — matches
        Linux's accept() returning an AF_INET6 child from a V6ONLY=0
        listener. The wire '_address_family' attribute stays
        AF_INET4 so socket_id-keyed RX-path lookups still find the
        socket for inbound IPv4 packets.
        """

        if self._dual_stack:
            return AddressFamily.INET6
        return self._address_family

    @property
    def type(self) -> SocketType:
        """
        Get the '_socket_type' attribute.
        """

        return self._socket_type

    @property
    def proto(self) -> IpProto:
        """
        Get the '_ip_proto' attribute.
        """

        return self._ip_proto

    def fileno(self) -> int:
        """
        Get the OS file descriptor backing this socket. Returns the
        underlying eventfd that signals readability when the RX
        queue is non-empty, suitable for 'select.select' /
        'select.poll' / 'select.epoll' / 'selectors.DefaultSelector'.
        """

        return self._read_event_fd

    def setblocking(self, flag: bool, /) -> None:
        """
        Set the socket's blocking mode per POSIX 'socket(2)' /
        CPython 'socket.setblocking'. With 'flag=True' (default),
        recv / accept calls block until data / a child is available;
        with 'flag=False', the same calls raise 'BlockingIOError'
        carrying 'errno.EAGAIN' when they would otherwise block.
        Non-bool truthy / falsy values are coerced to bool to match
        CPython's stdlib behavior.
        """

        self._blocking = bool(flag)

    def getblocking(self) -> bool:
        """
        Get the socket's current blocking mode per CPython
        'socket.getblocking'. Returns 'True' for blocking sockets
        (the default) and 'False' for non-blocking sockets.
        """

        return self._blocking

    def _signal_readable(self) -> None:
        """
        Mark the socket's eventfd as select-readable. The producer
        (stack-thread RX path) calls this whenever a new datagram /
        segment / accept-queue child lands. Best-effort: a closed fd
        is silently tolerated so the producer never crashes on a
        race with application-side close().
        """

        if (fd := self._read_event_fd) < 0:
            return
        try:
            os.eventfd_write(fd, 1)
        except OSError:
            pass

    def _drain_readable(self) -> None:
        """
        Return the socket's eventfd to the not-readable state. The
        consumer (application-thread recv / accept) calls this once
        the RX queue / accept queue has been drained empty so the
        next selector tick stops firing. Best-effort: a closed fd
        or already-zero counter (EAGAIN) is silently tolerated.
        """

        if (fd := self._read_event_fd) < 0:
            return
        try:
            os.eventfd_read(fd)
        except OSError:
            pass

    def _close_io_runtime(self) -> None:
        """
        Close the OS-level eventfd backing 'fileno()'. Idempotent
        so concrete 'close()' overrides can call it unconditionally
        without tracking whether the fd is still open.
        """

        if (fd := self._read_event_fd) < 0:
            return
        self._read_event_fd = -1
        try:
            os.close(fd)
        except OSError:
            pass

    def _mark_closed(self) -> None:
        """
        Atomically mark the socket closed and release its OS-level
        runtime, under '_lock__io'. Concrete 'close()' overrides call
        this (after removing the socket from 'stack.sockets') so an
        in-flight RX delivery either completes before the socket is
        marked closed or observes '_closed' and drops the datagram —
        'close()' thus drains in-flight deliveries.
        """

        with self._lock__io:
            self._closed = True
            self._close_io_runtime()

        self._release_ip4_memberships()
        self._release_ip6_memberships()

    def __del__(self) -> None:
        """
        Finalizer safety net: a socket dropped without an explicit
        close() still releases its OS-level runtime (the backing eventfd)
        and its IPv4 / IPv6 multicast memberships when garbage-collected,
        so a leaked joined socket cannot keep its group joined on the
        interface forever. This mirrors Linux 'ip_mc_drop_socket', which
        runs silently from the fd release — no ResourceWarning is emitted
        (the stdlib socket's warning would be noise across the stack's
        many internal socket consumers, and the cleanup, not the
        diagnostic, is the point).

        It runs the resource-only '_mark_closed', NOT the per-flavour
        close(), so it never attempts protocol-graceful teardown from a
        finalizer (a TCP socket still needs an explicit close() for its
        FIN handshake). Guarded so a partially-constructed socket or
        interpreter-shutdown teardown cannot raise out of '__del__'.
        """

        if getattr(self, "_closed", True):
            return

        try:
            self._mark_closed()
        except Exception:  # pylint: disable=broad-exception-caught
            # A finalizer must never raise; resource teardown during GC
            # or interpreter shutdown is best-effort.
            pass

    def _release_ip4_memberships(self) -> None:
        """
        Release every IPv4 multicast source filter this socket still
        holds — the Linux 'ip_mc_drop_socket' equivalent run on close().
        The interface leaves a group (and emits the state-change Leave)
        only when this socket was its last contributor (RFC 3376 §3.2).
        Idempotent: a socket that joined no group clears an empty map.
        Released outside '_lock__io' so the membership/timer path does
        not run under the socket IO lock.
        """

        import pytcp.stack as _stack

        with self._lock__ip4_source_filters:
            if not self._ip4_source_filters:
                return

            for ifindex, group in list(self._ip4_source_filters):
                try:
                    _stack.membership.interface(ifindex).clear_socket_filter(group=group, token=id(self))
                except KeyError:
                    # Best-effort cleanup: the interface may already be
                    # torn down (KeyError) during stack shutdown. Mirrors
                    # the best-effort nature of the Linux close-time drop.
                    pass
            self._ip4_source_filters.clear()

    def _release_ip6_memberships(self) -> None:
        """
        Release every IPv6 multicast source filter this socket still
        holds — the Linux 'ipv6_sock_mc_close' equivalent run on close().
        The interface leaves a group (and emits the MLD Leave) only when
        this socket was its last contributor (RFC 3810 §4.2). Idempotent:
        a socket that joined no group clears an empty map. Released
        outside '_lock__io' so the membership/timer path does not run
        under the socket IO lock. The IPv6 analogue of
        '_release_ip4_memberships'.
        """

        import pytcp.stack as _stack

        with self._lock__ip6_source_filters:
            if not self._ip6_source_filters:
                return

            for ifindex, group in list(self._ip6_source_filters):
                try:
                    _stack.membership6.interface(ifindex).clear_socket_filter(group=group, token=id(self))
                except KeyError:
                    # Best-effort cleanup: the interface may already be
                    # torn down (KeyError) during stack shutdown. Mirrors
                    # the best-effort nature of the Linux close-time drop.
                    pass
            self._ip6_source_filters.clear()

    def ip4_multicast_source_admits(self, *, ifindex: int, group: Ip4Address, source: Ip4Address) -> bool:
        """
        RFC 3376 §3.1 data-plane source-delivery gate (Linux
        'ip_mc_sf_allow'): admit an inbound IPv4 multicast datagram only
        if this socket's source filter for '(ifindex, group)' admits
        'source'. A socket with no filter for the pair keeps any-source
        delivery. Shared by the UDP and RAW delivery paths.
        """

        with self._lock__ip4_source_filters:
            source_filter = self._ip4_source_filters.get((ifindex, group))
        # 'Ip4MulticastFilter' is immutable, so 'allows' is evaluated
        # outside the lock against the snapshotted reference.
        return source_filter is None or source_filter.allows(source)

    def ip6_multicast_source_admits(self, *, ifindex: int, group: Ip6Address, source: Ip6Address) -> bool:
        """
        RFC 3810 §4.1 data-plane source-delivery gate (Linux
        'ip_mc_sf_allow' in 'ip6_mc_input'): admit an inbound IPv6
        multicast datagram only if this socket's source filter for
        '(ifindex, group)' admits 'source'. A socket with no filter for
        the pair keeps any-source delivery. Shared by the UDP and RAW
        delivery paths. The IPv6 analogue of 'ip4_multicast_source_admits'.
        """

        with self._lock__ip6_source_filters:
            source_filter = self._ip6_source_filters.get((ifindex, group))
        # 'Ip6MulticastFilter' is immutable, so 'allows' is evaluated
        # outside the lock against the snapshotted reference.
        return source_filter is None or source_filter.allows(source)

    def getsockname(self) -> tuple[str, int]:
        """
        Get the local address and port. Reads through the
        'local_ip_address' property so a dual-stack accepted child
        returns the IPv4-mapped IPv6 string form (Linux parity).
        """

        return str(self.local_ip_address), self._local_port

    def getpeername(self) -> tuple[str, int]:
        """
        Get the remote address and port. Reads through the
        'remote_ip_address' property — dual-stack accepted children
        return the IPv4-mapped IPv6 string form.

        Raises 'OSError(ENOTCONN)' when the socket is not connected (no
        peer — a bound-only / listening socket has a zero remote port),
        matching the BSD / stdlib 'getpeername(2)' contract. asyncio's
        transport relies on this: it calls 'getpeername()' to decide
        whether a datagram socket is connected (use 'send') or not (use
        'sendto') — returning a zero peer instead of raising made
        'create_datagram_endpoint' send with no destination.
        """

        if self._remote_port == 0:
            raise OSError(errno.ENOTCONN, os.strerror(errno.ENOTCONN))

        return str(self.remote_ip_address), self._remote_port

    def bind(
        self,
        address: Any,
    ) -> None:
        """
        The 'bind()' socket API method placeholder.

        The address is typed 'Any' because it is address-family
        dependent: IP sockets take '(ip_str, port)', while an
        AF_PACKET socket takes a 'SockAddrLl'. Each concrete subclass
        narrows the parameter to its own precise address type.
        """

        raise NotImplementedError

    def connect(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'connect()' socket API method placeholder.
        """

        raise NotImplementedError

    def send(
        self,
        data: bytes,
    ) -> int:
        """
        The 'send()' socket API method placeholder.
        """

        raise NotImplementedError

    def recv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """
        The 'recv()' socket API method placeholder.
        """

        raise NotImplementedError

    def recv__mv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> memoryview:
        """
        The 'recv__mv()' socket API method placeholder.
        """

        raise NotImplementedError

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        The 'setsockopt()' socket API method placeholder. Each concrete
        IP socket implements the SOL_SOCKET / IPPROTO_* option surface;
        AF_PACKET sockets do not support socket options.
        """

        raise NotImplementedError

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        The 'getsockopt()' socket API method placeholder. Symmetric to
        'setsockopt'.
        """

        raise NotImplementedError

    def close(self) -> None:
        """
        The 'close()' socket API placeholder.
        """

        raise NotImplementedError

    def listen(self, *, backlog: int = 16) -> None:
        """
        The 'listen()' socket API placeholder.
        """

        raise NotImplementedError

    def accept(self, *, timeout: float | None = None) -> tuple[socket, tuple[str, int]]:
        """
        The 'accept()' socket API placeholder.
        """

        raise NotImplementedError

    def sendto(self, data: bytes, address: Any) -> int:
        """
        The 'sendto()' socket API placeholder.

        The address is typed 'Any' because it is address-family
        dependent: IP sockets take '(ip_str, port)', while an
        AF_PACKET socket takes a 'SockAddrLl'. Each concrete subclass
        narrows the parameter to its own precise address type.
        """

        raise NotImplementedError

    def recvfrom(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes, Any]:
        """
        The 'recvfrom()' socket API placeholder.

        The address half is typed 'Any' because it is address-family
        dependent: IP sockets return '(ip_str, port)', while an
        AF_PACKET socket returns a 'SockAddrLl'. Each concrete subclass
        narrows the return to its own precise address type (mirroring
        typeshed's 'socket.recvfrom() -> tuple[bytes, Any]').
        """

        raise NotImplementedError

    def recvfrom__mv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> tuple[memoryview, tuple[str, int]]:
        """
        The 'recvfrom__mv()' socket API placeholder.
        """

        raise NotImplementedError

    def recvmsg(
        self,
        bufsize: int | None = None,
        ancbufsize: int = 0,
        flags: int = 0,
        timeout: float | None = None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        The 'recvmsg()' socket API placeholder. Mirrors stdlib
        'socket.recvmsg(bufsize, ancbufsize=0, flags=0)'; each concrete
        IP socket returns '(data, ancdata, msg_flags, address)'.
        """

        raise NotImplementedError

    def sendmsg(
        self,
        buffers: Iterable[Buffer],
        ancdata: Iterable[tuple[int, int, Buffer]] = (),
        flags: int = 0,
        address: Any = None,
    ) -> int:
        """
        The 'sendmsg()' socket API placeholder. Mirrors stdlib
        'socket.sendmsg(buffers, ancdata=[], flags=0, address=None)'.

        The address is typed 'Any' because it is address-family
        dependent (see 'sendto'); each concrete subclass narrows it.
        """

        raise NotImplementedError

    @staticmethod
    def _validate_sendmsg_ancdata(
        ancdata: Iterable[tuple[int, int, Buffer]],
        /,
    ) -> None:
        """
        Validate the structural shape of sendmsg() ancillary data.

        Phase-1 PyTCP honours no send-side cmsg type — per Linux,
        unrecognised control messages are silently ignored. This guard
        only enforces the stdlib structural contract: every entry must
        be a '(cmsg_level, cmsg_type, cmsg_data)' 3-tuple.
        """

        for item in ancdata:
            if len(item) != 3:
                raise TypeError(
                    "sendmsg(): ancillary data items must be " "(cmsg_level, cmsg_type, cmsg_data) 3-tuples",
                )
