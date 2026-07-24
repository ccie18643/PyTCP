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
Per-socket ICMP error queue plumbing for the
IP_RECVERR / IPV6_RECVERR Linux socket-API surface
(recvmsg(MSG_ERRQUEUE)).

This module owns:
  - 'ErrorQueueEntry' — the dataclass representing one queued
    ICMP error.
  - 'icmp4_to_errno' / 'icmp6_to_errno' — POSIX errno mapping
    for ICMP (type, code) pairs, mirroring Linux's
    'net/ipv4/icmp.c::icmp_err_convert' /
    'net/ipv6/icmpv6.c'.
  - 'pack_sock_extended_err' — packs the cmsg payload (the
    16-byte 'struct sock_extended_err' followed by the
    offender's sockaddr_in / sockaddr_in6, matching Linux
    'ip(7)' / 'ipv6(7)' wire shape so applications can
    'struct.unpack' the bytes exactly as they would on Linux).

pytcp/runtime/socket/error_queue.py

ver 3.0.9
"""

import errno as _errno
import struct
from dataclasses import dataclass
from enum import IntEnum

from net_addr import Ip4Address, Ip6Address


class SoEeOrigin(IntEnum):
    """
    'struct sock_extended_err.ee_origin' values (Linux
    '<linux/errqueue.h>'). Identifies which layer generated
    the error queued on the socket — ICMP / ICMPv6 / kernel-
    local / etc. PyTCP currently surfaces ICMP-origin errors
    only; LOCAL / TXSTATUS / TIMESTAMPING are reserved for
    future surface.
    """

    NONE = 0
    LOCAL = 1
    ICMP = 2
    ICMP6 = 3
    TXSTATUS = 4
    ZEROCOPY = 5
    TXTIME = 6


# Queue depth cap. Drop oldest on overflow (FIFO). Linux uses
# a byte-cap via 'sysctl_optmem_max'; PyTCP uses a count cap
# for simplicity. 32 entries cover any realistic flood; an
# attacker triggering more than that loses the oldest, which
# is the conservative choice for application code that polls
# the queue periodically.
ERROR_QUEUE__MAX_LEN: int = 32

# 'struct sock_extended_err' wire layout (Linux
# <linux/errqueue.h>). 16 bytes total, native endianness; the
# trailing 'offender sockaddr' is appended by callers.
# Layout:
#   uint32 ee_errno
#   uint8  ee_origin
#   uint8  ee_type
#   uint8  ee_code
#   uint8  ee_pad
#   uint32 ee_info
#   uint32 ee_data
_SOCK_EXTENDED_ERR__STRUCT: str = "=IBBBBII"

# Linux's 'sockaddr_in' wire layout (16 bytes; Linux's actual
# struct is 16 bytes with 8 trailing pad bytes — we keep the
# pad to match the on-wire length). Layout:
#   uint16 sin_family
#   uint16 sin_port (network byte order)
#   uint32 sin_addr (network byte order)
#   uint64 sin_zero (padding)
_SOCKADDR_IN__STRUCT: str = "=HH4s8x"

# Linux's 'sockaddr_in6' wire layout (28 bytes). Layout:
#   uint16 sin6_family
#   uint16 sin6_port (network byte order)
#   uint32 sin6_flowinfo
#   uint8[16] sin6_addr
#   uint32 sin6_scope_id
_SOCKADDR_IN6__STRUCT: str = "=HHI16sI"

# Linux address-family constants (matches stdlib socket.AF_*).
_AF_INET: int = 2
_AF_INET6: int = 10


@dataclass(frozen=True, kw_only=True, slots=True)
class ErrorQueueEntry:
    """
    One inbound ICMP error matched to a socket, awaiting
    'recvmsg(flags=MSG_ERRQUEUE)' dequeue. Fields mirror Linux
    'struct sock_extended_err' plus the embedded datagram and
    offender's IP address.
    """

    # POSIX errno equivalent (ECONNREFUSED, EMSGSIZE,
    # EHOSTUNREACH, ENETUNREACH, EPROTO, ETIMEDOUT).
    errno: int
    # ICMP / ICMPv6 / LOCAL / etc.
    origin: SoEeOrigin
    # ICMP type field (ICMPv4 or ICMPv6).
    icmp_type: int
    # ICMP code field.
    icmp_code: int
    # Auxiliary 32-bit field. Carries the next-hop MTU on
    # PMTU errors (RFC 1191 §3 / RFC 8201 §4); 0 otherwise.
    ee_info: int = 0
    # ICMP source — the router or end-host that emitted the
    # error message. Same value Linux returns as the recvmsg
    # 'address' tuple for MSG_ERRQUEUE.
    offender_ip: Ip4Address | Ip6Address
    # The triggering outbound datagram, as quoted in the ICMP
    # error 'data' field. Applications read this to identify
    # which sendto/send call triggered the error.
    embedded_datagram: bytes = b""


def icmp4_to_errno(*, icmp_type: int, icmp_code: int) -> int:
    """
    Map an ICMPv4 (type, code) pair to the POSIX errno that
    Linux would deliver via IP_RECVERR. Mirrors
    'net/ipv4/icmp.c::icmp_err_convert' in the Linux kernel.

    Reference: RFC 792 (ICMPv4 message types).
    """

    match (icmp_type, icmp_code):
        # Destination Unreachable (type 3).
        case (3, 0):
            return _errno.ENETUNREACH  # Net unreachable
        case (3, 1):
            return _errno.EHOSTUNREACH  # Host unreachable
        case (3, 2):
            return _errno.ENOPROTOOPT  # Protocol unreachable
        case (3, 3):
            return _errno.ECONNREFUSED  # Port unreachable
        case (3, 4):
            return _errno.EMSGSIZE  # Frag Needed and DF set
        case (3, 5):
            return _errno.EOPNOTSUPP  # Source Route Failed
        case (3, 6 | 7):
            return _errno.ENETUNREACH  # Dest Net/Host Unknown
        case (3, 8):
            return _errno.EHOSTDOWN  # Source Host Isolated
        case (3, 9 | 11):
            return _errno.ENETUNREACH  # Net admin / TOS prohibited
        case (3, 10 | 12):
            return _errno.EHOSTUNREACH  # Host admin / TOS prohibited
        case (3, 13):
            return _errno.EHOSTUNREACH  # Communication admin prohibited
        # Time Exceeded (type 11).
        case (11, _):
            return _errno.EHOSTUNREACH
        # Parameter Problem (type 12).
        case (12, _):
            return _errno.EPROTO
        # Default — Linux falls back to EHOSTUNREACH for unknown ICMPv4 errors.
        case _:
            return _errno.EHOSTUNREACH


def icmp6_to_errno(*, icmp_type: int, icmp_code: int) -> int:
    """
    Map an ICMPv6 (type, code) pair to the POSIX errno that
    Linux would deliver via IPV6_RECVERR. Mirrors
    'net/ipv6/icmpv6.c::icmpv6_err_convert' in the Linux kernel.

    Reference: RFC 4443 (ICMPv6 message types).
    """

    match (icmp_type, icmp_code):
        # Destination Unreachable (type 1).
        case (1, 0):
            return _errno.ENETUNREACH  # No route to destination
        case (1, 1):
            return _errno.EACCES  # Communication admin prohibited
        case (1, 2):
            return _errno.EHOSTUNREACH  # Beyond scope of source address
        case (1, 3):
            return _errno.EHOSTUNREACH  # Address unreachable
        case (1, 4):
            return _errno.ECONNREFUSED  # Port unreachable
        case (1, 5 | 6):
            return _errno.EACCES  # Source policy / reject route
        # Packet Too Big (type 2).
        case (2, _):
            return _errno.EMSGSIZE
        # Time Exceeded (type 3).
        case (3, _):
            return _errno.EHOSTUNREACH
        # Parameter Problem (type 4).
        case (4, _):
            return _errno.EPROTO
        case _:
            return _errno.EHOSTUNREACH


def build_icmp_error_entry(
    *,
    icmp_origin: SoEeOrigin,
    icmp_type: int,
    icmp_code: int,
    offender_ip: Ip4Address | Ip6Address,
    embedded_datagram: bytes,
) -> ErrorQueueEntry:
    """
    Build an 'ErrorQueueEntry' for an inbound ICMP error matched
    to a socket. Maps the ICMP (type, code) pair to the POSIX
    errno per the family's mapping table — Linux
    'icmp_err_convert' for ICMPv4, 'icmpv6_err_convert' for
    ICMPv6 — based on the supplied 'icmp_origin'.

    Shared by UdpSocket and TcpSocket so the construction is
    identical across protocols. Both PMTU paths (errno=EMSGSIZE
    + ee_info=MTU) are still constructed inline by the caller's
    notify_pmtu because they carry the MTU as 'ee_info'; this
    helper is for the four non-PMTU notify paths.
    """

    if icmp_origin is SoEeOrigin.ICMP6:
        errno_ = icmp6_to_errno(icmp_type=icmp_type, icmp_code=icmp_code)
    else:
        errno_ = icmp4_to_errno(icmp_type=icmp_type, icmp_code=icmp_code)

    return ErrorQueueEntry(
        errno=errno_,
        origin=icmp_origin,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        offender_ip=offender_ip,
        embedded_datagram=embedded_datagram,
    )


def pack_sock_extended_err(entry: ErrorQueueEntry, /) -> bytes:
    """
    Pack one 'ErrorQueueEntry' into the Linux wire shape
    consumed by 'recvmsg(MSG_ERRQUEUE)' applications: a
    16-byte 'struct sock_extended_err' followed by the
    offender's 'sockaddr_in' (16 bytes) for IPv4 or
    'sockaddr_in6' (28 bytes) for IPv6. Applications run
    'struct.unpack' on the result with the corresponding
    format strings, transferring code unchanged from Linux.

    The 'ee_data' field is unused today (Linux reserves it
    for protocol-specific extensions, e.g. AccECN counter
    overflow). Pack as 0.
    """

    ee_errno = entry.errno & 0xFFFFFFFF
    ee_origin = entry.origin & 0xFF
    ee_type = entry.icmp_type & 0xFF
    ee_code = entry.icmp_code & 0xFF
    ee_pad = 0
    ee_info = entry.ee_info & 0xFFFFFFFF
    ee_data = 0
    extended_err = struct.pack(
        _SOCK_EXTENDED_ERR__STRUCT,
        ee_errno,
        ee_origin,
        ee_type,
        ee_code,
        ee_pad,
        ee_info,
        ee_data,
    )

    if isinstance(entry.offender_ip, Ip4Address):
        # Linux's sockaddr_in: family + port + addr + 8-byte pad.
        # ICMP has no port; pack port=0.
        offender_sockaddr = struct.pack(
            _SOCKADDR_IN__STRUCT,
            _AF_INET,
            0,
            bytes(entry.offender_ip),
        )
    else:
        # Linux's sockaddr_in6: family + port + flowinfo + addr + scope_id.
        offender_sockaddr = struct.pack(
            _SOCKADDR_IN6__STRUCT,
            _AF_INET6,
            0,
            0,
            bytes(entry.offender_ip),
            0,
        )

    return extended_err + offender_sockaddr
