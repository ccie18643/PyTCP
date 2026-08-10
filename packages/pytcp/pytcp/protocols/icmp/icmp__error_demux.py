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
This module contains the embedded-header parser shared by the ICMPv4
and ICMPv6 error demux paths. Given the 'data' field of an ICMP error
message (RFC 792 §2 / RFC 4443 §3), it extracts the inner IP+L4
4-tuple plus, for TCP, the sequence of the segment that triggered the
error so callers can apply the RFC 5927 §4 sequence-in-window guard
before acting on the error.

pytcp/protocols/icmp/icmp__error_demux.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass

from net_addr import Buffer, Ip4Address, Ip6Address, IpVersion
from net_proto import (
    IP4__HEADER__LEN,
    IP6__HEADER__LEN,
    TCP__HEADER__LEN,
    UDP__HEADER__LEN,
    IpProto,
)

# Minimum embedded data length the parser requires to dispatch the
# inner header. ICMP errors quote the inner IP header plus at least
# the first 8 octets of L4 (RFC 792 / RFC 4443 §3). UDP and TCP both
# expose 4-tuple addressing in their first 8 bytes; for TCP the seq
# field also lives within the first 8 octets so the RFC 5927 guard is
# always testable.
_EMBEDDED__MIN_L4_LEN = 8

# Bit masks for the IPv4 first byte.
_IP4__VERSION_MASK = 0xF0
_IP4__VERSION_SHIFT = 4
_IP4__IHL_MASK = 0x0F


@dataclass(frozen=True, slots=True)
class EmbeddedL4:
    """
    Decoded inner IP+L4 4-tuple extracted from the 'data' field of
    an ICMP error message.

    'local_ip' / 'local_port' refer to the addressing on the host
    that received the ICMP error (i.e. the source of the original
    datagram). 'remote_ip' / 'remote_port' refer to the destination
    that elicited the error.

    'embedded_seq' is populated only for TCP and carries the sequence
    of the segment that triggered the ICMP error. Demux paths use
    it to apply the RFC 5927 §4 sequence-in-window guard before
    notifying the matching session.
    """

    ip_version: IpVersion
    proto: IpProto
    local_ip: Ip4Address | Ip6Address
    remote_ip: Ip4Address | Ip6Address
    local_port: int
    remote_port: int
    embedded_seq: int | None = None


def parse_embedded_l4(frame: Buffer, ip_version: IpVersion, /) -> EmbeddedL4 | None:
    """
    Parse the inner IP+L4 header from an ICMP error 'data' field and
    return the extracted 4-tuple. Returns None when the frame is
    structurally invalid or carries an unsupported L4 protocol —
    callers treat that as "no demux possible" without raising.
    """

    match ip_version:
        case IpVersion.IP4:
            return _parse_embedded_ip4(frame)
        case IpVersion.IP6:
            return _parse_embedded_ip6(frame)


def _parse_embedded_ip4(frame: Buffer) -> EmbeddedL4 | None:
    """
    Parse an embedded IPv4 + UDP/TCP header. Returns None on any
    structural integrity failure (truncated, bad version, unsupported
    L4 proto).
    """

    frame_bytes = bytes(frame)

    if len(frame_bytes) < IP4__HEADER__LEN:
        return None

    if (frame_bytes[0] & _IP4__VERSION_MASK) >> _IP4__VERSION_SHIFT != 4:
        return None

    ihl_words = frame_bytes[0] & _IP4__IHL_MASK
    ihl_bytes = ihl_words << 2

    if ihl_bytes < IP4__HEADER__LEN or len(frame_bytes) < ihl_bytes:
        return None

    proto = IpProto.from_int(frame_bytes[9])

    if proto not in (IpProto.UDP, IpProto.TCP):
        return None

    l4_min_len = UDP__HEADER__LEN if proto is IpProto.UDP else TCP__HEADER__LEN
    # We accept frames that carry only the first 8 octets of TCP
    # (RFC 1812 §4.3.2.3 says ICMP errors quote at least 8 octets of
    # the inner L4 header — the 4-tuple and seq both fit in those 8
    # bytes). 'l4_min_len' is the maximum we'd parse; we only need
    # _EMBEDDED__MIN_L4_LEN to decode the 4-tuple + seq.
    _ = l4_min_len  # documentation only — the actual check is below

    if len(frame_bytes) < ihl_bytes + _EMBEDDED__MIN_L4_LEN:
        return None

    local_ip = Ip4Address(frame_bytes[12:16])
    remote_ip = Ip4Address(frame_bytes[16:20])
    local_port = struct.unpack("!H", frame_bytes[ihl_bytes + 0 : ihl_bytes + 2])[0]
    remote_port = struct.unpack("!H", frame_bytes[ihl_bytes + 2 : ihl_bytes + 4])[0]

    embedded_seq: int | None = None
    if proto is IpProto.TCP:
        embedded_seq = struct.unpack("!L", frame_bytes[ihl_bytes + 4 : ihl_bytes + 8])[0]

    return EmbeddedL4(
        ip_version=IpVersion.IP4,
        proto=proto,
        local_ip=local_ip,
        remote_ip=remote_ip,
        local_port=local_port,
        remote_port=remote_port,
        embedded_seq=embedded_seq,
    )


def _parse_embedded_ip6(frame: Buffer) -> EmbeddedL4 | None:
    """
    Parse an embedded IPv6 + UDP/TCP header. IPv6 extension headers
    are not handled — if the embedded packet uses them the parser
    bails out with None. Callers treat that as "no demux possible".
    """

    frame_bytes = bytes(frame)

    if len(frame_bytes) < IP6__HEADER__LEN:
        return None

    if (frame_bytes[0] & _IP4__VERSION_MASK) >> _IP4__VERSION_SHIFT != 6:
        return None

    proto = IpProto.from_int(frame_bytes[6])

    if proto not in (IpProto.UDP, IpProto.TCP):
        return None

    if len(frame_bytes) < IP6__HEADER__LEN + _EMBEDDED__MIN_L4_LEN:
        return None

    local_ip = Ip6Address(frame_bytes[8:24])
    remote_ip = Ip6Address(frame_bytes[24:40])
    l4_offset = IP6__HEADER__LEN
    local_port = struct.unpack("!H", frame_bytes[l4_offset + 0 : l4_offset + 2])[0]
    remote_port = struct.unpack("!H", frame_bytes[l4_offset + 2 : l4_offset + 4])[0]

    embedded_seq: int | None = None
    if proto is IpProto.TCP:
        embedded_seq = struct.unpack("!L", frame_bytes[l4_offset + 4 : l4_offset + 8])[0]

    return EmbeddedL4(
        ip_version=IpVersion.IP6,
        proto=proto,
        local_ip=local_ip,
        remote_ip=remote_ip,
        local_port=local_port,
        remote_port=remote_port,
        embedded_seq=embedded_seq,
    )
