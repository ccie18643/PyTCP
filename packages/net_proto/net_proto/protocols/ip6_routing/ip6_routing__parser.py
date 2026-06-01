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
This module contains the IPv6 Routing Header packet parser class.

net_proto/protocols/ip6_routing/ip6_routing__parser.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip6_routing.ip6_routing__base import Ip6Routing
from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType
from net_proto.protocols.ip6_routing.ip6_routing__errors import (
    Ip6RoutingIntegrityError,
)
from net_proto.protocols.ip6_routing.ip6_routing__header import (
    IP6_ROUTING__HEADER__LEN,
    Ip6RoutingHeader,
)

# RFC 5095 §3 hard-drop pointer for RH0: the offset of the Routing
# Type byte within the Routing Header (used by Phase 8's chain-walker
# to compute the absolute IPv6-packet pointer for Param Problem code 0).
IP6_ROUTING__ROUTING_TYPE__OFFSET = 2


class Ip6RoutingParser(Ip6Routing, ProtoParser):
    """
    The IPv6 Routing Header packet parser.

    RFC 5095 §3 mandates a hard-drop on receipt of routing_type=0
    (RH0) with ICMPv6 Parameter Problem code 0 pointing at the
    Routing Type byte. The integrity-check phase enforces this by
    raising 'Ip6RoutingIntegrityError(pointer=2)' before any further
    parsing. The chain-walker in Phase 8 catches the error, computes
    the absolute pointer (40 + chain_offset + 2), and emits the
    ICMPv6 reply.

    Other routing types (RH2 / RH3 / RH4 and unknowns via dynamic
    enum extension) are parsed as opaque type-specific data — the
    host has no semantic action to take, but a future Phase-2
    forwarder must re-emit the bytes faithfully.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv6 Routing Header packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip6_routing = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv6 Routing packet before parsing it.
        """

        # RFC 8200 §4.4 — the Routing header's fixed prefix is 4
        # octets (Next Header / Hdr Ext Len / Routing Type /
        # Segments Left); the type-specific data follows.
        if len(self._frame) < IP6_ROUTING__HEADER__LEN:
            raise Ip6RoutingIntegrityError(
                "The condition 'IP6_ROUTING__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP6_ROUTING__HEADER__LEN=}, {len(self._frame)=}",
            )

        # RFC 8200 §4.4 — Hdr Ext Len in 8-octet units NOT
        # including the first 8 octets; total wire length =
        # (Hdr Ext Len + 1) * 8. Frame MUST hold every octet the
        # header claims.
        hdr_ext_len = self._frame[1]
        total_routing_len = (hdr_ext_len + 1) * 8

        if total_routing_len > len(self._frame):
            raise Ip6RoutingIntegrityError(
                "The condition '(hdr_ext_len + 1) * 8 <= len(self._frame)' must be met. "
                f"Got: {hdr_ext_len=}, {total_routing_len=}, {len(self._frame)=}",
            )

        # RFC 5095 §3 — "An IPv6 node that receives a packet with
        # a destination address assigned to it and containing an
        # RH0 extension header MUST NOT execute the algorithm
        # specified in the latter part of RFC 2460 Section 4.4
        # for RH0. Instead, such packets MUST be processed
        # according to the behavior described in [RFC4884] for a
        # packet with an unrecognized Routing Type value." Hard-
        # drop with ICMPv6 Parameter Problem Code 0 (Erroneous
        # Header Field Encountered) pointing at the Routing Type
        # byte.
        routing_type = self._frame[IP6_ROUTING__ROUTING_TYPE__OFFSET]
        if routing_type == int(Ip6RoutingType.RH0):
            raise Ip6RoutingIntegrityError(
                "RFC 5095 §3: Type 0 Routing Header (RH0) is deprecated; "
                "drop with ICMPv6 Parameter Problem code 0 (erroneous header field).",
                pointer=IP6_ROUTING__ROUTING_TYPE__OFFSET,
            )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 Routing packet.
        """

        self._header = Ip6RoutingHeader.from_buffer(self._frame)
        total_routing_len = (self._header.hdr_ext_len + 1) * 8
        self._data = bytes(self._frame[IP6_ROUTING__HEADER__LEN:total_routing_len])
        self._payload = self._frame[total_routing_len:]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv6 Routing packet after parsing it.

        No host-side sanity rules apply to non-RH0 routing types —
        the host preserves the data block byte-for-byte and forwards
        it through to the chain walker. RH2/3/4 semantics are
        forwarder-only (Phase 2 of the project) and out of scope here.
        """

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv6 Routing packet header bytes (full header
        including the trailing type-specific data block).
        """

        return self._frame[: (self._header.hdr_ext_len + 1) * 8]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv6 Routing packet payload bytes.
        """

        return self._payload
