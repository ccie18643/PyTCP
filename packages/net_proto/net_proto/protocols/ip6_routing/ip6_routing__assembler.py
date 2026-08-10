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
This module contains the IPv6 Routing Header packet assembler.

net_proto/protocols/ip6_routing/ip6_routing__assembler.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.enums import IpProto
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.ip6_routing.ip6_routing__base import Ip6Routing
from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType
from net_proto.protocols.ip6_routing.ip6_routing__header import (
    IP6_ROUTING__HEADER__LEN,
    Ip6RoutingHeader,
)


class Ip6RoutingAssembler(Ip6Routing, ProtoAssembler):
    """
    The IPv6 Routing Header packet assembler.

    Built for symmetry with the parser. PyTCP's host stack does
    not currently emit Routing Headers — the assembler exists so
    a Phase-2 forwarder (or test fixtures) can construct them
    cleanly.
    """

    _payload: Buffer

    def __init__(
        self,
        *,
        ip6_routing__next: IpProto = IpProto.RAW,
        ip6_routing__routing_type: Ip6RoutingType = Ip6RoutingType.RH4,
        ip6_routing__segments_left: int = 0,
        ip6_routing__data: bytes = bytes(),
        ip6_routing__payload: Buffer = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the IPv6 Routing Header packet assembler.

        The 'hdr_ext_len' field is computed automatically from the
        provided type-specific data. The total header (4-byte fixed
        prefix + data) must be a multiple of 8 octets — the
        assembler asserts this requirement.
        """

        # RFC 5095 §3 — "An IPv6 node ... MUST NOT execute the
        # algorithm specified in [RFC 2460] for RH0". The hard-drop
        # mandate applies symmetrically to RX and TX: the parser at
        # `Ip6RoutingParser._validate_integrity` rejects inbound
        # RH0 with `Ip6RoutingIntegrityError(pointer=2)`; the
        # assembler MUST refuse to originate one. RH2/RH3/RH4 are
        # permitted (parsed and emitted as opaque per the existing
        # Phase-2-forwarder design); UNKNOWN_n variants are
        # tolerated so test fixtures can exercise peer-rejection
        # behaviour.
        assert ip6_routing__routing_type != Ip6RoutingType.RH0, (
            f"The IPv6 Routing Header type MUST NOT be RH0 "
            f"(RFC 5095 §3 — Type 0 Routing Header is deprecated and "
            f"hard-dropped on receipt). Got: {ip6_routing__routing_type!r}"
        )

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = ip6_routing__payload
        self._data = ip6_routing__data

        total_header_len = IP6_ROUTING__HEADER__LEN + len(self._data)

        assert total_header_len % 8 == 0, (
            "The IPv6 Routing header (4-byte prefix + type-specific data) must be "
            f"a multiple of 8 octets. Got: {total_header_len} bytes total."
        )

        # hdr_ext_len = (total_header_len / 8) - 1
        hdr_ext_len = total_header_len // 8 - 1

        self._header = Ip6RoutingHeader(
            next=ip6_routing__next,
            hdr_ext_len=hdr_ext_len,
            routing_type=ip6_routing__routing_type,
            segments_left=ip6_routing__segments_left,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IPv6 Routing packet into list of buffers.
        """

        buffers.append(bytearray(self._header))
        buffers.append(self._data)
        buffers.append(self._payload)
