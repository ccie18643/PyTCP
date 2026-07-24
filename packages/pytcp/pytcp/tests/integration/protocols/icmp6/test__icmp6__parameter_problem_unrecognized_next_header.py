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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the ICMPv6 Unrecognized Next Header generator.
RFC 8200 §4 mandates that an IPv6 node receiving a packet with an
unrecognized Next Header value MUST discard the packet and send an
ICMPv6 Parameter Problem (code 1) with a pointer to the offending
Next Header field.

pytcp/tests/integration/protocols/icmp6/test__icmp6__parameter_problem_unrecognized_next_header.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Buffer, Ip6Address, MacAddress
from net_proto import (
    IpProto,
)
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)


def _build_unrecognized_next_header_frame(
    *,
    eth_src: MacAddress = HOST_A__MAC_ADDRESS,
    eth_dst: MacAddress = STACK__MAC_ADDRESS,
    ip_src: str = str(HOST_A__IP6_ADDRESS),
    ip_dst: str = str(STACK__IP6_HOST.address),
    next_header: int = 142,
    payload: bytes = b"opaque payload",
) -> bytes:
    """
    Build an Ethernet/IPv6 frame whose IPv6 Next Header field is set
    to a value (default 142) the stack does not implement.
    """

    raw = RawAssembler(
        raw__payload=payload,
        ip_proto=IpProto.from_int(next_header),
    )
    ip6 = Ip6Assembler(
        ip6__src=Ip6Address(ip_src),
        ip6__dst=Ip6Address(ip_dst),
        ip6__payload=raw,
    )
    eth = EthernetAssembler(
        ethernet__src=eth_src,
        ethernet__dst=eth_dst,
        ethernet__payload=ip6,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


class TestIcmp6UnrecognizedNextHeader__CleanUnicast(IcmpTestCase, TestCase):
    """
    The ICMPv6 Unrecognized Next Header generator clean-unicast tests.
    """

    def test__icmp6__parameter_problem__unrecognized_next_header__unicast_emits_response(self) -> None:
        """
        Ensure that a unicast IPv6 datagram with an unrecognized Next
        Header value elicits an ICMPv6 Parameter Problem (code 1)
        response with a pointer to the offending Next Header field
        (offset 6 in the IPv6 main header).

        Reference: RFC 8200 §4 (IPv6 node MUST discard and send Param
        Problem code 1 on unrecognized Next Header).
        Reference: RFC 4443 §3.4 (Parameter Problem code 1 wire format).
        """

        frames_tx = self._drive_rx(frame=_build_unrecognized_next_header_frame())

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Unsupported-next-header unicast must produce exactly one ICMPv6 error.",
        )
        probe = self._parse_tx_icmp6(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            4,
            msg=f"Outbound ICMPv6 must be Parameter Problem (type 4). Got: {probe!r}",
        )
        self.assertEqual(
            probe.icmp_code,
            1,
            msg=f"Outbound ICMPv6 must be Unrecognized Next Header (code 1). Got: {probe!r}",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6__no_proto_support__respond_icmp6_param_problem,
            1,
            msg="ip6__no_proto_support__respond_icmp6_param_problem counter must bump exactly once.",
        )
