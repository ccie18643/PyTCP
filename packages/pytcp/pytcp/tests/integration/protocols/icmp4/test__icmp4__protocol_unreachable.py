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
Integration tests for the ICMPv4 Protocol Unreachable generator.
RFC 1122 §3.2.2.1 says hosts SHOULD generate Destination Unreachable
code 2 in response to a datagram whose IP-layer 'proto' field
designates a transport protocol the host does not implement.

pytcp/tests/integration/protocols/icmp4/test__icmp4__protocol_unreachable.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import (
    IpProto,
)
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)


def _build_unsupported_proto_frame(
    *,
    eth_src: MacAddress = HOST_A__MAC_ADDRESS,
    eth_dst: MacAddress = STACK__MAC_ADDRESS,
    ip_src: str = str(HOST_A__IP4_ADDRESS),
    ip_dst: str = str(STACK__IP4_HOST.address),
    ip_proto: int = 42,
    payload: bytes = b"opaque payload",
) -> bytes:
    """
    Build an Ethernet/IPv4 frame whose IP 'proto' field is set to a
    value (default 42) the stack does not implement. Defaults aim a
    unicast probe at the stack so the IP RX path reaches the
    unsupported-protocol branch.
    """

    raw = RawAssembler(
        raw__payload=payload,
        ip_proto=IpProto.from_int(ip_proto),
    )
    ip4 = Ip4Assembler(
        ip4__src=Ip4Address(ip_src),
        ip4__dst=Ip4Address(ip_dst),
        ip4__payload=raw,
    )
    eth = EthernetAssembler(
        ethernet__src=eth_src,
        ethernet__dst=eth_dst,
        ethernet__payload=ip4,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


class TestIcmp4ProtocolUnreachable__CleanUnicast(IcmpTestCase, TestCase):
    """
    The ICMPv4 Protocol Unreachable generator clean-unicast tests.
    """

    def test__icmp4__protocol_unreachable__unicast_emits_response(self) -> None:
        """
        Ensure that a unicast IPv4 datagram with an unsupported 'proto'
        field elicits an ICMPv4 Destination Unreachable code 2
        (Protocol Unreachable) response.

        Reference: RFC 1122 §3.2.2.1 (host SHOULD generate Destination
        Unreachable code 2 when the designated transport protocol is
        not supported).
        """

        frames_tx = self._drive_rx(frame=_build_unsupported_proto_frame())

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Unsupported-proto unicast must produce exactly one ICMP error.",
        )
        probe = self._parse_tx_icmp4(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            3,
            msg=f"Outbound ICMPv4 must be Destination Unreachable (type 3). Got: {probe!r}",
        )
        self.assertEqual(
            probe.icmp_code,
            2,
            msg=f"Outbound ICMPv4 must be Protocol Unreachable (code 2). Got: {probe!r}",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__no_proto_support__respond_icmp4_unreachable,
            1,
            msg="ip4__no_proto_support__respond_icmp4_unreachable counter must bump exactly once.",
        )


class TestIcmp4ProtocolUnreachable__GateSuppressed(IcmpTestCase, TestCase):
    """
    The ICMPv4 Protocol Unreachable generator gate-suppression tests.
    """

    def test__icmp4__protocol_unreachable__bcast_dst_suppressed(self) -> None:
        """
        Ensure that a broadcast-destination unsupported-proto inbound
        does NOT trigger an outbound Protocol Unreachable. The same
        host-requirements gate that protects the UDP closed-port emitter
        also gates the new IP-layer emitter.

        Reference: RFC 1122 §3.2.2 (host MUST NOT send ICMP error in
        response to bcast destination).
        """

        frames_tx = self._drive_rx(
            frame=_build_unsupported_proto_frame(
                ip_dst="255.255.255.255",
                eth_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            ),
        )

        self.assertEqual(
            frames_tx,
            [],
            msg="Broadcast-dst unsupported-proto must not elicit an ICMP error.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__no_proto_support__icmp4_unreachable_suppressed,
            1,
            msg="Suppression counter must bump exactly once on broadcast-dst gate hit.",
        )
