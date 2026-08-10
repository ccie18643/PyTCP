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
This module contains tests for the RFC 6980 §5 NDP-no-
fragmentation predicate ('is_ndp_message') in
'pytcp/runtime/packet_handler/packet_handler__ip6_frag__tx.py'.

pytcp/tests/unit/runtime/packet_handler/test__packet_handler__ip6_frag__tx__rfc6980.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptions,
    RawAssembler,
    TcpAssembler,
    UdpAssembler,
)
from net_proto.protocols.icmp6.message.icmp6__message__echo_request import (
    Icmp6MessageEchoRequest,
)
from pytcp.runtime.packet_handler.packet_handler__ip6_frag__tx import is_ndp_message


class TestIp6FragRfc6980NdpPredicate(TestCase):
    """
    'is_ndp_message' identifies ICMPv6 NDP messages (RS / RA
    / NS / NA / Redirect) so the IPv6 TX fragmentation path
    can refuse to fragment them per RFC 6980 §5.
    """

    def test__is_ndp_message__neighbor_solicitation(self) -> None:
        """
        Ensure 'is_ndp_message' returns True for an
        Icmp6Assembler carrying a Neighbor Solicitation.

        Reference: RFC 6980 §5 (NDP messages MUST NOT use IPv6 fragmentation).
        """

        ns_payload = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageNeighborSolicitation(
                target_address=Ip6Address("fe80::1"),
                options=Icmp6NdOptions(),
            ),
        )

        self.assertTrue(
            is_ndp_message(ns_payload),
            msg="Neighbor Solicitation must be recognised as an NDP message.",
        )

    def test__is_ndp_message__neighbor_advertisement(self) -> None:
        """
        Ensure 'is_ndp_message' returns True for a Neighbor
        Advertisement.

        Reference: RFC 6980 §5.
        """

        na_payload = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageNeighborAdvertisement(
                target_address=Ip6Address("fe80::1"),
                flag_r=False,
                flag_s=True,
                flag_o=False,
                options=Icmp6NdOptions(),
            ),
        )

        self.assertTrue(
            is_ndp_message(na_payload),
            msg="Neighbor Advertisement must be recognised as an NDP message.",
        )

    def test__is_ndp_message__router_solicitation(self) -> None:
        """
        Ensure 'is_ndp_message' returns True for a Router
        Solicitation.

        Reference: RFC 6980 §5.
        """

        rs_payload = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageRouterSolicitation(
                options=Icmp6NdOptions(),
            ),
        )

        self.assertTrue(
            is_ndp_message(rs_payload),
            msg="Router Solicitation must be recognised as an NDP message.",
        )

    def test__is_ndp_message__router_advertisement(self) -> None:
        """
        Ensure 'is_ndp_message' returns True for a Router
        Advertisement.

        Reference: RFC 6980 §5.
        """

        ra_payload = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageRouterAdvertisement(
                hop=64,
                flag_m=False,
                flag_o=False,
                router_lifetime=1800,
                reachable_time=0,
                retrans_timer=0,
                options=Icmp6NdOptions(),
            ),
        )

        self.assertTrue(
            is_ndp_message(ra_payload),
            msg="Router Advertisement must be recognised as an NDP message.",
        )

    def test__is_ndp_message__echo_request_not_ndp(self) -> None:
        """
        Ensure 'is_ndp_message' returns False for a
        non-NDP ICMPv6 message (Echo Request).

        Reference: RFC 6980 §5 (gate only applies to NDP types).
        """

        echo_payload = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoRequest(id=0x1234, seq=1),
        )

        self.assertFalse(
            is_ndp_message(echo_payload),
            msg="Echo Request must NOT be flagged as an NDP message.",
        )

    def test__is_ndp_message__tcp_not_ndp(self) -> None:
        """
        Ensure 'is_ndp_message' returns False for a
        TCP-payload IPv6 packet.

        Reference: RFC 6980 §5 (only applies to ICMPv6 NDP types).
        """

        tcp_payload = TcpAssembler(tcp__sport=80, tcp__dport=12345)

        self.assertFalse(
            is_ndp_message(tcp_payload),
            msg="TCP payload must NOT be flagged as an NDP message.",
        )

    def test__is_ndp_message__udp_not_ndp(self) -> None:
        """
        Ensure 'is_ndp_message' returns False for a
        UDP-payload IPv6 packet.

        Reference: RFC 6980 §5 (only applies to ICMPv6 NDP types).
        """

        udp_payload = UdpAssembler(udp__sport=53, udp__dport=12345)

        self.assertFalse(
            is_ndp_message(udp_payload),
            msg="UDP payload must NOT be flagged as an NDP message.",
        )

    def test__is_ndp_message__raw_not_ndp(self) -> None:
        """
        Ensure 'is_ndp_message' returns False for a Raw IPv6
        payload (e.g. test fixture).

        Reference: RFC 6980 §5 (only applies to ICMPv6 NDP types).
        """

        raw_payload = RawAssembler(raw__payload=b"\x00" * 64)

        self.assertFalse(
            is_ndp_message(raw_payload),
            msg="Raw payload must NOT be flagged as an NDP message.",
        )

    def test__is_ndp_message__none_not_ndp(self) -> None:
        """
        Ensure 'is_ndp_message' returns False for a non-
        assembler argument (defensive — the predicate's
        isinstance guard makes it safe to call on any
        IPv6 payload candidate).

        Reference: PyTCP test infrastructure (defensive predicate).
        """

        self.assertFalse(
            is_ndp_message(None),
            msg="None must NOT be flagged as an NDP message.",
        )

    def test__is_ndp_message__mac_address_not_ndp(self) -> None:
        """
        Ensure 'is_ndp_message' returns False for an
        unrelated object type (defensive).

        Reference: PyTCP test infrastructure (defensive predicate).
        """

        self.assertFalse(
            is_ndp_message(MacAddress("02:00:00:00:00:01")),
            msg="MacAddress must NOT be flagged as an NDP message.",
        )
