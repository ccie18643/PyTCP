#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable=fixme


#
# tests/icmp6_phtx.py -  tests specific for ICMPv6 phtx module
#
# ver 3.0.2
#


from testslide import TestCase

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6DestinationUnreachableMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_reply import (
    Icmp6EchoReplyMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_request import (
    Icmp6EchoRequestMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
)
from pytcp.subsystems.packet_handler import PacketHandler
from tests__legacy.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests__legacy/unit/test_frames/icmp6_phtx/"


class TestIcmp6Phtx(TestCase):
    """
    ICMPv6 packet handler TX unit test class.
    """

    def setUp(self) -> None:
        """
        Setup tests.
        """
        super().setUp()
        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)
        self.frame_tx: bytearray
        self.packet_handler: PacketHandler

    # Test name format: 'test_name__test_description__optional_condition'

    def test_icmp6_phtx__ip6_icmp6_echo_request(self) -> None:
        """
        Test sending the IPv6/ICMPv6 'Echo Request' packet.
        """
        tx_status = self.packet_handler._phtx_icmp6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_a_ip6_address,
            icmp6__message=Icmp6EchoRequestMessage(
                id=12345,
                seq=54320,
                data=b"0123456789ABCDEF" * 20,
            ),
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__echo_request__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_echo_request.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp6_phtx__ip6_icmp6_echo_reply(self) -> None:
        """
        Test sending the IPv6/ICMPv6 'Echo Reply' packet.
        """

        tx_status = self.packet_handler._phtx_icmp6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_a_ip6_address,
            icmp6__message=Icmp6EchoReplyMessage(
                id=12345,
                seq=54320,
                data=b"0123456789ABCDEF" * 20,
            ),
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__echo_reply__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_echo_reply.tx", "rb") as _:
            frame_tx = _.read()

        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp6_phtx__ip6_icmp6_unreachable_port(self) -> None:
        """
        Test sending the IPv6/ICMPv6 'Unreachable Port' packet.
        """
        tx_status = self.packet_handler._phtx_icmp6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.host_a_ip6_address,
            icmp6__message=Icmp6DestinationUnreachableMessage(
                code=Icmp6DestinationUnreachableCode.PORT,
                data=b"0123456789ABCDEF" * 100,
            ),
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__destination_unreachable__port__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        )
        with open(TEST_FRAME_DIR + "ip6_icmp6_unreachable_port.tx", "rb") as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_icmp6_phtx__ip6_icmp6_nd_router_solicitation(self) -> None:
        """
        Test sending the IPv6/ICMPv6 'ND Router Solicitation' packet.
        """
        tx_status = self.packet_handler._phtx_icmp6(
            ip6__src=self.mns.stack_ip6_host.address,
            ip6__dst=self.mns.ip6_multicast_all_routers,
            ip6__hop=255,
            icmp6__message=Icmp6NdRouterSolicitationMessage(
                options=Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=self.mns.stack_mac_address)
                ),
            ),
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__router_solicitation__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR + "ip6_icmp6_nd_router_solicitation.tx", "rb"
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)


# TODO: ND Router Advertisement test needed.
# TODO: ND Neighbor Solicitation test needed (also need to test the variant
# TODO: used by DAD with :: src address and no options).
# TODO: ND Neighbor Advertisement test needed.
