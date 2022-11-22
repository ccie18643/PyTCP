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


#
# tests/ip4_phtx.py -  tests specific for IPv4 phtx module
#
# ver 2.7
#


from testslide import TestCase

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.raw.fpa import RawAssembler
from tests.unit.mock_network import (
    MockNetworkSettings,
    patch_config,
    setup_mock_packet_handler,
)

TEST_FRAME_DIR = "tests/unit/test_frames/ip4_phtx/"


class TestIp4Phtx(TestCase):
    """
    IPv4 packet handler TX unit test class.
    """

    def setUp(self) -> None:
        """
        Setup tests.
        """
        super().setUp()
        self.mns = MockNetworkSettings()
        patch_config(self)
        setup_mock_packet_handler(self)

    # Test name format: 'test_name__test_description__optional_condition'

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_valid(
        self,
    ) -> None:
        """
        Test sending IPv4 packet to unicast address on local network,
        valid source.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_to_unicast_address_on_local_network__src_valid.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_not_owned_drop(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        src not owned.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.host_b_ip4_address,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__IP4__SRC_NOT_OWNED)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_not_owned__drop=1,
            ),
        )

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_multicast_replace(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        multicast source, able to replace.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_multicast_all_nodes,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_multicast__replace=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_to_unicast_address_on_local_network__src_multicast_replace.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_multicast_drop(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        multicast source, not able to replace.
        """
        self.packet_handler.ip4_host = []

        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_multicast_all_nodes,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__IP4__SRC_MULTICAST)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_multicast__drop=1,
            ),
        )

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_limited_broadcast_replace(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        limited broadcst source, able to replace.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_limited_broadcast,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_limited_broadcast__replace=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_to_unicast_address_on_local_network__src_limited_broadcast_replace.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_limited_broadcast_drop(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        limited broadcast source, not able to replace.
        """
        self.packet_handler.ip4_host = []
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_limited_broadcast,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__IP4__SRC_LIMITED_BROADCAST)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_limited_broadcast__drop=1,
            ),
        )

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_network_broadcast_replace(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        network broadcst source, able to replace.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.network.broadcast,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_network_broadcast__replace=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_to_unicast_address_on_local_network__src_network_broadcast_replace.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_unspecified_replace_local(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        uspecified source, able to replace.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_unspecified,
            ip4_dst=self.mns.host_a_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_network_unspecified__replace_local=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_to_unicast_address_on_local_network__src_unspecified_replace_local.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_unspecified_replace_external(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        uspecified source, able to replace with ip from subnet with gateway.
        """
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_unspecified,
            ip4_dst=self.mns.host_c_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_network_unspecified__replace_external=1,
                ip4__mtu_ok__send=1,
                ether__pre_assemble=1,
                ether__src_unspec__fill=1,
                ether__dst_unspec__ip4_lookup=1,
                ether__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send=1,
            ),
        )
        with open(
            TEST_FRAME_DIR
            + "ip4_to_unicast_address_on_local_network__src_unspecified_replace_external.tx",
            "rb",
        ) as _:
            frame_tx = _.read()
        self.assertEqual(self.frame_tx[: len(frame_tx)], frame_tx)

    def test_ip4_phtx__ip4_to_unicast_address_on_local_network__src_unspecified_drop(
        self,
    ):
        """
        Test sending IPv4 packet to unicast address on local network,
        uspecified source, not able to replace.
        """
        self.mns.stack_ip4_host.gateway = None
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.ip4_unspecified,
            ip4_dst=self.mns.host_c_ip4_address,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__IP4__SRC_UNSPECIFIED)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__src_unspecified__drop=1,
            ),
        )

    def test_ip4_phtx__ip4_to_unspecified_address__dst_unspecified_drop(
        self,
    ) -> None:
        """
        Test sending IPv4 packet to unspecified address.
        """
        self.mns.stack_ip4_host.gateway = None
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.ip4_unspecified,
        )
        self.assertEqual(tx_status, TxStatus.DROPED__IP4__DST_UNSPECIFIED)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__dst_unspecified__drop=1,
            ),
        )

    def test_ip4_phtx__ip4_fragmentation(self) -> None:
        """
        Test sending IPv4 packet large enough to require fragmentation.
        """
        self.mns.stack_ip4_host.gateway = None
        tx_status = self.packet_handler._phtx_ip4(
            ip4_src=self.mns.stack_ip4_host.address,
            ip4_dst=self.mns.host_a_ip4_address,
            carried_packet=RawAssembler(data=b"01234567890ABCDEF" * 400),
        )
        self.assertEqual(tx_status, TxStatus.PASSED__ETHER__TO_TX_RING)
        self.assertEqual(
            self.packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_exceed__frag=1,
                ip4__mtu_exceed__frag__send=5,
                ether__pre_assemble=5,
                ether__src_unspec__fill=5,
                ether__dst_unspec__ip4_lookup=5,
                ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=5,
            ),
        )
        for index in range(5):
            with open(
                f"tests/unit/test_frames/ip4_phtx/ip4_fragmentation__frag_{index}.tx",
                "rb",
            ) as _:
                frame_tx = _.read()
            self.assertEqual(self.frames_tx[index][: len(frame_tx)], frame_tx)
