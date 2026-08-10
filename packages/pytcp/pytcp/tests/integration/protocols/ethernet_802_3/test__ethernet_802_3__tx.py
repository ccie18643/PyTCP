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
This module contains integration tests for the Packet Handler Ethernet 802.3 TX operations.

pytcp/tests/integration/protocols/ethernet_802_3/test__ethernet_802_3__tx.py

ver 3.0.9
"""

from typing import Any

from net_proto import RawAssembler
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.ethernet_802_3_testcase import Ethernet8023TestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    MAC__UNSPECIFIED,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 - src specified MAC address",
            "_kwargs": {
                "ethernet_802_3__src": STACK__MAC_ADDRESS,
                "ethernet_802_3__dst": HOST_A__MAC_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Length          : 0x0000 (header-only frame)
                #
                # Summary: Raw 802.3 frame transmitted with caller-specified MAC addresses.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x00\x00",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet_802_3__pre_assemble=1,
                ethernet_802_3__src_spec=1,
                ethernet_802_3__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet 802.3 - src unspecified MAC address",
            "_kwargs": {
                "ethernet_802_3__src": MAC__UNSPECIFIED,
                "ethernet_802_3__dst": HOST_A__MAC_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (filled by stack)
                #   Length          : 0x0000 (header-only frame)
                #
                # Summary: Source MAC unspecified; stack fills in before transmitting the 802.3 header.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x00\x00",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet_802_3__pre_assemble=1,
                ethernet_802_3__src_unspec__fill=1,
                ethernet_802_3__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet 802.3 - dst unspecified MAC address",
            "_kwargs": {
                "ethernet_802_3__src": STACK__MAC_ADDRESS,
                "ethernet_802_3__dst": MAC__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet_802_3__pre_assemble=1,
                ethernet_802_3__src_spec=1,
                ethernet_802_3__dst_unspec__drop=1,
            ),
        },
        {
            "_description": "Ethernet 802.3 - src and dst both unspecified, src filled then dropped",
            "_kwargs": {
                "ethernet_802_3__src": MAC__UNSPECIFIED,
                "ethernet_802_3__dst": MAC__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet_802_3__pre_assemble=1,
                ethernet_802_3__src_unspec__fill=1,
                ethernet_802_3__dst_unspec__drop=1,
            ),
        },
        {
            "_description": "Ethernet 802.3 - payload",
            "_kwargs": {
                "ethernet_802_3__src": STACK__MAC_ADDRESS,
                "ethernet_802_3__dst": HOST_A__MAC_ADDRESS,
                "ethernet_802_3__payload": RawAssembler(raw__payload=bytes(range(16))),
            },
            "_expected__frames_tx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Length          : 0x0010 (16 bytes of payload)
                #
                # Payload
                #   Bytes           : 00..0f (RawAssembler content)
                #
                # Summary: 802.3 frame with a 16-byte LLC payload assembled by RawAssembler.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x00\x10\x00\x01"
                b"\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet_802_3__pre_assemble=1,
                ethernet_802_3__src_spec=1,
                ethernet_802_3__dst_spec__send=1,
            ),
        },
    ]
)
class TestPacketHandlerEthernet8023Tx(Ethernet8023TestCase):
    """
    Test the Packet Handler Ethernet 802.3 TX operations.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet_802_3__tx(self) -> None:
        """
        Ensure the Packet Handler Ethernet 802.3 TX path produces
        the expected frames, statuses, and statistics for each
        parametrized case.

        Reference: IEEE 802.3 §3 (802.3 TX).
        """

        self.assertEqual(
            self._packet_handler._phtx_ethernet_802_3(**self._kwargs),
            self._expected__tx_status,
            msg=f"Unexpected TxStatus for case: {self._description}",
        )

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )
