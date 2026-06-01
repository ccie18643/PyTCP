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
Integration tests for the Packet Handler ARP TX operations,
migrated to 'ArpTestCase'. The legacy fixture-style copy is
preserved at 'pytcp/tests/integration/packet_handler/test__packet_handler__arp__tx.py'
for reference; this file is the canonical migration target.

pytcp/tests/integration/protocols/arp/test__arp__tx.py

ver 3.0.8
"""

from typing import Any

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto import ArpOperation
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.arp_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - request, broadcast resolution lookup",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__BROADCAST,
                "arp__oper": ArpOperation.REQUEST,
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": MAC__UNSPECIFIED,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=STACK__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=STACK__MAC_ADDRESS,
                    arp_spa=STACK__IP4_HOST.address,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=HOST_A__IP4_ADDRESS,
                ),
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet/ARP - reply, unicast direct response",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
                "arp__oper": ArpOperation.REPLY,
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": HOST_A__MAC_ADDRESS,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=HOST_A__MAC_ADDRESS,
                    ethernet_src=STACK__MAC_ADDRESS,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=STACK__MAC_ADDRESS,
                    arp_spa=STACK__IP4_HOST.address,
                    arp_tha=HOST_A__MAC_ADDRESS,
                    arp_tpa=HOST_A__IP4_ADDRESS,
                ),
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
    ]
)
class TestArpTx(ArpTestCase):
    """
    The Packet Handler ARP TX success-path tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    def test__arp__tx(self) -> None:
        """
        Ensure the Packet Handler ARP TX path produces the expected
        wire frame, TxStatus, and TX packet stats for each
        parametrized case.

        Reference: RFC 826 (foundational ARP wire format).
        """

        self.assertEqual(
            self._packet_handler._phtx_arp(**self._kwargs),
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


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - invalid ArpOperation, raises ValueError",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__BROADCAST,
                # 'ArpOperation.from_int' extends the enum with
                # UNKNOWN_<value>; this is the only way to
                # construct an out-of-spec member that exercises
                # the 'case _:' arm in '_phtx_arp'.
                "arp__oper": ArpOperation.from_int(0x55),
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": MAC__UNSPECIFIED,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_expected__error": ValueError("Invalid ARP operation: Unknown 85"),
        },
    ]
)
class TestArpTxErrors(ArpTestCase):
    """
    The Packet Handler ARP TX error-path tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__error: Exception

    def test__arp__tx__error(self) -> None:
        """
        Ensure the Packet Handler ARP TX path raises the expected
        exception when handed an out-of-spec ArpOperation.

        Reference: RFC 826 (only REQUEST = 1 / REPLY = 2 are defined).
        """

        with self.assertRaises(type(self._expected__error)) as error:
            self._packet_handler._phtx_arp(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            str(self._expected__error),
            msg=f"Unexpected error message for case: {self._description}",
        )


class TestArpTxNoIp4Support(ArpTestCase):
    """
    The Packet Handler ARP TX no-IPv4-support short-circuit tests.
    """

    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable IPv4 protocol
        support so the ARP TX path takes the no-protocol-support
        branch.
        """

        super().setUp()
        self._packet_handler._ip4_support = False

    def test__arp__tx__no_ip4_support(self) -> None:
        """
        Ensure '_phtx_arp' returns 'DROPPED__ARP__NO_PROTOCOL_SUPPORT'
        and bumps only 'arp__pre_assemble' / 'arp__no_proto_support__drop'
        when IPv4 protocol support is disabled — no frame is emitted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tx_status = self._packet_handler._phtx_arp(
            ethernet__src=STACK__MAC_ADDRESS,
            ethernet__dst=MAC__BROADCAST,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=STACK__MAC_ADDRESS,
            arp__spa=STACK__IP4_HOST.address,
            arp__tha=MAC__UNSPECIFIED,
            arp__tpa=HOST_A__IP4_ADDRESS,
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__ARP__NO_PROTOCOL_SUPPORT,
            msg="'_phtx_arp' must return 'DROPPED__ARP__NO_PROTOCOL_SUPPORT' when IPv4 is disabled.",
        )

        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when IPv4 protocol support is disabled.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                arp__pre_assemble=1,
                arp__no_proto_support__drop=1,
            ),
            msg="Only 'arp__pre_assemble' and 'arp__no_proto_support__drop' must be bumped.",
        )


@parameterized_class(
    [
        {
            "_description": "_send_arp_reply - unicast reply to peer",
            "_method_name": "_send_arp_reply",
            "_kwargs": {
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": HOST_A__MAC_ADDRESS,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_clear_ip4_host": False,
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=HOST_A__MAC_ADDRESS,
                    ethernet_src=STACK__MAC_ADDRESS,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=STACK__MAC_ADDRESS,
                    arp_spa=STACK__IP4_HOST.address,
                    arp_tha=HOST_A__MAC_ADDRESS,
                    arp_tpa=HOST_A__IP4_ADDRESS,
                ),
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "send_arp_request - resolution lookup with own IP populated",
            "_method_name": "send_arp_request",
            "_kwargs": {"arp__tpa": HOST_A__IP4_ADDRESS},
            "_clear_ip4_host": False,
            "_expected__frames_tx": [
                # SPA = first entry of '_ip4_unicast' = STACK__IP4_HOST.
                ArpTestCase._build_arp_frame(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=STACK__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=STACK__MAC_ADDRESS,
                    arp_spa=STACK__IP4_HOST.address,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=HOST_A__IP4_ADDRESS,
                ),
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "send_arp_request - resolution lookup with empty '_ip4_unicast' (pre-DAD)",
            "_method_name": "send_arp_request",
            "_kwargs": {"arp__tpa": HOST_A__IP4_ADDRESS},
            "_clear_ip4_host": True,
            "_expected__frames_tx": [
                # SPA falls back to the unspecified Ip4Address()
                # when '_ip4_unicast' is empty (pre-DAD state).
                ArpTestCase._build_arp_frame(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=STACK__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=STACK__MAC_ADDRESS,
                    arp_spa=Ip4Address(),
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=HOST_A__IP4_ADDRESS,
                ),
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
    ]
)
class TestArpTxHelpers(ArpTestCase):
    """
    The Packet Handler ARP TX convenience-helper tests.
    """

    _description: str
    _method_name: str
    _kwargs: dict[str, Any]
    _clear_ip4_host: bool
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_tx: PacketStatsTx

    def test__arp__tx__helper(self) -> None:
        """
        Ensure each ARP TX convenience helper
        ('_send_arp_reply' / 'send_arp_request')
        emits the expected wire frame and bumps the expected TX
        statistics.

        Reference: RFC 826 (ARP Request / Reply wire format).
        """

        if self._clear_ip4_host:
            self._packet_handler._ip4_ifaddr = []

        getattr(self._packet_handler, self._method_name)(**self._kwargs)

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
