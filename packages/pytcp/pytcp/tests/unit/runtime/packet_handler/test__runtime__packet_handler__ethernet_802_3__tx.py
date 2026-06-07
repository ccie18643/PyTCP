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
This module contains unit tests for the 'Ethernet8023TxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ethernet_802_3__tx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import create_autospec

from net_addr import MacAddress
from net_proto import Ethernet8023Assembler, RawAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__ethernet_802_3__tx import Ethernet8023TxHandler
from pytcp.runtime.tx_ring import TxRing

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
PEER__MAC_ADDRESS = MacAddress("02:00:00:00:00:91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' interface.

    Carries the TX-stat counters, the stack MAC, and the per-interface
    TX ring the 802.3 TX sub-handler reaches through 'self._if'. A
    purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        """
        Initialize the stub interface with the bare attributes the
        sub-handler reads.
        """

        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._tx_ring: TxRing | None = None


class TestPacketHandlerEthernet8023Tx(TestCase):
    """
    The 'Ethernet8023TxHandler._phtx_ethernet_802_3' behaviour tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the 802.3 TX sub-handler over a stub interface and inject
        a mock TX ring so assemble()-enqueue calls can be inspected
        without touching a real file descriptor.
        """

        self._if = _StubInterface()

        # The TX ring is injected per-interface; assign the mock to the
        # stub interface's own '_tx_ring' (the send-out path reads it
        # through 'self._if').
        self._tx_ring = create_autospec(TxRing, spec_set=True)
        self._if._tx_ring = self._tx_ring

        self._tx = Ethernet8023TxHandler(interface=cast("PacketHandlerL2", self._if))

    def test__stack__packet_handler__ethernet_802_3__tx__fills_unspecified_src(self) -> None:
        """
        Ensure the handler fills an unspecified source MAC with the
        stack's unicast MAC and increments 'ethernet_802_3__src_unspec__fill'.

        Reference: IEEE 802.3 §3 (802.3 TX).
        """

        status = self._tx._phtx_ethernet_802_3(
            ethernet_802_3__dst=PEER__MAC_ADDRESS,
            ethernet_802_3__payload=RawAssembler(),
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING,
            msg="Handler must return PASSED__ETHERNET_802_3__TO_TX_RING when dst is specified.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__pre_assemble,
            1,
            msg="ethernet_802_3__pre_assemble must be incremented exactly once.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__src_unspec__fill,
            1,
            msg="ethernet_802_3__src_unspec__fill must be incremented when src is unspecified.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__dst_spec__send,
            1,
            msg="ethernet_802_3__dst_spec__send must be incremented when dst is specified.",
        )

        self._tx_ring.enqueue.assert_called_once()
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertIsInstance(
            enqueued,
            Ethernet8023Assembler,
            msg="Handler must enqueue an Ethernet8023Assembler instance.",
        )
        self.assertEqual(
            enqueued.src,
            STACK__MAC_UNICAST,
            msg="The enqueued packet's src MAC must be set to the stack unicast MAC.",
        )
        self.assertEqual(
            enqueued.dst,
            PEER__MAC_ADDRESS,
            msg="The enqueued packet's dst MAC must match the caller-supplied dst.",
        )

    def test__stack__packet_handler__ethernet_802_3__tx__honors_specified_src(self) -> None:
        """
        Ensure the handler does not overwrite a caller-supplied source
        MAC and instead increments 'ethernet_802_3__src_spec'.

        Reference: IEEE 802.3 §3 (802.3 TX).
        """

        custom_src = MacAddress("02:00:00:00:00:aa")

        status = self._tx._phtx_ethernet_802_3(
            ethernet_802_3__src=custom_src,
            ethernet_802_3__dst=PEER__MAC_ADDRESS,
            ethernet_802_3__payload=RawAssembler(),
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING,
            msg="Handler must return PASSED__ETHERNET_802_3__TO_TX_RING when dst is specified.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__src_spec,
            1,
            msg="ethernet_802_3__src_spec must be incremented when a src MAC is supplied.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__src_unspec__fill,
            0,
            msg="ethernet_802_3__src_unspec__fill must NOT be incremented when src is supplied.",
        )

        self._tx_ring.enqueue.assert_called_once()
        enqueued = self._tx_ring.enqueue.call_args.args[0]
        self.assertEqual(
            enqueued.src,
            custom_src,
            msg="The enqueued packet's src MAC must equal the caller-supplied src.",
        )

    def test__stack__packet_handler__ethernet_802_3__tx__drops_when_dst_unspecified(self) -> None:
        """
        Ensure the handler drops the packet when the destination MAC is
        unspecified, returns 'DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL',
        and does not enqueue to the TX ring.

        Reference: IEEE 802.3 §3 (802.3 TX).
        """

        status = self._tx._phtx_ethernet_802_3(
            ethernet_802_3__payload=RawAssembler(),
        )

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL,
            msg="Handler must return DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL when dst is unspecified.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__dst_unspec__drop,
            1,
            msg="ethernet_802_3__dst_unspec__drop must be incremented when dst is unspecified.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__dst_spec__send,
            0,
            msg="ethernet_802_3__dst_spec__send must NOT be incremented when the packet is dropped.",
        )
        self._tx_ring.enqueue.assert_not_called()

    def test__stack__packet_handler__ethernet_802_3__tx__defaults_drop_with_no_kwargs(self) -> None:
        """
        Ensure calling the handler without any kwargs (all defaults)
        drops the packet — both src and dst default to unspecified.

        Reference: IEEE 802.3 §3 (802.3 TX).
        """

        status = self._tx._phtx_ethernet_802_3()

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL,
            msg="Handler with no kwargs must drop the packet (dst defaults to unspecified).",
        )
        self.assertEqual(
            self._if._packet_stats_tx.ethernet_802_3__src_unspec__fill,
            1,
            msg="Even when dropping, the unspecified src is still filled before the dst check.",
        )
