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
This module contains unit tests for the 'Ethernet8023RxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ethernet_802_3__rx.py

ver 3.0.9
"""

from typing import TYPE_CHECKING, Any, cast, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.runtime.packet_handler.packet_handler__ethernet_802_3__rx import Ethernet8023RxHandler
from pytcp.tests.lib.parameterized import parameterized_class

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


# Stack MAC addresses used by every test case in this module.
STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
STACK__MAC_MULTICAST = MacAddress("33:33:00:00:00:01")
STACK__MAC_BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")


# Ethernet 802.3 baseline wire frames used in parametrized cases.

# Ethernet 802.3 (14 bytes header + 0 payload, Length = 0x0000):
#   Bytes 0-5  : 02:00:00:00:00:07                -> dst=stack unicast MAC
#   Bytes 6-11 : 52:54:00:df:85:37                -> src
#   Bytes 12-13: 0x0000                           -> length (empty payload)
_FRAME_802_3__DST_UNICAST = b"\x02\x00\x00\x00\x00\x07" b"\x52\x54\x00\xdf\x85\x37" b"\x00\x00"

# Ethernet 802.3 frame addressed to the stack multicast MAC.
#   Bytes 0-5  : 33:33:00:00:00:01                -> dst=stack multicast MAC
#   Bytes 6-11 : 52:54:00:df:85:37                -> src
#   Bytes 12-13: 0x0000                           -> length (empty payload)
_FRAME_802_3__DST_MULTICAST = b"\x33\x33\x00\x00\x00\x01" b"\x52\x54\x00\xdf\x85\x37" b"\x00\x00"

# Ethernet 802.3 frame addressed to the broadcast MAC.
#   Bytes 0-5  : ff:ff:ff:ff:ff:ff                -> dst=broadcast MAC
#   Bytes 6-11 : 52:54:00:df:85:37                -> src
#   Bytes 12-13: 0x0000                           -> length (empty payload)
_FRAME_802_3__DST_BROADCAST = b"\xff\xff\xff\xff\xff\xff" b"\x52\x54\x00\xdf\x85\x37" b"\x00\x00"

# Ethernet 802.3 frame addressed to an unknown unicast MAC.
#   Bytes 0-5  : 02:00:00:99:99:99                -> dst=unknown unicast
#   Bytes 6-11 : 52:54:00:df:85:37                -> src
#   Bytes 12-13: 0x0000                           -> length (empty payload)
_FRAME_802_3__DST_UNKNOWN = b"\x02\x00\x00\x99\x99\x99" b"\x52\x54\x00\xdf\x85\x37" b"\x00\x00"

# Truncated Ethernet 802.3 frame (13 bytes — shorter than mandatory 14).
#   Bytes 0-12: 02:00:00:00:00:07 52:54:00:df:85:37 0x00 (truncated length)
_FRAME_802_3__TRUNCATED = b"\x02\x00\x00\x00\x00\x07" b"\x52\x54\x00\xdf\x85\x37" b"\x00"


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' interface.

    Carries the MAC-filter state and the upper-layer cross-call
    surface ('_phrx_arp' / '_phrx_ip4' / '_phrx_ip6') the 802.3 RX
    sub-handler reaches through 'self._if', recording any dispatch
    in 'self.dispatched'. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        """
        Initialize the stub interface with the bare attributes the
        sub-handler reads, plus a dispatch recorder.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._mac_multicast = [STACK__MAC_MULTICAST]
        self._mac_broadcast = STACK__MAC_BROADCAST

        self.dispatched: list[str] = []

    def _phrx_arp(self, packet_rx: PacketRx, /) -> None:
        """
        Record an ARP dispatch.
        """

        self.dispatched.append("arp")

    def _phrx_ip4(self, packet_rx: PacketRx, /) -> None:
        """
        Record an IPv4 dispatch.
        """

        self.dispatched.append("ip4")

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        Record an IPv6 dispatch.
        """

        self.dispatched.append("ip6")


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 frame addressed to stack unicast MAC (LLC parse fails on empty payload).",
            "_frame": _FRAME_802_3__DST_UNICAST,
            "_results": {
                "ethernet_802_3__pre_parse": 1,
                "ethernet_802_3__dst_unicast": 1,
                "ethernet_802_3__llc_failed_parse__drop": 1,
            },
        },
        {
            "_description": "Ethernet 802.3 frame addressed to stack multicast MAC (LLC parse fails on empty payload).",
            "_frame": _FRAME_802_3__DST_MULTICAST,
            "_results": {
                "ethernet_802_3__pre_parse": 1,
                "ethernet_802_3__dst_multicast": 1,
                "ethernet_802_3__llc_failed_parse__drop": 1,
            },
        },
        {
            "_description": "Ethernet 802.3 frame addressed to broadcast MAC (LLC parse fails on empty payload).",
            "_frame": _FRAME_802_3__DST_BROADCAST,
            "_results": {
                "ethernet_802_3__pre_parse": 1,
                "ethernet_802_3__dst_broadcast": 1,
                "ethernet_802_3__llc_failed_parse__drop": 1,
            },
        },
        {
            "_description": "Ethernet 802.3 frame addressed to an unknown MAC.",
            "_frame": _FRAME_802_3__DST_UNKNOWN,
            "_results": {
                "ethernet_802_3__pre_parse": 1,
                "ethernet_802_3__dst_unknown__drop": 1,
            },
        },
        {
            "_description": "Truncated Ethernet 802.3 frame fails the parser.",
            "_frame": _FRAME_802_3__TRUNCATED,
            "_results": {
                "ethernet_802_3__pre_parse": 1,
                "ethernet_802_3__failed_parse__drop": 1,
            },
        },
    ]
)
class TestPacketHandlerEthernet8023Rx(TestCase):
    """
    The 'PacketHandlerEthernet8023Rx._phrx_ethernet_802_3' behaviour tests.
    """

    _description: str
    _frame: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the 802.3 RX sub-handler over a stub interface and run
        the frame through it.
        """

        self._if = _StubInterface()
        self._rx = Ethernet8023RxHandler(interface=cast("PacketHandlerL2", self._if))
        self._rx._phrx_ethernet_802_3(PacketRx(self._frame))

    def test__stack__packet_handler__ethernet_802_3__rx__packet_stats_rx(self) -> None:
        """
        Ensure the handler updates the exact set of RX statistics the
        behavioral contract promises for this case.

        Reference: IEEE 802.3 §3 (802.3 RX dispatch).
        """

        expected = PacketStatsRx(**self._results)
        self.assertEqual(
            self._if._packet_stats_rx,
            expected,
            msg=f"Unexpected RX packet statistics for case: {self._description}",
        )


class TestPacketHandlerEthernet8023RxDispatch(TestCase):
    """
    The 'PacketHandlerEthernet8023Rx' dispatch-to-subhandler contract tests.
    """

    def test__stack__packet_handler__ethernet_802_3__rx__does_not_dispatch_arp_ip4_ip6(self) -> None:
        """
        Ensure the 802.3 handler never dispatches to the Ethernet II
        upper-protocol handlers (_phrx_arp / _phrx_ip4 / _phrx_ip6).
        802.3 frames are accepted into stats only; upper layers are
        routed by the plain Ethernet handler in the real code path.

        Reference: IEEE 802.3 §3 (802.3 RX dispatch).
        """

        iface = _StubInterface()
        rx = Ethernet8023RxHandler(interface=cast("PacketHandlerL2", iface))

        rx._phrx_ethernet_802_3(PacketRx(_FRAME_802_3__DST_UNICAST))

        self.assertEqual(
            iface.dispatched,
            [],
            msg="Ethernet8023RxHandler must not dispatch to any upper-layer _phrx_* method.",
        )
