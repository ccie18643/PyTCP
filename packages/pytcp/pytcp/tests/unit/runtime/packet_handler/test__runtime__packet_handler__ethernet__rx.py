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
This module contains unit tests for the 'EthernetRxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ethernet__rx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import MacAddress
from net_proto import EtherType
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.runtime.packet_handler.dispatch import DispatchRegistry
from pytcp.runtime.packet_handler.packet_handler__ethernet__rx import (
    EthernetRxHandler,
)

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
STACK__MAC_MULTICAST = MacAddress("33:33:00:00:00:01")
STACK__MAC_BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")


# Ethernet II baseline wire frames used in parametrized cases. All
# frames here are header-only (14 bytes) and payload-less; the handler
# only inspects the parsed Ethernet header.

# Ethernet II frame with ARP payload, destined to the stack unicast MAC.
#   Bytes 0-5  : 02:00:00:00:00:07 -> dst=stack unicast
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x0806            -> EtherType.ARP
_FRAME_ETH__ARP_UNICAST = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x08\x06"

# Ethernet II frame with IPv4 payload, destined to the stack unicast MAC.
#   Bytes 0-5  : 02:00:00:00:00:07 -> dst=stack unicast
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x0800            -> EtherType.IP4
_FRAME_ETH__IP4_UNICAST = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x08\x00"

# Ethernet II frame with IPv6 payload, destined to the stack unicast MAC.
#   Bytes 0-5  : 02:00:00:00:00:07 -> dst=stack unicast
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x86dd            -> EtherType.IP6
_FRAME_ETH__IP6_UNICAST = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x86\xdd"

# Ethernet II frame with IPv4 payload, destined to the stack multicast MAC.
#   Bytes 0-5  : 33:33:00:00:00:01 -> dst=stack multicast
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x0800            -> EtherType.IP4
_FRAME_ETH__IP4_MULTICAST = b"\x33\x33\x00\x00\x00\x01\x52\x54\x00\xdf\x85\x37\x08\x00"

# Ethernet II frame with IPv4 payload, destined to the broadcast MAC.
#   Bytes 0-5  : ff:ff:ff:ff:ff:ff -> dst=broadcast
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x0800            -> EtherType.IP4
_FRAME_ETH__IP4_BROADCAST = b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x08\x00"

# Ethernet II frame addressed to an unknown unicast MAC.
#   Bytes 0-5  : 02:00:00:99:99:99 -> dst=unknown unicast (not in our table)
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x0800            -> EtherType.IP4
_FRAME_ETH__DST_UNKNOWN = b"\x02\x00\x00\x99\x99\x99\x52\x54\x00\xdf\x85\x37\x08\x00"

# Ethernet II frame carrying an unsupported EtherType.
#   Bytes 0-5  : 02:00:00:00:00:07 -> dst=stack unicast
#   Bytes 6-11 : 52:54:00:df:85:37 -> src
#   Bytes 12-13: 0x88cc            -> EtherType LLDP (not supported by this stack)
_FRAME_ETH__UNSUPPORTED_PROTO = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x88\xcc"

# Truncated Ethernet II frame (13 bytes — shorter than mandatory 14).
_FRAME_ETH__TRUNCATED = b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x08"


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' interface.

    Carries the RX-stat counters, the stack MAC addresses, the IPv4 /
    IPv6 support flags, and the upper-layer dispatch spies ('_phrx_arp'
    / '_phrx_ip4' / '_phrx_ip6') the Ethernet RX demux hub reaches
    through 'self._if', recording each call for assertions. A
    purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which autospec
    walks) cannot evaluate at runtime.
    """

    def __init__(self, *, ip4_support: bool = True, ip6_support: bool = True) -> None:
        """
        Initialize the stub interface with attributes and spies for the
        upper-layer dispatch methods.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._mac_multicast = [STACK__MAC_MULTICAST]
        self._mac_broadcast = STACK__MAC_BROADCAST
        self._ip4_support = ip4_support
        self._ip6_support = ip6_support

        self.dispatched: list[str] = []

        # Build the link-layer dispatch registry the way the real
        # 'PacketHandlerL2' does: support-gated, with the ARP / IPv4 /
        # IPv6 spies as the registered handlers.
        self._ethertype_registry: DispatchRegistry[EtherType] = DispatchRegistry()
        if ip4_support:
            self._ethertype_registry.register(EtherType.ARP, self._phrx_arp)
            self._ethertype_registry.register(EtherType.IP4, self._phrx_ip4)
        if ip6_support:
            self._ethertype_registry.register(EtherType.IP6, self._phrx_ip6)

    def _phrx_arp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("arp")

    def _phrx_ip4(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("ip4")

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("ip6")


def _make_ethernet_rx(
    *,
    ip4_support: bool = True,
    ip6_support: bool = True,
) -> tuple[EthernetRxHandler, _StubInterface]:
    """
    Build an 'EthernetRxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface(ip4_support=ip4_support, ip6_support=ip6_support)
    return (
        EthernetRxHandler(interface=cast("PacketHandlerL2", interface)),
        interface,
    )


@parameterized_class(
    [
        {
            "_description": "ARP frame to stack unicast dispatches to _phrx_arp.",
            "_frame": _FRAME_ETH__ARP_UNICAST,
            "_expected_dispatch": ["arp"],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_unicast": 1,
            },
        },
        {
            "_description": "IPv4 frame to stack unicast dispatches to _phrx_ip4.",
            "_frame": _FRAME_ETH__IP4_UNICAST,
            "_expected_dispatch": ["ip4"],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_unicast": 1,
            },
        },
        {
            "_description": "IPv6 frame to stack unicast dispatches to _phrx_ip6.",
            "_frame": _FRAME_ETH__IP6_UNICAST,
            "_expected_dispatch": ["ip6"],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_unicast": 1,
            },
        },
        {
            "_description": "IPv4 frame to stack multicast MAC dispatches to _phrx_ip4 with multicast stat.",
            "_frame": _FRAME_ETH__IP4_MULTICAST,
            "_expected_dispatch": ["ip4"],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_multicast": 1,
            },
        },
        {
            "_description": "IPv4 frame to broadcast MAC dispatches to _phrx_ip4 with broadcast stat.",
            "_frame": _FRAME_ETH__IP4_BROADCAST,
            "_expected_dispatch": ["ip4"],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_broadcast": 1,
            },
        },
        {
            "_description": "Frame to unknown unicast is dropped; no dispatch.",
            "_frame": _FRAME_ETH__DST_UNKNOWN,
            "_expected_dispatch": [],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_unknown__drop": 1,
            },
        },
        {
            "_description": "Unsupported EtherType is dropped after passing MAC filter.",
            "_frame": _FRAME_ETH__UNSUPPORTED_PROTO,
            "_expected_dispatch": [],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__dst_unicast": 1,
                "ethernet__no_proto_support__drop": 1,
            },
        },
        {
            "_description": "Truncated frame fails the Ethernet parser.",
            "_frame": _FRAME_ETH__TRUNCATED,
            "_expected_dispatch": [],
            "_results": {
                "ethernet__pre_parse": 1,
                "ethernet__failed_parse__drop": 1,
            },
        },
    ]
)
class TestPacketHandlerEthernetRx(TestCase):
    """
    The 'EthernetRxHandler._phrx_ethernet' behaviour tests.
    """

    _description: str
    _frame: bytes
    _expected_dispatch: list[str]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the stub handler and run the frame through the mixin method.
        """

        self._handler, self._if = _make_ethernet_rx()
        self._handler._phrx_ethernet(PacketRx(self._frame))

    def test__stack__packet_handler__ethernet__rx__dispatch(self) -> None:
        """
        Ensure the handler dispatches to the correct upper-layer
        _phrx_* method for the parsed EtherType (or none, when the
        packet is dropped upstream of the dispatch switch).

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        self.assertEqual(
            self._if.dispatched,
            self._expected_dispatch,
            msg=f"Unexpected dispatch chain for case: {self._description}",
        )

    def test__stack__packet_handler__ethernet__rx__packet_stats_rx(self) -> None:
        """
        Ensure the handler updates the exact set of RX statistics the
        behavioral contract promises for this case.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        expected = PacketStatsRx(**self._results)
        self.assertEqual(
            self._if._packet_stats_rx,
            expected,
            msg=f"Unexpected RX packet statistics for case: {self._description}",
        )


class TestPacketHandlerEthernetRxProtocolGating(TestCase):
    """
    The 'EthernetRxHandler' IPv4/IPv6 support-flag gating tests.
    """

    def test__stack__packet_handler__ethernet__rx__ip4_disabled_drops_ip4(self) -> None:
        """
        Ensure an IPv4 frame is dropped when '_ip4_support' is False,
        even though the MAC filter passed. The switch has explicit
        guards for each support flag.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        handler, iface = _make_ethernet_rx(ip4_support=False)
        handler._phrx_ethernet(PacketRx(_FRAME_ETH__IP4_UNICAST))

        self.assertEqual(
            iface.dispatched,
            [],
            msg="IPv4 frame must not dispatch when _ip4_support is False.",
        )
        self.assertEqual(
            iface._packet_stats_rx.ethernet__no_proto_support__drop,
            1,
            msg="ethernet__no_proto_support__drop must be incremented when IPv4 support is disabled.",
        )

    def test__stack__packet_handler__ethernet__rx__ip6_disabled_drops_ip6(self) -> None:
        """
        Ensure an IPv6 frame is dropped when '_ip6_support' is False.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        handler, iface = _make_ethernet_rx(ip6_support=False)
        handler._phrx_ethernet(PacketRx(_FRAME_ETH__IP6_UNICAST))

        self.assertEqual(
            iface.dispatched,
            [],
            msg="IPv6 frame must not dispatch when _ip6_support is False.",
        )
        self.assertEqual(
            iface._packet_stats_rx.ethernet__no_proto_support__drop,
            1,
            msg="ethernet__no_proto_support__drop must be incremented when IPv6 support is disabled.",
        )

    def test__stack__packet_handler__ethernet__rx__ip4_disabled_drops_arp(self) -> None:
        """
        Ensure ARP dispatch is gated on '_ip4_support' — ARP is
        meaningless in an IPv6-only stack and the handler drops it.

        Reference: RFC 894 (Ethernet II RX dispatch).
        """

        handler, iface = _make_ethernet_rx(ip4_support=False)
        handler._phrx_ethernet(PacketRx(_FRAME_ETH__ARP_UNICAST))

        self.assertEqual(
            iface.dispatched,
            [],
            msg="ARP frame must not dispatch when _ip4_support is False.",
        )
        self.assertEqual(
            iface._packet_stats_rx.ethernet__no_proto_support__drop,
            1,
            msg="ethernet__no_proto_support__drop must be incremented when ARP is dropped.",
        )
