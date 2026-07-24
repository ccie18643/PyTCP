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
This module contains unit tests for the 'PacketHandlerLoopback' handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__loopback.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.runtime.loopback_ring import LoopbackRing
from pytcp.runtime.packet_handler import PacketHandlerLoopback

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL

# Minimal version-nibble-only IP headers for the RX-dispatch tests.
_IP4_FRAME = b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x00\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
_IP6_FRAME = b"\x60" + b"\x00" * 39


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


def _build_loopback_handler() -> PacketHandlerLoopback:
    """
    Build a 'PacketHandlerLoopback' at the canonical loopback MTU.
    """

    return PacketHandlerLoopback(interface_mtu=stack.INTERFACE__LOOPBACK__MTU)


class TestPacketHandlerLoopbackConstruction(TestCase):
    """
    The 'PacketHandlerLoopback' construction / self-addressing tests.
    """

    def test__loopback__interface_layer_is_loopback(self) -> None:
        """
        Ensure the loopback handler reports the LOOPBACK interface layer so
        the Link API surfaces the LOOPBACK flag and the TX 'match' arms
        never mistake it for L2 / L3.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_loopback_handler()

        self.assertIs(
            handler.interface_layer,
            InterfaceLayer.LOOPBACK,
            msg="PacketHandlerLoopback must report the LOOPBACK interface layer.",
        )

    def test__loopback__has_no_mac(self) -> None:
        """
        Ensure the loopback handler has no unicast MAC — the 'lo' device
        has no Ethernet layer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_loopback_handler()

        self.assertIsNone(
            handler.mac_unicast,
            msg="PacketHandlerLoopback must have no unicast MAC (no Ethernet layer).",
        )

    def test__loopback__mtu_is_65535(self) -> None:
        """
        Ensure the loopback handler carries the canonical loopback MTU
        (the uint16 wire ceiling).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_loopback_handler()

        self.assertEqual(
            handler.interface_mtu,
            stack.INTERFACE__LOOPBACK__MTU,
            msg="PacketHandlerLoopback must carry INTERFACE__LOOPBACK__MTU.",
        )
        self.assertEqual(
            stack.INTERFACE__LOOPBACK__MTU,
            65535,
            msg="INTERFACE__LOOPBACK__MTU must be the uint16 wire ceiling (65535).",
        )

    def test__loopback__owns_ipv4_loopback_address(self) -> None:
        """
        Ensure the loopback handler self-assigns 127.0.0.1 so local IPv4
        delivery has a receiving address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_loopback_handler()

        self.assertEqual(
            handler.ip4_unicast,
            [Ip4Address("127.0.0.1")],
            msg="PacketHandlerLoopback must own the 127.0.0.1 loopback address.",
        )

    def test__loopback__owns_ipv6_loopback_address(self) -> None:
        """
        Ensure the loopback handler self-assigns ::1 so local IPv6
        delivery has a receiving address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_loopback_handler()

        self.assertEqual(
            handler.ip6_unicast,
            [Ip6Address("::1")],
            msg="PacketHandlerLoopback must own the ::1 loopback address.",
        )

    def test__loopback__owns_a_loopback_ring(self) -> None:
        """
        Ensure the loopback handler is constructed with its own
        'LoopbackRing' — the in-process delivery queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _build_loopback_handler()
        self.addCleanup(handler._lo_ring.close)

        self.assertIsInstance(
            handler._lo_ring,
            LoopbackRing,
            msg="PacketHandlerLoopback must own a LoopbackRing.",
        )


class TestPacketHandlerLoopbackDelivery(TestCase):
    """
    The 'PacketHandlerLoopback' RX-dispatch tests — a queued packet is
    delivered into the correct IP-version RX path.
    """

    @override
    def setUp(self) -> None:
        """
        Build a loopback handler and register its ring cleanup.
        """

        self._handler = _build_loopback_handler()
        self.addCleanup(self._handler._lo_ring.close)

    def test__loopback__delivers_ipv4_to_phrx_ip4(self) -> None:
        """
        Ensure an IPv4 packet drained from the ring is delivered to the
        IPv4 RX path and not the IPv6 one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        packet_rx = PacketRx(_IP4_FRAME)
        with patch.object(self._handler, "_phrx_ip4") as phrx_ip4, patch.object(self._handler, "_phrx_ip6") as phrx_ip6:
            self._handler._deliver_loopback(packet_rx)

        phrx_ip4.assert_called_once_with(packet_rx)
        phrx_ip6.assert_not_called()

    def test__loopback__delivers_ipv6_to_phrx_ip6(self) -> None:
        """
        Ensure an IPv6 packet drained from the ring is delivered to the
        IPv6 RX path and not the IPv4 one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        packet_rx = PacketRx(_IP6_FRAME)
        with patch.object(self._handler, "_phrx_ip4") as phrx_ip4, patch.object(self._handler, "_phrx_ip6") as phrx_ip6:
            self._handler._deliver_loopback(packet_rx)

        phrx_ip6.assert_called_once_with(packet_rx)
        phrx_ip4.assert_not_called()

    def test__loopback__subsystem_loop_drains_and_delivers(self) -> None:
        """
        Ensure one iteration of the subsystem loop drains a queued packet
        and delivers it to the version-appropriate RX path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        packet_rx = PacketRx(_IP4_FRAME)
        self._handler._lo_ring.enqueue(packet_rx)

        with patch.object(self._handler, "_phrx_ip4") as phrx_ip4:
            self._handler._subsystem_loop()

        phrx_ip4.assert_called_once_with(packet_rx)
