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
Integration tests for the loopback test-harness affordances.

pytcp/tests/integration/loopback/test__loopback__harness.py

ver 3.0.10
"""

from unittest.mock import patch

from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.tests.lib.network_testcase import NetworkTestCase

# Bare version-nibble IPv4 / IPv6 headers — enough for the ring-drive
# dispatch; full RX acceptance semantics are covered by the P5 tests.
_IP4_FRAME = b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x00\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
_IP6_FRAME = b"\x60" + b"\x00" * 39


class TestLoopbackHarness(NetworkTestCase):
    """
    The loopback harness-affordance tests ('_register_loopback' /
    'drive_loopback').
    """

    def test__loopback__register_adds_loopback_interface(self) -> None:
        """
        Ensure '_register_loopback' installs a loopback interface into the
        stack registry so cross-interface lookups (local-address and
        connected-route synthesis) see it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lo = self._register_loopback()

        self.assertIs(
            stack.loopback_handler(),
            lo,
            msg="_register_loopback must register the loopback handler in stack.interfaces.",
        )
        self.assertIs(
            lo.interface_layer,
            InterfaceLayer.LOOPBACK,
            msg="The registered loopback interface must report the LOOPBACK layer.",
        )

    def test__loopback__drive_delivers_queued_ipv4_packet(self) -> None:
        """
        Ensure 'drive_loopback' synchronously drains an enqueued IPv4
        packet and delivers it into the IPv4 RX path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lo = self._register_loopback()

        with patch.object(lo, "_phrx_ip4") as phrx_ip4:
            lo.enqueue_loopback(PacketRx(_IP4_FRAME))
            delivered = self.drive_loopback(lo=lo)

        self.assertEqual(delivered, 1, msg="drive_loopback must deliver the one queued packet.")
        phrx_ip4.assert_called_once()

    def test__loopback__drive_delivers_queued_ipv6_packet(self) -> None:
        """
        Ensure 'drive_loopback' delivers an enqueued IPv6 packet into the
        IPv6 RX path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lo = self._register_loopback()

        with patch.object(lo, "_phrx_ip6") as phrx_ip6:
            lo.enqueue_loopback(PacketRx(_IP6_FRAME))
            delivered = self.drive_loopback(lo=lo)

        self.assertEqual(delivered, 1, msg="drive_loopback must deliver the one queued IPv6 packet.")
        phrx_ip6.assert_called_once()

    def test__loopback__drive_on_empty_ring_delivers_nothing(self) -> None:
        """
        Ensure 'drive_loopback' on an empty ring returns zero without
        blocking on the ring's poll timeout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lo = self._register_loopback()

        self.assertEqual(
            self.drive_loopback(lo=lo),
            0,
            msg="drive_loopback on an empty ring must deliver nothing.",
        )
