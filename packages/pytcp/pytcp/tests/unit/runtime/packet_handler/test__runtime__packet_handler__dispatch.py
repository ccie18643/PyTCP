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
This module contains unit tests for the 'DispatchRegistry' RX dispatch table.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__dispatch.py

ver 3.0.8
"""

from unittest import TestCase
from unittest.mock import MagicMock

from net_proto import EtherType, IpProto
from net_proto.lib.packet_rx import PacketRx
from pytcp.runtime.packet_handler.dispatch import DispatchRegistry


class TestDispatchRegistry(TestCase):
    """
    The 'DispatchRegistry' codepoint-keyed RX dispatch table tests.
    """

    def test__runtime__packet_handler__dispatch__get_miss_returns_none(self) -> None:
        """
        Ensure a lookup for an unregistered codepoint returns None so
        the demux site can treat it as "this interface does not handle
        that codepoint".

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        registry: DispatchRegistry[EtherType] = DispatchRegistry()

        self.assertIsNone(
            registry.get(EtherType.ARP),
            msg="An unregistered codepoint must look up to None.",
        )

    def test__runtime__packet_handler__dispatch__get_returns_registered_handler(self) -> None:
        """
        Ensure a registered codepoint looks up to exactly the handler
        it was registered with.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = MagicMock()
        registry: DispatchRegistry[EtherType] = DispatchRegistry()
        registry.register(EtherType.IP4, handler)

        self.assertIs(
            registry.get(EtherType.IP4),
            handler,
            msg="A registered codepoint must look up to its handler.",
        )

    def test__runtime__packet_handler__dispatch__distinct_codepoints_map_distinctly(self) -> None:
        """
        Ensure distinct codepoints route to their own handlers and a
        codepoint registered on one registry does not leak into another.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        icmp4_handler = MagicMock()
        udp_handler = MagicMock()
        registry: DispatchRegistry[IpProto] = DispatchRegistry()
        registry.register(IpProto.ICMP4, icmp4_handler)
        registry.register(IpProto.UDP, udp_handler)

        self.assertIs(registry.get(IpProto.ICMP4), icmp4_handler)
        self.assertIs(registry.get(IpProto.UDP), udp_handler)
        self.assertIsNone(
            registry.get(IpProto.TCP),
            msg="A codepoint registered nowhere must look up to None.",
        )

    def test__runtime__packet_handler__dispatch__registered_handler_is_invoked_with_packet(self) -> None:
        """
        Ensure invoking the looked-up handler forwards the PacketRx
        unchanged — the registry adds no argument transformation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = MagicMock()
        registry: DispatchRegistry[IpProto] = DispatchRegistry()
        registry.register(IpProto.TCP, handler)

        packet_rx = PacketRx(b"\x00" * 20)
        looked_up = registry.get(IpProto.TCP)
        assert looked_up is not None
        looked_up(packet_rx)

        handler.assert_called_once_with(packet_rx)

    def test__runtime__packet_handler__dispatch__reregister_overwrites(self) -> None:
        """
        Ensure re-registering a codepoint replaces the prior handler so
        the registry holds a single handler per codepoint.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = MagicMock()
        second = MagicMock()
        registry: DispatchRegistry[EtherType] = DispatchRegistry()
        registry.register(EtherType.IP6, first)
        registry.register(EtherType.IP6, second)

        self.assertIs(
            registry.get(EtherType.IP6),
            second,
            msg="Re-registering a codepoint must replace the prior handler.",
        )
