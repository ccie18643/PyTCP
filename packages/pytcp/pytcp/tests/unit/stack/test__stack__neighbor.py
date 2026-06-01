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
The 'pytcp.stack.neighbor' control-plane API unit tests — the
'ip neighbor' / RTM_NEWNEIGH equivalent backed by the per-interface
ARP / ND caches.

pytcp/tests/unit/stack/test__stack__neighbor.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import cast, override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp import stack
from pytcp.lib.neighbor import NudState
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import PacketHandlerL2
from pytcp.runtime.socket import AddressFamily
from pytcp.stack.neighbor import NeighborApi, NeighborSnapshot

_ARP_IP = Ip4Address("10.0.1.50")
_ARP_MAC = MacAddress("02:00:00:00:00:50")
_ND_IP = Ip6Address("2001:db8:0:1::50")
_ND_MAC = MacAddress("02:00:00:00:00:60")


class TestStackNeighborApi(TestCase):
    """
    The 'stack.neighbor' control-plane API tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a Neighbor API bound to a stub interface carrying a real
        ARP cache and ND cache; silence the subsystem / NUD log lines.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(patch("pytcp.lib.neighbor.log"))
        self.enterContext(patch("pytcp.stack.neighbor.log"))
        self._arp_cache = ArpCache()
        self._nd_cache = NdCache()
        self._handler = cast(
            PacketHandlerL2,
            SimpleNamespace(_arp_cache=self._arp_cache, _nd_cache=self._nd_cache),
        )
        self._api = NeighborApi(packet_handler=self._handler)

    def test__neighbor__add_arp_then_list(self) -> None:
        """
        Ensure a static ARP entry added through the Neighbor API appears
        in 'list_neighbors' as a PERMANENT neighbour with the configured MAC.

        Reference: RFC 826 (ARP — static address resolution mapping).
        """

        self._api.add(ip=_ARP_IP, mac=_ARP_MAC)

        snaps = self._api.list_neighbors(family=AddressFamily.INET4)
        self.assertEqual(
            snaps,
            (NeighborSnapshot(address=_ARP_IP, mac_address=_ARP_MAC, state=NudState.PERMANENT),),
            msg="add must install one PERMANENT ARP neighbour visible via list_neighbors.",
        )

    def test__neighbor__add_nd_then_list(self) -> None:
        """
        Ensure a static ND entry added through the Neighbor API appears
        in 'list_neighbors' as a PERMANENT neighbour with the configured MAC.

        Reference: RFC 4861 §7.2 (Neighbor Cache — static entry).
        """

        self._api.add(ip=_ND_IP, mac=_ND_MAC)

        snaps = self._api.list_neighbors(family=AddressFamily.INET6)
        self.assertEqual(
            snaps,
            (NeighborSnapshot(address=_ND_IP, mac_address=_ND_MAC, state=NudState.PERMANENT),),
            msg="add must install one PERMANENT ND neighbour visible via list_neighbors.",
        )

    def test__neighbor__list_is_copy_by_value(self) -> None:
        """
        Ensure 'list_neighbors' returns a point-in-time snapshot — a later
        mutation does not change a tuple already returned to the caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._api.add(ip=_ARP_IP, mac=_ARP_MAC)
        before = self._api.list_neighbors(family=AddressFamily.INET4)

        self._api.add(ip=Ip4Address("10.0.1.51"), mac=MacAddress("02:00:00:00:00:51"))

        self.assertEqual(
            len(before),
            1,
            msg="A snapshot returned before a second add must not observe the later entry.",
        )

    def test__neighbor__remove_arp(self) -> None:
        """
        Ensure 'remove' deletes the matching ARP neighbour, keyed off the
        IPv4 address type.

        Reference: RFC 826 (ARP — neighbour mapping removal).
        """

        self._api.add(ip=_ARP_IP, mac=_ARP_MAC)

        self._api.remove(ip=_ARP_IP)

        self.assertEqual(
            self._api.list_neighbors(family=AddressFamily.INET4),
            (),
            msg="remove(ip=<IPv4>) must delete the matching ARP neighbour.",
        )

    def test__neighbor__remove_nd(self) -> None:
        """
        Ensure 'remove' deletes the matching ND neighbour, keyed off the
        IPv6 address type.

        Reference: RFC 4861 §7.2 (Neighbor Cache — entry removal).
        """

        self._api.add(ip=_ND_IP, mac=_ND_MAC)

        self._api.remove(ip=_ND_IP)

        self.assertEqual(
            self._api.list_neighbors(family=AddressFamily.INET6),
            (),
            msg="remove(ip=<IPv6>) must delete the matching ND neighbour.",
        )

    def test__neighbor__flush_ipv4_clears_only_arp(self) -> None:
        """
        Ensure 'flush(family=INET4)' clears the ARP cache and leaves the
        ND cache untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._api.add(ip=_ARP_IP, mac=_ARP_MAC)
        self._api.add(ip=_ND_IP, mac=_ND_MAC)

        self._api.flush(family=AddressFamily.INET4)

        self.assertEqual(
            self._api.list_neighbors(family=AddressFamily.INET4),
            (),
            msg="flush(INET4) must clear the ARP cache.",
        )
        self.assertEqual(
            len(self._api.list_neighbors(family=AddressFamily.INET6)),
            1,
            msg="flush(INET4) must leave the ND cache untouched.",
        )

    def test__neighbor__flush_ipv6_clears_only_nd(self) -> None:
        """
        Ensure 'flush(family=INET6)' clears the ND cache and leaves the
        ARP cache untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._api.add(ip=_ARP_IP, mac=_ARP_MAC)
        self._api.add(ip=_ND_IP, mac=_ND_MAC)

        self._api.flush(family=AddressFamily.INET6)

        self.assertEqual(
            self._api.list_neighbors(family=AddressFamily.INET6),
            (),
            msg="flush(INET6) must clear the ND cache.",
        )
        self.assertEqual(
            len(self._api.list_neighbors(family=AddressFamily.INET4)),
            1,
            msg="flush(INET6) must leave the ARP cache untouched.",
        )

    def test__neighbor__interface_selector_binds_to_ifindex(self) -> None:
        """
        Ensure 'interface(ifindex)' returns an API bound to that
        interface's caches — the 'ip neighbor ... dev <ifX>' equivalent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        table[1] = self._handler
        self.enterContext(patch.object(stack, "interfaces", table))

        NeighborApi().interface(1).add(ip=_ARP_IP, mac=_ARP_MAC)

        self.assertEqual(
            self._api.list_neighbors(family=AddressFamily.INET4),
            (NeighborSnapshot(address=_ARP_IP, mac_address=_ARP_MAC, state=NudState.PERMANENT),),
            msg="interface(ifindex) must bind mutations to that interface's ARP cache.",
        )

    def test__neighbor__unbound_tool_raises_with_sole_interface(self) -> None:
        """
        Ensure a bare mutation on the unbound Neighbor tool raises even
        when exactly one interface is registered, leaving its cache
        untouched — there is no sole-interface default; the caller must
        select a device, like Linux 'ip neighbor ... dev <ifX>'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        table[1] = self._handler
        self.enterContext(patch.object(stack, "interfaces", table))

        with self.assertRaises(RuntimeError):
            NeighborApi().add(ip=_ARP_IP, mac=_ARP_MAC)

        self.assertEqual(
            self._api.list_neighbors(family=AddressFamily.INET4),
            (),
            msg="A bare mutation on the unbound tool must not touch any interface's cache.",
        )
