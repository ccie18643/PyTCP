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
This module contains tests for the AF_PACKET socket registry
('PacketSocketTable') — the fan-out lookup that the Ethernet RX tap
uses to deliver a copy of each matching frame to every bound packet
socket.

pytcp/tests/unit/runtime/socket/test__runtime__socket__packet__socket_table.py

ver 3.0.8
"""

from typing import cast, override
from unittest import TestCase

from net_proto.lib.enums import EtherType
from pytcp.runtime.socket import ETH_P_ALL, ETH_P_ARP, ETH_P_IP
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.packet__socket_table import PacketSocketTable


class _StubPacketSocket:
    """
    Minimal stand-in exposing only the 'ifindex' / 'ethertype'
    attributes the table reads, so the registry can be tested
    without constructing a real 'PacketSocket' (and its eventfd /
    self-registration side effects).
    """

    def __init__(self, *, ifindex: int, ethertype: EtherType | int) -> None:
        self.ifindex = ifindex
        self.ethertype = ethertype


def _sock(*, ifindex: int = 0, ethertype: EtherType | int = ETH_P_ALL) -> PacketSocket:
    """
    Build a stub packet socket cast to the real type for the table.
    """

    return cast(PacketSocket, _StubPacketSocket(ifindex=ifindex, ethertype=ethertype))


class TestPacketSocketTable(TestCase):
    """
    The AF_PACKET 'PacketSocketTable' registry tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh empty registry per test.
        """

        self._table = PacketSocketTable()

    def test__packet_socket_table__empty_is_falsy(self) -> None:
        """
        Ensure a freshly-built registry is empty and falsy so the RX
        tap's cheap 'is anything bound?' guard short-circuits.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(bool(self._table), msg="A fresh PacketSocketTable must be falsy (no sockets bound).")
        self.assertEqual(len(self._table), 0, msg="A fresh PacketSocketTable must have length 0.")

    def test__packet_socket_table__register_then_len_and_truthy(self) -> None:
        """
        Ensure registering a socket makes the registry non-empty and
        truthy.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.register(_sock())

        self.assertTrue(bool(self._table), msg="A registry with one socket must be truthy.")
        self.assertEqual(len(self._table), 1, msg="Registering one socket must give length 1.")

    def test__packet_socket_table__unregister_removes(self) -> None:
        """
        Ensure unregistering a previously-registered socket drops it
        and a second unregister of the same socket is a silent no-op.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _sock()
        self._table.register(sock)

        self._table.unregister(sock)
        self._table.unregister(sock)

        self.assertEqual(len(self._table), 0, msg="Unregister must remove the socket; a repeat is a no-op.")

    def test__packet_socket_table__matching_eth_p_all_wildcard(self) -> None:
        """
        Ensure a socket bound with the ETH_P_ALL wildcard matches a
        frame of any ethertype.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _sock(ethertype=ETH_P_ALL)
        self._table.register(sock)

        self.assertEqual(
            self._table.matching(ifindex=1, ethertype=EtherType.IP4),
            [sock],
            msg="An ETH_P_ALL socket must match a frame of any ethertype.",
        )

    def test__packet_socket_table__matching_exact_ethertype_only(self) -> None:
        """
        Ensure a socket bound to a specific ethertype matches only that
        ethertype and is skipped for others.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        arp_sock = _sock(ethertype=ETH_P_ARP)
        ip_sock = _sock(ethertype=ETH_P_IP)
        self._table.register(arp_sock)
        self._table.register(ip_sock)

        self.assertEqual(
            self._table.matching(ifindex=1, ethertype=EtherType.ARP),
            [arp_sock],
            msg="An ethertype-filtered socket must match only its own ethertype.",
        )

    def test__packet_socket_table__matching_ifindex_scope(self) -> None:
        """
        Ensure ifindex scoping: an unbound socket (ifindex 0) matches
        every interface, while a socket bound to a specific ifindex
        matches only frames arriving on that interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        any_if = _sock(ifindex=0)
        if1 = _sock(ifindex=1)
        if2 = _sock(ifindex=2)
        self._table.register(any_if)
        self._table.register(if1)
        self._table.register(if2)

        self.assertEqual(
            self._table.matching(ifindex=1, ethertype=EtherType.ARP),
            [any_if, if1],
            msg="ifindex 0 matches any interface; a specific ifindex matches only its own.",
        )

    def test__packet_socket_table__snapshot_is_detached_copy(self) -> None:
        """
        Ensure 'snapshot' returns a detached list — mutating the
        registry afterward does not change a snapshot already taken.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.register(_sock())
        snap = self._table.snapshot()

        self._table.register(_sock())

        self.assertEqual(len(snap), 1, msg="A snapshot taken before a second register must not observe it.")

    def test__packet_socket_table__clear_empties(self) -> None:
        """
        Ensure 'clear' removes every registered socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.register(_sock())
        self._table.register(_sock())

        self._table.clear()

        self.assertEqual(len(self._table), 0, msg="clear() must drop every registered socket.")
