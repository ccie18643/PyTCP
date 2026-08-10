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
This module contains tests for the AF_PACKET link-layer address value
type ('SockAddrLl'), the 'PacketType' enum, and the 'ETH_P_*' /
'PACKET_*' module-level constants.

pytcp/tests/unit/runtime/socket/test__runtime__socket__sockaddr_ll.py

ver 3.0.10
"""

import dataclasses
from unittest import TestCase

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from pytcp.runtime.socket import (
    ETH_P_ALL,
    ETH_P_ARP,
    ETH_P_IP,
    ETH_P_IPV6,
    PACKET_BROADCAST,
    PACKET_HOST,
    PACKET_MULTICAST,
    PACKET_OTHERHOST,
    PACKET_OUTGOING,
    PacketType,
)
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


class TestEthProtocolConstants(TestCase):
    """
    The 'ETH_P_*' link-layer protocol constant tests.
    """

    def test__socket__eth_p_all_is_three(self) -> None:
        """
        Ensure 'ETH_P_ALL' equals 0x0003 — the Linux <linux/if_ether.h>
        capture-all pseudo-ethertype and the stdlib 'socket.ETH_P_ALL'
        value. It is a plain int sentinel, not an 'EtherType' member,
        because 0x0003 is not a real wire ethertype.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            ETH_P_ALL,
            0x0003,
            msg="ETH_P_ALL must equal 0x0003 per <linux/if_ether.h>.",
        )
        self.assertNotIsInstance(
            ETH_P_ALL,
            EtherType,
            msg="ETH_P_ALL must be a plain int sentinel, not an EtherType member.",
        )

    def test__socket__eth_p_aliases_map_to_ethertype(self) -> None:
        """
        Ensure the 'ETH_P_IP', 'ETH_P_ARP', and 'ETH_P_IPV6' Linux-name
        aliases resolve to the matching 'EtherType' wire-codepoint
        members so the AF_PACKET protocol filter shares one ethertype
        namespace with the parser layer.

        Reference: RFC 894 (IPv4 over Ethernet ethertype 0x0800).
        Reference: RFC 826 (ARP ethertype 0x0806).
        Reference: RFC 2464 (IPv6 over Ethernet ethertype 0x86DD).
        """

        self.assertIs(
            ETH_P_IP,
            EtherType.IP4,
            msg="ETH_P_IP alias must resolve to EtherType.IP4 (0x0800).",
        )
        self.assertIs(
            ETH_P_ARP,
            EtherType.ARP,
            msg="ETH_P_ARP alias must resolve to EtherType.ARP (0x0806).",
        )
        self.assertIs(
            ETH_P_IPV6,
            EtherType.IP6,
            msg="ETH_P_IPV6 alias must resolve to EtherType.IP6 (0x86DD).",
        )


class TestPacketType(TestCase):
    """
    The 'PacketType' (sll_pkttype) enum tests.
    """

    def test__socket__packet_type_members(self) -> None:
        """
        Ensure the 'PacketType' enum carries the five Linux
        <linux/if_packet.h> sll_pkttype values with their canonical
        integer numbers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            (
                int(PacketType.PACKET_HOST),
                int(PacketType.PACKET_BROADCAST),
                int(PacketType.PACKET_MULTICAST),
                int(PacketType.PACKET_OTHERHOST),
                int(PacketType.PACKET_OUTGOING),
            ),
            (0, 1, 2, 3, 4),
            msg="PacketType members must carry the canonical Linux sll_pkttype numbers.",
        )

    def test__socket__packet_type_aliases(self) -> None:
        """
        Ensure the 'PACKET_*' module-level aliases point at the matching
        'PacketType' members so stdlib-style bare constants resolve.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(PACKET_HOST, PacketType.PACKET_HOST, msg="PACKET_HOST alias must resolve to the enum member.")
        self.assertIs(
            PACKET_BROADCAST,
            PacketType.PACKET_BROADCAST,
            msg="PACKET_BROADCAST alias must resolve to the enum member.",
        )
        self.assertIs(
            PACKET_MULTICAST,
            PacketType.PACKET_MULTICAST,
            msg="PACKET_MULTICAST alias must resolve to the enum member.",
        )
        self.assertIs(
            PACKET_OTHERHOST,
            PacketType.PACKET_OTHERHOST,
            msg="PACKET_OTHERHOST alias must resolve to the enum member.",
        )
        self.assertIs(
            PACKET_OUTGOING,
            PacketType.PACKET_OUTGOING,
            msg="PACKET_OUTGOING alias must resolve to the enum member.",
        )


class TestSockAddrLl(TestCase):
    """
    The 'SockAddrLl' link-layer address value type tests.
    """

    def test__socket__sockaddr_ll_defaults(self) -> None:
        """
        Ensure a 'SockAddrLl' built with no arguments defaults to the
        unbound capture-all shape: ifindex 0 (all interfaces), ethertype
        ETH_P_ALL, pkttype PACKET_HOST, and the unspecified MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        addr = SockAddrLl()

        self.assertEqual(
            (addr.ifindex, addr.ethertype, addr.pkttype, addr.mac),
            (0, ETH_P_ALL, PacketType.PACKET_HOST, MacAddress()),
            msg="SockAddrLl() must default to the unbound capture-all link-layer address.",
        )

    def test__socket__sockaddr_ll_stores_fields(self) -> None:
        """
        Ensure a 'SockAddrLl' preserves every keyword-supplied field
        verbatim through its read surface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mac = MacAddress("02:00:00:00:00:07")
        addr = SockAddrLl(
            ifindex=7,
            ethertype=ETH_P_ARP,
            pkttype=PacketType.PACKET_BROADCAST,
            mac=mac,
        )

        self.assertEqual(
            (addr.ifindex, addr.ethertype, addr.pkttype, addr.mac),
            (7, ETH_P_ARP, PacketType.PACKET_BROADCAST, mac),
            msg="SockAddrLl must preserve every supplied field.",
        )

    def test__socket__sockaddr_ll_is_frozen(self) -> None:
        """
        Ensure 'SockAddrLl' is immutable — assigning to a field raises
        'FrozenInstanceError' so the address value type cannot be
        mutated after construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        addr = SockAddrLl()

        with self.assertRaises(dataclasses.FrozenInstanceError):
            addr.ifindex = 1  # type: ignore[misc]

    def test__socket__sockaddr_ll_equality_by_value(self) -> None:
        """
        Ensure two 'SockAddrLl' instances built from the same fields
        compare equal — the value type supports by-value equality so it
        can key per-interface registry lookups.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            SockAddrLl(ifindex=3, ethertype=ETH_P_IP),
            SockAddrLl(ifindex=3, ethertype=ETH_P_IP),
            msg="SockAddrLl instances with identical fields must compare equal.",
        )
