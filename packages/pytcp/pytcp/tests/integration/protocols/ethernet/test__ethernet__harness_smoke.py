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
Smoke tests for the 'EthernetTestCase' integration-test harness. The
goal is to pin '_build_ethernet_frame', '_build_broadcast_ethernet_frame',
and '_drive_ethernet_rx' so the migrated Ethernet II RX/TX integration
tests can rely on the harness shape.

pytcp/tests/integration/protocols/ethernet/test__ethernet__harness_smoke.py

ver 3.0.9
"""

from net_addr import MacAddress
from net_proto import EthernetParser
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from pytcp.tests.lib.ethernet_testcase import EthernetTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)

_BROADCAST_MAC: MacAddress = MacAddress(0xFFFFFFFFFFFF)


class TestEthernetHarnessSmoke(EthernetTestCase):
    """
    Smoke tests for 'EthernetTestCase'.
    """

    def test__ethernet__harness__build_ethernet_frame_emits_14_byte_header(self) -> None:
        """
        Ensure '_build_ethernet_frame' emits a frame whose first 14
        bytes are the Ethernet II header (6 dst + 6 src + 2 type).

        Reference: IEEE 802.3 §3.2 (Ethernet II / DIX header layout).
        """

        frame = self._build_ethernet_frame()

        self.assertEqual(
            len(frame),
            14,
            msg=f"Default '_build_ethernet_frame' must emit a 14-byte header-only frame; got {len(frame)}.",
        )

    def test__ethernet__harness__build_ethernet_frame_round_trips_through_parser(self) -> None:
        """
        Ensure a frame produced by '_build_ethernet_frame' is
        parsable by 'EthernetParser' and the parsed fields match
        the harness defaults (HOST_A → STACK, EtherType IP4).

        Reference: RFC 894 (Ethernet II wire format for IPv4 carriage).
        """

        frame = self._build_ethernet_frame()

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        self.assertEqual(
            packet_rx.ethernet.dst,
            STACK__MAC_ADDRESS,
            msg="Default '_build_ethernet_frame' must address the stack unicast MAC.",
        )
        self.assertEqual(
            packet_rx.ethernet.src,
            HOST_A__MAC_ADDRESS,
            msg="Default '_build_ethernet_frame' must source from HOST_A.",
        )
        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.IP4,
            msg="Default '_build_ethernet_frame' must carry EtherType IPv4.",
        )

    def test__ethernet__harness__build_ethernet_frame_kwargs_override(self) -> None:
        """
        Ensure every kwarg of '_build_ethernet_frame' is honoured —
        dst_mac, src_mac, ether_type, and payload all show through
        to the wire bytes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        custom_dst = MacAddress("02:00:00:00:00:42")
        custom_src = MacAddress("02:00:00:00:00:99")
        custom_payload = b"\xde\xad\xbe\xef"

        frame = self._build_ethernet_frame(
            dst_mac=custom_dst,
            src_mac=custom_src,
            ether_type=EtherType.IP6,
            payload=custom_payload,
        )

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        self.assertEqual(
            packet_rx.ethernet.dst,
            custom_dst,
            msg="Caller-supplied 'dst_mac' must appear in the wire frame.",
        )
        self.assertEqual(
            packet_rx.ethernet.src,
            custom_src,
            msg="Caller-supplied 'src_mac' must appear in the wire frame.",
        )
        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.IP6,
            msg="Caller-supplied 'ether_type' must appear in the wire frame.",
        )
        self.assertEqual(
            bytes(packet_rx.frame),
            custom_payload,
            msg="Caller-supplied 'payload' must follow the Ethernet header verbatim.",
        )

    def test__ethernet__harness__build_broadcast_ethernet_frame_uses_ff_ff(self) -> None:
        """
        Ensure '_build_broadcast_ethernet_frame' sets the destination
        MAC to FF:FF:FF:FF:FF:FF and defaults the EtherType to ARP
        (the canonical broadcast traffic on real Ethernet wires).

        Reference: IEEE 802.3 §3.2.4 (link-layer broadcast address).
        Reference: RFC 826 (ARP runs over broadcast).
        """

        frame = self._build_broadcast_ethernet_frame()

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        self.assertEqual(
            packet_rx.ethernet.dst,
            _BROADCAST_MAC,
            msg="Broadcast builder must address ff:ff:ff:ff:ff:ff.",
        )
        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.ARP,
            msg="Broadcast builder must default the EtherType to ARP.",
        )

    def test__ethernet__harness__drive_ethernet_rx_invokes_packet_handler(self) -> None:
        """
        Ensure '_drive_ethernet_rx' feeds the frame into
        'PacketHandler._phrx_ethernet' so the classifier bumps the
        ethernet__pre_parse counter exactly once. Pins the
        harness's "RX in" contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Header-only frame to the stack unicast MAC with an
        # ethertype the stack does not dispatch (RAW = 0xFFFF) —
        # exercises the classifier path without engaging
        # upper-layer parsers.
        frame = self._build_ethernet_frame(ether_type=EtherType.RAW)

        self._drive_ethernet_rx(frame=frame)

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ethernet__pre_parse,
            1,
            msg="'_drive_ethernet_rx' must bump the ethernet__pre_parse counter exactly once.",
        )

    def test__ethernet__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'EthernetTestCase.setUp' does not perturb the
        addresses, MAC, or host state inherited from
        'NetworkTestCase'. Migrated tests depend on the same
        baseline they got under the parent harness.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet_handler._mac_unicast,
            STACK__MAC_ADDRESS,
            msg="Inherited stack MAC must be unchanged.",
        )
        addresses = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            STACK__IP4_HOST.address,
            addresses,
            msg="Inherited stack IPv4 host must be present in '_ip4_ifaddr'.",
        )
