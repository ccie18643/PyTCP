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
Smoke tests for the 'Ip4TestCase' integration-test harness. Pins
'_build_ip4_frame', '_drive_ip4_rx', '_parse_tx_ip4', and
'_set_ip4_hosts' so the migrated IPv4 RFC 6724 / martian-source
tests can rely on the harness shape.

pytcp/tests/integration/protocols/ip4/test__ip4__harness_smoke.py

ver 3.0.8
"""

from net_addr import Ip4Address, Ip4IfAddr
from net_proto import Icmp4Assembler, Icmp4MessageEchoRequest, IpProto
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from pytcp.tests.lib.ip4_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    Ip4TestCase,
)


class TestIp4HarnessSmoke(Ip4TestCase):
    """
    Smoke tests for 'Ip4TestCase'.
    """

    def test__ip4__harness__build_ip4_frame_emits_ethernet_ip4_envelope(self) -> None:
        """
        Ensure '_build_ip4_frame' emits a frame whose Ethernet
        header carries EtherType IPv4 and whose default source +
        destination match the canonical HOST_A → STACK fixture.

        Reference: RFC 894 (Ethernet II IPv4 carriage); RFC 791 §3.1 (IPv4 header).
        """

        frame = self._build_ip4_frame()

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.IP4,
            msg="'_build_ip4_frame' must wrap the IPv4 packet in an Ethernet/IP4 envelope.",
        )
        self.assertEqual(
            packet_rx.ethernet.src,
            HOST_A__MAC_ADDRESS,
            msg="Default '_build_ip4_frame' must source from HOST_A MAC.",
        )
        self.assertEqual(
            packet_rx.ethernet.dst,
            STACK__MAC_ADDRESS,
            msg="Default '_build_ip4_frame' must address the stack unicast MAC.",
        )

    def test__ip4__harness__drive_ip4_rx_returns_emitted_frames(self) -> None:
        """
        Ensure '_drive_ip4_rx' on a valid ICMPv4 Echo Request
        returns exactly one TX frame — the harness contract for
        "RX in, captured TX out".

        Reference: RFC 792 (Echo / Echo Reply).
        """

        frame = self._build_ip4_frame(
            payload=Icmp4Assembler(
                icmp4__message=Icmp4MessageEchoRequest(id=7, seq=10, data=b"abcd"),
            ),
        )

        frames_tx = self._drive_ip4_rx(frame=frame)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Echo Request must elicit exactly one Echo Reply; got {len(frames_tx)}.",
        )

    def test__ip4__harness__parse_tx_ip4_decodes_into_probe(self) -> None:
        """
        Ensure '_parse_tx_ip4' decodes the outbound Echo Reply
        frame into an 'Ip4Probe' whose src/dst swap relative to
        the request and whose next-header is ICMPv4.

        Reference: RFC 792 (Echo / Echo Reply).
        Reference: RFC 791 §3.1 (IPv4 header).
        """

        frame = self._build_ip4_frame(
            payload=Icmp4Assembler(
                icmp4__message=Icmp4MessageEchoRequest(id=7, seq=10, data=b"abcd"),
            ),
        )

        frames_tx = self._drive_ip4_rx(frame=frame)
        probe = self._parse_tx_ip4(frames_tx[0])

        self.assertEqual(
            probe.ip_src,
            STACK__IP4_HOST.address,
            msg="Echo Reply ip_src must be the stack IPv4 address.",
        )
        self.assertEqual(
            probe.ip_dst,
            HOST_A__IP4_ADDRESS,
            msg="Echo Reply ip_dst must be the original requester.",
        )
        self.assertIs(
            probe.proto,
            IpProto.ICMP4,
            msg="Echo Reply next-header must be ICMPv4.",
        )

    def test__ip4__harness__parse_tx_ip4_rejects_non_ip4(self) -> None:
        """
        Ensure '_parse_tx_ip4' raises AssertionError when the
        frame's EtherType is not IPv4 — guards against silent
        misclassification in IPv4 test fixtures.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Build a raw Ethernet/IPv6 frame manually so the EtherType
        # mismatch fires.
        bogus = bytes(STACK__MAC_ADDRESS) + bytes(HOST_A__MAC_ADDRESS) + int(EtherType.IP6).to_bytes(2)

        with self.assertRaises(AssertionError):
            self._parse_tx_ip4(bogus)

    def test__ip4__harness__set_ip4_hosts_replaces_owned_list(self) -> None:
        """
        Ensure '_set_ip4_hosts' replaces the stack's '_ip4_ifaddr'
        list with the supplied hosts. Source-selection tests rely
        on this controlled-owned-address contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.0.2.10/24")
        b = Ip4IfAddr("198.51.100.20/24")

        self._set_ip4_hosts(a, b)

        addresses = [host.address for host in self._packet_handler._ip4_ifaddr]
        self.assertEqual(
            addresses,
            [Ip4Address("192.0.2.10"), Ip4Address("198.51.100.20")],
            msg="'_set_ip4_hosts' must replace '_ip4_ifaddr' with the supplied list in order.",
        )

    def test__ip4__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'Ip4TestCase.setUp' does not perturb the addresses,
        MAC, or host state inherited from 'NetworkTestCase'.

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
