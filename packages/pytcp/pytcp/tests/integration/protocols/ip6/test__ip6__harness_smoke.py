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
Smoke tests for the 'Ip6TestCase' integration-test harness. Pins
'_build_ip6_frame', '_drive_ip6_rx', '_parse_tx_ip6', and
'_set_ip6_hosts' so the migrated IPv6 RFC 6724 / extension-header /
martian-source tests can rely on the harness shape.

pytcp/tests/integration/protocols/ip6/test__ip6__harness_smoke.py

ver 3.0.9
"""

from net_addr import Ip6Address, Ip6IfAddr
from net_proto import Icmp6Assembler, Icmp6MessageEchoRequest, IpProto
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from pytcp.tests.lib.ip6_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
    Ip6TestCase,
)


class TestIp6HarnessSmoke(Ip6TestCase):
    """
    Smoke tests for 'Ip6TestCase'.
    """

    def test__ip6__harness__build_ip6_frame_emits_ethernet_ip6_envelope(self) -> None:
        """
        Ensure '_build_ip6_frame' emits a frame whose Ethernet
        header carries EtherType IPv6 and whose default source +
        destination match the canonical HOST_A → STACK fixture.

        Reference: RFC 8200 §3 (IPv6 header); RFC 894 (Ethernet II carriage).
        """

        frame = self._build_ip6_frame()

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        self.assertIs(
            packet_rx.ethernet.type,
            EtherType.IP6,
            msg="'_build_ip6_frame' must wrap the IPv6 packet in an Ethernet/IP6 envelope.",
        )
        self.assertEqual(
            packet_rx.ethernet.src,
            HOST_A__MAC_ADDRESS,
            msg="Default '_build_ip6_frame' must source from HOST_A MAC.",
        )
        self.assertEqual(
            packet_rx.ethernet.dst,
            STACK__MAC_ADDRESS,
            msg="Default '_build_ip6_frame' must address the stack unicast MAC.",
        )

    def test__ip6__harness__drive_ip6_rx_returns_emitted_frames(self) -> None:
        """
        Ensure '_drive_ip6_rx' on a valid ICMPv6 Echo Request
        returns exactly one TX frame — the harness contract for
        "RX in, captured TX out".

        Reference: RFC 4443 §4 (Echo Request / Echo Reply).
        """

        frame = self._build_ip6_frame(
            payload=Icmp6Assembler(
                icmp6__message=Icmp6MessageEchoRequest(id=7, seq=10, data=b"abcd"),
            ),
        )

        frames_tx = self._drive_ip6_rx(frame=frame)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Echo Request must elicit exactly one Echo Reply; got {len(frames_tx)}.",
        )

    def test__ip6__harness__parse_tx_ip6_decodes_into_probe(self) -> None:
        """
        Ensure '_parse_tx_ip6' decodes the outbound Echo Reply
        frame into an 'Ip6Probe' whose src/dst swap relative to
        the request and whose next-header is ICMPv6.

        Reference: RFC 4443 §4 (Echo Reply).
        Reference: RFC 8200 §3 (IPv6 header).
        """

        frame = self._build_ip6_frame(
            payload=Icmp6Assembler(
                icmp6__message=Icmp6MessageEchoRequest(id=7, seq=10, data=b"abcd"),
            ),
        )

        frames_tx = self._drive_ip6_rx(frame=frame)
        probe = self._parse_tx_ip6(frames_tx[0])

        self.assertEqual(
            probe.ip_src,
            STACK__IP6_HOST.address,
            msg="Echo Reply ip_src must be the stack IPv6 address.",
        )
        self.assertEqual(
            probe.ip_dst,
            HOST_A__IP6_ADDRESS,
            msg="Echo Reply ip_dst must be the original requester.",
        )
        self.assertIs(
            probe.next_header,
            IpProto.ICMP6,
            msg="Echo Reply next-header must be ICMPv6.",
        )

    def test__ip6__harness__parse_tx_ip6_rejects_non_ip6(self) -> None:
        """
        Ensure '_parse_tx_ip6' raises AssertionError when the
        frame's EtherType is not IPv6 — guards against silent
        misclassification in IPv6 test fixtures.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Manual Ethernet/IPv4 frame so the EtherType mismatch fires.
        bogus = bytes(STACK__MAC_ADDRESS) + bytes(HOST_A__MAC_ADDRESS) + int(EtherType.IP4).to_bytes(2)

        with self.assertRaises(AssertionError):
            self._parse_tx_ip6(bogus)

    def test__ip6__harness__set_ip6_hosts_replaces_owned_list(self) -> None:
        """
        Ensure '_set_ip6_hosts' replaces the stack's '_ip6_ifaddr'
        list with the supplied hosts. Source-selection tests rely
        on this controlled-owned-address contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6IfAddr("2001:db8:1::10/64")
        b = Ip6IfAddr("2001:db8:2::20/64")

        self._set_ip6_hosts(a, b)

        addresses = [host.address for host in self._packet_handler._ip6_ifaddr]
        self.assertEqual(
            addresses,
            [Ip6Address("2001:db8:1::10"), Ip6Address("2001:db8:2::20")],
            msg="'_set_ip6_hosts' must replace '_ip6_ifaddr' with the supplied list in order.",
        )

    def test__ip6__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'Ip6TestCase.setUp' does not perturb the addresses,
        MAC, or host state inherited from 'NetworkTestCase'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet_handler._mac_unicast,
            STACK__MAC_ADDRESS,
            msg="Inherited stack MAC must be unchanged.",
        )
        addresses = {host.address for host in self._packet_handler._ip6_ifaddr}
        self.assertIn(
            STACK__IP6_HOST.address,
            addresses,
            msg="Inherited stack IPv6 host must be present in '_ip6_ifaddr'.",
        )
