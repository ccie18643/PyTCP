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
Smoke tests for the 'UdpTestCase' integration-test harness. Pins
the socket-state snapshot/restore around 'setUp' / 'tearDown',
'_bind_udp_socket', '_drive_udp_rx', and '_parse_tx' so the UDP
socket-API / options / PMTUD tests can rely on the harness shape.

pytcp/tests/integration/protocols/udp/test__udp__harness_smoke.py

ver 3.0.9
"""

from net_addr import IpVersion
from net_proto import (
    EthernetAssembler,
    Ip4Assembler,
    UdpAssembler,
)
from pytcp import stack
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.udp_testcase import (
    _DEFAULT_LOCAL_PORT,
    UdpTestCase,
)


class TestUdpHarnessSmoke(UdpTestCase):
    """
    Smoke tests for 'UdpTestCase'.
    """

    def test__udp__harness__sockets_cleared_in_setup(self) -> None:
        """
        Ensure 'UdpTestCase.setUp' clears 'stack.sockets' so every
        test starts with an empty socket registry. The
        snapshot/restore around teardown is what keeps unrelated
        tests outside this harness unaffected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(stack.sockets),
            0,
            msg=f"stack.sockets must be empty at test entry; saw {len(stack.sockets)} entries.",
        )

    def test__udp__harness__bind_udp_socket_registers_in_stack_sockets(self) -> None:
        """
        Ensure '_bind_udp_socket' creates a UdpSocket on the
        canonical fixture addressing and registers it in
        'stack.sockets'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._bind_udp_socket()

        self.assertEqual(
            sock._local_ip_address,
            STACK__IP4_HOST.address,
            msg="Default '_bind_udp_socket' must bind to STACK IPv4 address.",
        )
        self.assertEqual(
            sock._local_port,
            _DEFAULT_LOCAL_PORT,
            msg=f"Default local port must be {_DEFAULT_LOCAL_PORT}.",
        )
        self.assertIn(
            sock.socket_id,
            stack.sockets,
            msg="Bound socket must be present in stack.sockets.",
        )

    def test__udp__harness__drive_udp_rx_returns_emitted_frames(self) -> None:
        """
        Ensure '_drive_udp_rx' on a frame that does not match any
        registered socket triggers the ICMPv4 Port Unreachable
        emit path and returns exactly one TX frame — pinning the
        "RX in, captured TX out" contract for the UDP family.

        Reference: RFC 1122 §4.1.3.1 (port unreachable on no listener).
        """

        # Build Ethernet/IPv4/UDP frame to an unbound port (no
        # _bind_udp_socket call) so the stack emits Port Unreachable.
        frame = bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__payload=UdpAssembler(
                        udp__sport=33333,
                        udp__dport=33334,
                        udp__payload=b"unreachable",
                    ),
                ),
            )
        )

        frames_tx = self._drive_udp_rx(frame=frame)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"UDP to closed port must elicit one ICMP Port Unreachable; got {len(frames_tx)}.",
        )

    def test__udp__harness__parse_tx_decodes_udp_probe(self) -> None:
        """
        Ensure '_parse_tx' decodes an Ethernet/IPv4/UDP frame the
        harness itself built into a 'UdpProbe' carrying matching
        ip / port / payload values.

        Reference: RFC 791 §3.1 (IPv4 header); RFC 768 (UDP header).
        """

        # Build a TX-direction frame and feed it through the parser.
        frame = bytes(
            EthernetAssembler(
                ethernet__src=STACK__MAC_ADDRESS,
                ethernet__dst=HOST_A__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=STACK__IP4_HOST.address,
                    ip4__dst=HOST_A__IP4_ADDRESS,
                    ip4__payload=UdpAssembler(
                        udp__sport=4444,
                        udp__dport=5555,
                        udp__payload=b"ABCD",
                    ),
                ),
            )
        )

        probe = self._parse_tx(frame)

        self.assertIs(
            probe.ip_ver,
            IpVersion.IP4,
            msg="UDP probe must report IPv4 for an IPv4-carried datagram.",
        )
        self.assertEqual(
            probe.ip_src,
            STACK__IP4_HOST.address,
            msg="UDP probe ip_src must equal the assembler input.",
        )
        self.assertEqual(
            probe.ip_dst,
            HOST_A__IP4_ADDRESS,
            msg="UDP probe ip_dst must equal the assembler input.",
        )
        self.assertEqual(
            probe.sport,
            4444,
            msg="UDP probe 'sport' must equal the assembler input.",
        )
        self.assertEqual(
            probe.dport,
            5555,
            msg="UDP probe 'dport' must equal the assembler input.",
        )
        self.assertEqual(
            probe.payload,
            b"ABCD",
            msg="UDP probe 'payload' must equal the assembler input.",
        )

    def test__udp__harness__bind_inet6_uses_stack_ip6(self) -> None:
        """
        Ensure '_bind_udp_socket(family=AddressFamily.INET6)'
        binds to the stack's IPv6 address by default rather than
        the IPv4 one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.tests.lib.network_testcase import STACK__IP6_HOST

        sock = self._bind_udp_socket(family=AddressFamily.INET6)

        self.assertEqual(
            sock._local_ip_address,
            STACK__IP6_HOST.address,
            msg="INET6 '_bind_udp_socket' must default to STACK IPv6 address.",
        )

    def test__udp__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'UdpTestCase.setUp' does not perturb the addresses,
        MAC, or host state inherited from 'NetworkTestCase' (it
        only adds the socket / PMTU snapshot/restore).

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
