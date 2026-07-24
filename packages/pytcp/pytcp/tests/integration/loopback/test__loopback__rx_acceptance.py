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
Integration tests for the loopback RX local-delivery acceptance hook.

pytcp/tests/integration/loopback/test__loopback__rx_acceptance.py

ver 3.0.9
"""

from typing import override

from net_addr import Ip4Address, Ip6Address
from pytcp.tests.lib.network_testcase import (
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    NetworkTestCase,
)

_FOREIGN_IP4 = Ip4Address("8.8.8.8")
_FOREIGN_IP6 = Ip6Address("2001:db8:ffff::1")


class TestLoopbackRxAcceptance(NetworkTestCase):
    """
    The loopback RX local-delivery acceptance tests
    ('_accepts_local_dst_ip4' / '_accepts_local_dst_ip6').
    """

    @override
    def setUp(self) -> None:
        """
        Bring up the boot interface and register a loopback interface.
        """

        super().setUp()
        self._lo = self._register_loopback()

    def test__loopback__accepts_whole_loopback_range_ipv4(self) -> None:
        """
        Ensure the loopback interface accepts delivery for any address in
        127.0.0.0/8, not just its own configured 127.0.0.1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._lo._accepts_local_dst_ip4(Ip4Address("127.0.0.5")),
            msg="Loopback RX must accept the whole 127.0.0.0/8 range.",
        )

    def test__loopback__accepts_own_routable_dst_ipv4(self) -> None:
        """
        Ensure the loopback interface accepts delivery for the host's own
        routable IPv4 address, so a packet looped to own-IP is delivered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._lo._accepts_local_dst_ip4(STACK__IP4_HOST.address),
            msg="Loopback RX must accept the host's own routable IPv4 address.",
        )

    def test__loopback__rejects_foreign_dst_ipv4(self) -> None:
        """
        Ensure the loopback interface rejects delivery for an address the
        host does not own.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._lo._accepts_local_dst_ip4(_FOREIGN_IP4),
            msg="Loopback RX must reject a foreign IPv4 destination.",
        )

    def test__loopback__accepts_loopback_dst_ipv6(self) -> None:
        """
        Ensure the loopback interface accepts delivery for ::1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._lo._accepts_local_dst_ip6(Ip6Address("::1")),
            msg="Loopback RX must accept the ::1 loopback destination.",
        )

    def test__loopback__accepts_own_routable_dst_ipv6(self) -> None:
        """
        Ensure the loopback interface accepts delivery for the host's own
        global IPv6 address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._lo._accepts_local_dst_ip6(STACK__IP6_HOST.address),
            msg="Loopback RX must accept the host's own routable IPv6 address.",
        )

    def test__loopback__rejects_foreign_dst_ipv6(self) -> None:
        """
        Ensure the loopback interface rejects delivery for an IPv6 address
        the host does not own.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._lo._accepts_local_dst_ip6(_FOREIGN_IP6),
            msg="Loopback RX must reject a foreign IPv6 destination.",
        )

    def test__physical__rx_acceptance_unchanged(self) -> None:
        """
        Ensure the physical interface's RX acceptance is unchanged: it
        accepts its own address, rejects a foreign one, and does NOT
        accept loopback traffic (which is delivered on 'lo').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._packet_handler._accepts_local_dst_ip4(STACK__IP4_HOST.address),
            msg="The physical interface must still accept its own address.",
        )
        self.assertFalse(
            self._packet_handler._accepts_local_dst_ip4(_FOREIGN_IP4),
            msg="The physical interface must still reject a foreign address.",
        )
        self.assertFalse(
            self._packet_handler._accepts_local_dst_ip4(Ip4Address("127.0.0.1")),
            msg="The physical interface must not accept loopback traffic.",
        )
