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
This module contains integration tests for the RFC 4861 §7.3.1
upper-layer reachability confirmation hook — Phase 4 of the
NUD migration plan ('docs/refactor/nud_state_machine.md').

When a TCP cum-ACK advances SND.UNA, the peer has demonstrably
received and acknowledged data we sent — strong upper-layer
evidence the neighbour is reachable. The session feeds this
evidence into the NUD cache via 'confirm_reachability' so any
STALE / DELAY / PROBE entry skips the unicast probe and
promotes directly to REACHABLE. Linux's
'NEIGH_UPDATE_F_USE' / 'NEIGH_UPDATE_F_OVERRIDE' on the
neighbour cache is the mirror.

pytcp/tests/integration/protocols/tcp/test__tcp__session__nud_reachability.py

ver 3.0.8
"""

from net_addr import Ip4Address, Ip6Address
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP4: Ip4Address = STACK__IP4_HOST.address
STACK__IP6: Ip6Address = STACK__IP6_HOST.address
PEER__IP4: Ip4Address = HOST_A__IP4_ADDRESS
PEER__IP6: Ip6Address = HOST_A__IP6_ADDRESS
PEER__PORT: int = 80
STACK__PORT: int = 12345

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000


class TestTcpSessionNudReachability(TcpTestCase):
    """
    The TCP → NUD reachability-confirmation hook tests. Pin
    that an inbound cum-ACK that advances SND.UNA fires
    'arp_cache.confirm_reachability(ip4_address=peer)' for
    IPv4 sessions and 'nd_cache.confirm_reachability(
    ip6_address=peer)' for IPv6 sessions.
    """

    def test__tcp__session__nud__ipv4_cum_ack_confirms_arp_reachability(self) -> None:
        """
        Ensure an inbound cum-ACK that advances SND.UNA on an
        IPv4 TCP session calls
        'self._arp_cache.confirm_reachability(
        ip4_address=peer_ip)'. The handshake's SYN-ACK is the
        first cum-ACK that advances SND.UNA, so driving
        '_drive_handshake_to_established' is sufficient to
        exercise the hook.

        Reference: RFC 4861 §7.3.1 (upper-layer reachability confirmation).
        """

        # Reset the mocks so 'reset_mock' clears any prior
        # confirm_reachability calls accumulated during fixture
        # setup (none expected in practice but belt-and-braces).
        self._arp_cache.reset_mock()
        self._nd_cache.reset_mock()

        self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            family=AddressFamily.INET4,
            local_ip=STACK__IP4,
            local_port=STACK__PORT,
            remote_ip=PEER__IP4,
            remote_port=PEER__PORT,
        )

        self._arp_cache.confirm_reachability.assert_called_with(
            ip4_address=PEER__IP4,
        )
        self._nd_cache.confirm_reachability.assert_not_called()

    def test__tcp__session__nud__ipv6_cum_ack_confirms_nd_reachability(self) -> None:
        """
        Ensure an inbound cum-ACK that advances SND.UNA on an
        IPv6 TCP session calls
        'self._nd_cache.confirm_reachability(
        ip6_address=peer_ip)'. The IPv6 mirror of the IPv4
        case above.

        Reference: RFC 4861 §7.3.1 (upper-layer reachability confirmation).
        """

        self._arp_cache.reset_mock()
        self._nd_cache.reset_mock()

        self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            family=AddressFamily.INET6,
            local_ip=STACK__IP6,
            local_port=STACK__PORT,
            remote_ip=PEER__IP6,
            remote_port=PEER__PORT,
        )

        self._nd_cache.confirm_reachability.assert_called_with(
            ip6_address=PEER__IP6,
        )
        self._arp_cache.confirm_reachability.assert_not_called()
