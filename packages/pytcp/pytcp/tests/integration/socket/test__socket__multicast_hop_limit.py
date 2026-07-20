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
Integration tests for the per-socket multicast hop-count surface:
the unicast IP_TTL / IPV6_UNICAST_HOPS overrides must NOT bleed
into multicast sends (Linux keeps the unicast and multicast hop
knobs separate — 'inet->uc_ttl' vs 'inet->mc_ttl',
'np->hop_limit' vs 'np->mcast_hops').

pytcp/tests/integration/socket/test__socket__multicast_hop_limit.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.runtime.socket import (
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_UNICAST_HOPS,
    AddressFamily,
)
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    IP6__MULTICAST__ALL_NODES,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    NetworkTestCase,
)

# The TTL byte lives at IPv4-header offset 8 (Ethernet offset 14);
# the Hop-Limit byte lives at IPv6-header offset 7.
_IP4__TTL_OFFSET = 14 + 8
_IP6__HOP_OFFSET = 14 + 7

_IP4__MULTICAST = Ip4Address("224.0.0.1")

# Silence the SOCKET log channel: UDP sockets log on send and the
# harness tearDown restores LOG__CHANNEL, leaking into runner output.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence stack log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the production log-channel configuration.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class TestSocketUnicastHopDoesNotBleedIntoMulticast(NetworkTestCase):
    """
    The unicast IP_TTL / IPV6_UNICAST_HOPS overrides bind unicast
    sends only; a multicast datagram keeps the multicast default
    (Hop-Limit / TTL = 1) regardless of the unicast override.
    """

    def test__ip_ttl_does_not_affect_ipv4_multicast_send(self) -> None:
        """
        Ensure a socket-level IP_TTL override does not change the
        TTL of an outbound IPv4 multicast datagram — the multicast
        default of 1 stands, since IP_TTL is a unicast-only knob.

        Reference: Linux net/ipv4/ip_sockglue.c (inet->uc_ttl vs
        inet->mc_ttl — IP_TTL binds unicast only).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        sock.setsockopt(IPPROTO_IP, IP_TTL, 50)

        sock.sendto(b"x", (str(_IP4__MULTICAST), 9999))

        self.assertEqual(len(self._frames_tx), 1, msg="Multicast sendto must emit exactly one frame.")
        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            1,
            msg="IP_TTL (unicast override) must not raise the multicast TTL; it stays at the default 1.",
        )

    def test__ip_ttl_still_applies_to_ipv4_unicast_send(self) -> None:
        """
        Ensure a socket-level IP_TTL override still binds an IPv4
        unicast datagram — regression pin so the multicast
        carve-out does not disturb the unicast path.

        Reference: Linux IP_TTL (per-socket unicast TTL override).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        sock.setsockopt(IPPROTO_IP, IP_TTL, 50)

        sock.sendto(b"x", (str(HOST_A__IP4_ADDRESS), 9999))

        self.assertEqual(
            self._frames_tx[0][_IP4__TTL_OFFSET],
            50,
            msg="IP_TTL must bind a unicast datagram's TTL verbatim.",
        )

    def test__ipv6_unicast_hops_does_not_affect_multicast_send(self) -> None:
        """
        Ensure a socket-level IPV6_UNICAST_HOPS override does not
        change the Hop-Limit of an outbound IPv6 multicast
        datagram — the multicast default of 1 stands, since
        IPV6_UNICAST_HOPS is a unicast-only knob.

        Reference: Linux net/ipv6/ipv6_sockglue.c (np->hop_limit vs
        np->mcast_hops — IPV6_UNICAST_HOPS binds unicast only).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        sock.bind((str(STACK__IP6_HOST.address), 0))
        sock.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 50)

        sock.sendto(b"x", (str(IP6__MULTICAST__ALL_NODES), 9999))

        self.assertEqual(len(self._frames_tx), 1, msg="Multicast sendto must emit exactly one frame.")
        self.assertEqual(
            self._frames_tx[0][_IP6__HOP_OFFSET],
            1,
            msg="IPV6_UNICAST_HOPS (unicast override) must not raise the multicast Hop-Limit; it stays at 1.",
        )

    def test__ipv6_unicast_hops_still_applies_to_unicast_send(self) -> None:
        """
        Ensure a socket-level IPV6_UNICAST_HOPS override still
        binds an IPv6 unicast datagram — regression pin so the
        multicast carve-out does not disturb the unicast path.

        Reference: Linux IPV6_UNICAST_HOPS (per-socket unicast Hop-Limit override).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        sock.bind((str(STACK__IP6_HOST.address), 0))
        sock.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 50)

        sock.sendto(b"x", (str(HOST_A__IP6_ADDRESS), 9999))

        self.assertEqual(
            self._frames_tx[0][_IP6__HOP_OFFSET],
            50,
            msg="IPV6_UNICAST_HOPS must bind a unicast datagram's Hop-Limit verbatim.",
        )
