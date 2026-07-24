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

ver 3.0.9
"""

import errno

from net_addr import Ip4Address
from pytcp import stack
from pytcp.runtime.socket import (
    IP_MULTICAST_TTL,
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_MULTICAST_HOPS,
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


class TestSocketMulticastHopOverride(NetworkTestCase):
    """
    The per-socket multicast hop-count knobs — IP_MULTICAST_TTL
    (IPv4) and IPV6_MULTICAST_HOPS (IPv6): a sender may raise the
    multicast Hop-Limit above the default 1, independently of the
    unicast IP_TTL / IPV6_UNICAST_HOPS override; a value of 0
    keeps the datagram host-local (RFC 1112 §6.1) so it is not put
    on the wire.
    """

    def test__ip_multicast_ttl_setsockopt_getsockopt_roundtrip(self) -> None:
        """
        Ensure IP_MULTICAST_TTL stores the set value and getsockopt
        echoes it back, and that an unset socket reports the Linux
        default of 1.

        Reference: Linux IP_MULTICAST_TTL (default 1).
        """

        sock = UdpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IP, IP_MULTICAST_TTL),
            1,
            msg="IP_MULTICAST_TTL must default to 1 when unset.",
        )
        sock.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 32)
        self.assertEqual(
            sock.getsockopt(IPPROTO_IP, IP_MULTICAST_TTL),
            32,
            msg="IP_MULTICAST_TTL getsockopt must echo the value set.",
        )

    def test__ip_multicast_ttl_applied_to_multicast_and_not_unicast(self) -> None:
        """
        Ensure IP_MULTICAST_TTL binds a multicast datagram's TTL
        while the unicast IP_TTL override binds the unicast path —
        the two knobs are independent.

        Reference: Linux IP_MULTICAST_TTL (multicast TTL, separate
        from the unicast IP_TTL).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        sock.setsockopt(IPPROTO_IP, IP_TTL, 10)
        sock.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 32)

        sock.sendto(b"x", (str(_IP4__MULTICAST), 9999))
        self.assertEqual(
            self._frames_tx[-1][_IP4__TTL_OFFSET],
            32,
            msg="A multicast datagram must ship with IP_MULTICAST_TTL.",
        )

        sock.sendto(b"x", (str(HOST_A__IP4_ADDRESS), 9999))
        self.assertEqual(
            self._frames_tx[-1][_IP4__TTL_OFFSET],
            10,
            msg="A unicast datagram must ship with IP_TTL, not IP_MULTICAST_TTL.",
        )

    def test__ip_multicast_ttl_zero_suppresses_multicast_send(self) -> None:
        """
        Ensure IP_MULTICAST_TTL=0 keeps the datagram host-local —
        PyTCP has no multicast loopback, so the send is accepted
        (returns the byte count) but no frame is put on the wire.

        Reference: RFC 1112 §6.1 (TTL 0 restricts a multicast
        datagram to the same host).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        sock.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 0)

        sent = sock.sendto(b"payload", (str(_IP4__MULTICAST), 9999))

        self.assertEqual(sent, len(b"payload"), msg="A host-scope multicast send must report the byte count.")
        self.assertEqual(
            self._frames_tx,
            [],
            msg="IP_MULTICAST_TTL=0 must not put the multicast datagram on the wire.",
        )

    def test__ip_multicast_ttl_reset_minus_one_restores_default(self) -> None:
        """
        Ensure IP_MULTICAST_TTL=-1 resets the override so the
        multicast default of 1 governs again.

        Reference: Linux IP_MULTICAST_TTL (-1 resets to the default).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        sock.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 32)
        sock.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, -1)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IP, IP_MULTICAST_TTL),
            1,
            msg="IP_MULTICAST_TTL=-1 must restore the default 1.",
        )
        sock.sendto(b"x", (str(_IP4__MULTICAST), 9999))
        self.assertEqual(
            self._frames_tx[-1][_IP4__TTL_OFFSET],
            1,
            msg="After reset, a multicast datagram must ship with the default TTL 1.",
        )

    def test__ip_multicast_ttl_out_of_range_raises_einval(self) -> None:
        """
        Ensure IP_MULTICAST_TTL rejects a value outside -1..255 with
        EINVAL, matching Linux's range check.

        Reference: Linux net/ipv4/ip_sockglue.c (IP_MULTICAST_TTL
        range -1..255).
        """

        sock = UdpSocket(family=AddressFamily.INET4)

        for bad in (256, -2):
            with self.subTest(value=bad):
                with self.assertRaises(OSError) as ctx:
                    sock.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, bad)
                self.assertEqual(
                    ctx.exception.errno,
                    errno.EINVAL,
                    msg=f"IP_MULTICAST_TTL={bad} must raise EINVAL.",
                )

    def test__ipv6_multicast_hops_applied_to_multicast_and_not_unicast(self) -> None:
        """
        Ensure IPV6_MULTICAST_HOPS binds a multicast datagram's
        Hop-Limit while IPV6_UNICAST_HOPS binds the unicast path —
        the two knobs are independent.

        Reference: Linux IPV6_MULTICAST_HOPS (multicast Hop-Limit,
        separate from the unicast IPV6_UNICAST_HOPS).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        sock.bind((str(STACK__IP6_HOST.address), 0))
        sock.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 10)
        sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 32)

        sock.sendto(b"x", (str(IP6__MULTICAST__ALL_NODES), 9999))
        self.assertEqual(
            self._frames_tx[-1][_IP6__HOP_OFFSET],
            32,
            msg="A multicast datagram must ship with IPV6_MULTICAST_HOPS.",
        )

        sock.sendto(b"x", (str(HOST_A__IP6_ADDRESS), 9999))
        self.assertEqual(
            self._frames_tx[-1][_IP6__HOP_OFFSET],
            10,
            msg="A unicast datagram must ship with IPV6_UNICAST_HOPS, not IPV6_MULTICAST_HOPS.",
        )

    def test__ipv6_multicast_hops_zero_suppresses_multicast_send(self) -> None:
        """
        Ensure IPV6_MULTICAST_HOPS=0 keeps the datagram host-local
        — no frame is put on the wire (PyTCP has no multicast
        loopback).

        Reference: RFC 1112 §6.1 (hop count 0 restricts a multicast
        datagram to the same host).
        """

        sock = UdpSocket(family=AddressFamily.INET6)
        sock.bind((str(STACK__IP6_HOST.address), 0))
        sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 0)

        sent = sock.sendto(b"payload", (str(IP6__MULTICAST__ALL_NODES), 9999))

        self.assertEqual(sent, len(b"payload"), msg="A host-scope multicast send must report the byte count.")
        self.assertEqual(
            self._frames_tx,
            [],
            msg="IPV6_MULTICAST_HOPS=0 must not put the multicast datagram on the wire.",
        )

    def test__ipv6_multicast_hops_roundtrip_and_einval(self) -> None:
        """
        Ensure IPV6_MULTICAST_HOPS round-trips through
        getsockopt (default 1) and rejects an out-of-range value
        with EINVAL.

        Reference: Linux IPV6_MULTICAST_HOPS (default 1; range -1..255).
        """

        sock = UdpSocket(family=AddressFamily.INET6)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS),
            1,
            msg="IPV6_MULTICAST_HOPS must default to 1 when unset.",
        )
        sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 200)
        self.assertEqual(
            sock.getsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS),
            200,
            msg="IPV6_MULTICAST_HOPS getsockopt must echo the value set.",
        )
        with self.assertRaises(OSError) as ctx:
            sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 256)
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="IPV6_MULTICAST_HOPS=256 must raise EINVAL.",
        )
