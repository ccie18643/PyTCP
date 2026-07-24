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
This module contains the no-route EHOSTUNREACH integration test — a
UDP 'sendto' to a destination the FIB cannot reach raises a synchronous
'OSError(EHOSTUNREACH)' (the route lookup happens at send time, before
the datagram is queued), matching Linux.

pytcp/tests/integration/protocols/udp/test__udp__no_route.py

ver 3.0.8
"""

import errno
from typing import override

from net_addr import Ip4Address, Ip4Network
from pytcp import stack
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.udp_testcase import UdpTestCase

# Off-link destination with no covering route once the fixture default
# route is removed (not on the 10.0.1.0/24 connected subnet).
_OFF_LINK_DST = Ip4Address("8.8.8.8")
_REMOTE_PORT = 5555


class TestUdpSendtoNoRoute(UdpTestCase):
    """
    The no-route synchronous-EHOSTUNREACH 'sendto' tests.
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv4 UdpSocket on the canonical fixture address and
        remove the fixture IPv4 default route so an off-link
        destination has no covering route.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(family=AddressFamily.INET4)
        stack.ip4_fib.remove(destination=Ip4Network("0.0.0.0/0"))

    def test__udp__sendto_no_route_raises_ehostunreach(self) -> None:
        """
        Ensure 'sendto' to a destination the FIB cannot reach raises a
        synchronous 'OSError(EHOSTUNREACH)' rather than silently
        accepting and async-dropping the datagram — the route lookup
        happens at send time.

        Reference: RFC 1122 §3.3.1 (next-hop selection; no route to host).
        """

        with self.assertRaises(OSError) as ctx:
            self._socket.sendto(b"unreachable", (str(_OFF_LINK_DST), _REMOTE_PORT))

        self.assertEqual(
            ctx.exception.errno,
            errno.EHOSTUNREACH,
            msg="sendto() to an unrouted destination must raise OSError(EHOSTUNREACH).",
        )

    def test__udp__sendto_with_route_still_succeeds(self) -> None:
        """
        Ensure re-installing a default route makes the same off-link
        'sendto' succeed again (the EHOSTUNREACH is route-driven, not a
        blanket block on off-link destinations).

        Reference: RFC 1122 §3.3.1 (next-hop selection via gateway).
        """

        from pytcp.runtime.fib import Route, RouteProtocol

        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip4Address("10.0.1.1"),
                protocol=RouteProtocol.BOOT,
            )
        )

        sent = self._socket.sendto(b"reachable", (str(_OFF_LINK_DST), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"reachable"),
            msg="sendto() to an off-link destination with a default route must report success.",
        )
