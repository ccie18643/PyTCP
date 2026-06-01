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
Integration tests for the socket finalizer safety net — a socket dropped
without close() still releases its IPv4 multicast memberships on GC
(Linux 'ip_mc_drop_socket' runs silently from the fd release). Without
this, a leaked joined socket would keep its group joined on the
interface forever.

pytcp/tests/integration/protocols/igmp/test__igmp__socket_gc_release.py

ver 3.0.8
"""

import gc
from typing import override

from net_addr import Ip4Address
from net_proto import IpProto
from pytcp.socket import (
    IP_ADD_SOURCE_MEMBERSHIP,
    IPPROTO_IP,
    AddressFamily,
    SocketType,
)
from pytcp.socket.udp__socket import UdpSocket
from pytcp.tests.lib.udp_testcase import UdpTestCase

_GROUP = Ip4Address("239.1.1.1")
_S1 = Ip4Address("10.0.0.1")


class TestIgmpSocketGcRelease(UdpTestCase):
    """
    The socket-finalizer multicast-membership release tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness. Sockets here are constructed directly (not
        registered in 'stack.sockets') so dropping the test's reference
        lets them be garbage-collected, exercising the finalizer.
        """

        super().setUp()

    def test__gc_of_unclosed_joined_socket_releases_membership(self) -> None:
        """
        Ensure a socket that joined a multicast group and is dropped
        without close() releases its membership on garbage collection, so
        the interface does not stay joined forever.

        Reference: RFC 3376 §3.2 (interface state follows the live socket set).
        """

        sock = UdpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM, protocol=IpProto.UDP)
        sock.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_S1) + bytes(Ip4Address()))
        self.assertIn(_GROUP, self._packet_handler._ip4_multicast, msg="The join must put the group on the interface.")

        del sock
        gc.collect()

        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="GC of an unclosed joined socket must release its membership.",
        )

    def test__gc_of_unclosed_socket_releases_all_source_filters(self) -> None:
        """
        Ensure the finalizer releases every group a leaked socket held,
        not just one — a socket joining two groups leaves both on GC.

        Reference: RFC 3376 §3.2 (interface state follows the live socket set).
        """

        group_b = Ip4Address("239.2.2.2")
        sock = UdpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM, protocol=IpProto.UDP)
        sock.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_S1) + bytes(Ip4Address()))
        sock.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(group_b) + bytes(_S1) + bytes(Ip4Address()))

        del sock
        gc.collect()

        self.assertNotIn(_GROUP, self._packet_handler._ip4_multicast, msg="The first joined group must be released.")
        self.assertNotIn(group_b, self._packet_handler._ip4_multicast, msg="The second joined group must be released.")

    def test__explicit_close_then_gc_is_idempotent(self) -> None:
        """
        Ensure a socket explicitly closed and then collected releases its
        membership exactly once (on close) — the finalizer no-ops on the
        already-closed socket and does not double-release.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = UdpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM, protocol=IpProto.UDP)
        sock.setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_S1) + bytes(Ip4Address()))
        sock.close()
        self.assertNotIn(_GROUP, self._packet_handler._ip4_multicast, msg="close() must release the membership.")

        # The finalizer must be a no-op on the already-closed socket.
        del sock
        gc.collect()
        self.assertNotIn(_GROUP, self._packet_handler._ip4_multicast)
