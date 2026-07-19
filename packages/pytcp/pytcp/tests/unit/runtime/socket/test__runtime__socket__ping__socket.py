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
This module contains tests for the 'PingSocket' ICMP Echo datagram socket.

pytcp/tests/unit/runtime/socket/test__runtime__socket__ping__socket.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.runtime.socket import (
    SO_RCVBUF,
    SOL_SOCKET,
    AddressFamily,
)
from pytcp.runtime.socket.ping__metadata import PingMetadata
from pytcp.runtime.socket.ping__socket import PingSocket


class _PingSocketTestCase(TestCase):
    """
    Shared fixture for 'PingSocket' tests that pins the module-level
    'log' and the 'stack.icmp_echo_sockets' registry so the real stack
    singletons are never touched from the unit-test process.
    """

    @override
    def setUp(self) -> None:
        """
        Patch logging and the ICMP-echo socket registry for the
        duration of the test.

        Patches register their stops via 'addCleanup' so test-level
        'self.addCleanup(s.close)' callbacks (LIFO-popped first) run
        while the 'log' patch is still active.
        """

        self._log_patch = patch("pytcp.runtime.socket.ping__socket.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._echo_sockets: dict[tuple[AddressFamily, int], PingSocket] = {}
        self._echo_sockets_patch = patch(
            "pytcp.runtime.socket.ping__socket.stack.icmp_echo_sockets",
            self._echo_sockets,
        )
        self._echo_sockets_patch.start()
        self.addCleanup(self._echo_sockets_patch.stop)


class TestPingSocketRcvbuf(_PingSocketTestCase):
    """
    The 'PingSocket' SO_RCVBUF receive-queue-cap tests.
    """

    def _make_md(self) -> PingMetadata:
        """
        Build a canonical IPv4 'PingMetadata' Echo Reply envelope with a
        7-byte ICMP message.
        """

        return PingMetadata(
            ip__ver=IpVersion.IP4,
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__ttl=64,
            icmp__data=b"payload",
        )

    def test__ping_socket__setsockopt_so_rcvbuf_sets_cap(self) -> None:
        """
        Ensure that 'setsockopt(SOL_SOCKET, SO_RCVBUF, n)' routes to the
        base SOL_SOCKET handler and records the receive-buffer cap on the
        ping socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = PingSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_RCVBUF, 4096)
        self.assertEqual(
            s._so_rcvbuf,
            4096,
            msg="setsockopt(SOL_SOCKET, SO_RCVBUF) must set the ping socket's receive-buffer cap.",
        )

    def test__ping_socket__so_rcvbuf_drops_reply_over_cap(self) -> None:
        """
        Ensure that once 'SO_RCVBUF' is set, an inbound Echo Reply whose
        message would push the queued receive bytes past the cap is
        dropped rather than enqueued.

        Reference: RFC 1122 §4.2.2.16 (receive-buffer bound).
        """

        s = PingSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self.addCleanup(s.close)
        s.setsockopt(SOL_SOCKET, SO_RCVBUF, 20)
        s.process_echo_reply(self._make_md())
        s.process_echo_reply(self._make_md())
        s.process_echo_reply(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            2,
            msg="An Echo Reply over the SO_RCVBUF cap must be dropped, not enqueued.",
        )

    def test__ping_socket__so_rcvbuf_unset_is_unbounded(self) -> None:
        """
        Ensure that with 'SO_RCVBUF' unset the ping receive queue is
        unbounded (no default cap).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = PingSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self.addCleanup(s.close)
        for _ in range(50):
            s.process_echo_reply(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            50,
            msg="With SO_RCVBUF unset every Echo Reply must be enqueued.",
        )
