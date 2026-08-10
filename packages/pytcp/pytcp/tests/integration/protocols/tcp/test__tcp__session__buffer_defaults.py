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
Integration tests for the TCP buffer-default sourcing (Tier-3 Track R/S,
step 5). A TCP socket's unset receive-window seed and send-buffer floor
come from the 'tcp.rmem.default' / 'tcp.wmem.default' sysctls (Linux
'tcp_rmem[1]' / 'tcp_wmem[1]'), so they are operator-tunable — while a
datagram socket keeps the generic 'net.core.*_default' stand-ins. The
shipped defaults keep PyTCP's conservative 65535 / 212992 values, so this
changes no behaviour; it only makes the starting points configurable and
gives the registered '.default' knobs live consumers.

pytcp/tests/integration/protocols/tcp/test__tcp__session__buffer_defaults.py

ver 3.0.9
"""

from typing import override

from pytcp.runtime.socket import (
    SOCKET__SO_RCVBUF__DEFAULT,
    SOCKET__SO_SNDBUF__DEFAULT,
    AddressFamily,
)
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.tcp_testcase import TcpTestCase


class TestTcpSessionBufferDefaults(TcpTestCase):
    """
    The TCP buffer-default sourcing tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore any sysctl overridden by an operator-override test so
        the mutation cannot leak into a sibling test.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__rcv_default__seeds_rcv_wnd_max_from_tcp_rmem_default(self) -> None:
        """
        Ensure a fresh session with no SO_RCVBUF seeds its advertised
        receive-window cap from 'tcp.rmem.default' — the shipped value
        keeps the conservative 65535.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux net.ipv4.tcp_rmem[1] (default receive window).
        """

        session = self._make_active_session(iss=1000)
        self.assertEqual(
            session.rcv_wnd_max,
            sysctl_module.get("tcp.rmem.default"),
            msg="rcv_wnd_max must seed from tcp.rmem.default.",
        )
        self.assertEqual(
            session.rcv_wnd_max,
            65535,
            msg="The shipped tcp.rmem.default must keep the conservative 65535.",
        )

    def test__rcv_default__operator_override_raises_seed(self) -> None:
        """
        Ensure raising 'tcp.rmem.default' raises the advertised-window
        seed of a subsequently-opened session, so the starting window
        is operator-tunable.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux net.ipv4.tcp_rmem[1] (operator-tunable default).
        """

        sysctl_module.set("tcp.rmem.default", 131072)
        session = self._make_active_session(iss=1000)
        self.assertEqual(
            session.rcv_wnd_max,
            131072,
            msg="A raised tcp.rmem.default must seed a larger rcv_wnd_max.",
        )

    def test__snd_default__effective_sndbuf_from_tcp_wmem_default(self) -> None:
        """
        Ensure a fresh TCP socket with no SO_SNDBUF reports a
        send-buffer floor from 'tcp.wmem.default' — the shipped value
        keeps the conservative 212992.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux net.ipv4.tcp_wmem[1] (default send buffer).
        """

        session = self._make_active_session(iss=1000)
        self.assertEqual(
            session._socket._effective_sndbuf(),
            sysctl_module.get("tcp.wmem.default"),
            msg="The TCP send-buffer floor must come from tcp.wmem.default.",
        )
        self.assertEqual(
            session._socket._effective_sndbuf(),
            212992,
            msg="The shipped tcp.wmem.default must keep the conservative 212992.",
        )

    def test__snd_default__operator_override_raises_floor(self) -> None:
        """
        Ensure raising 'tcp.wmem.default' raises the TCP send-buffer
        floor, so the starting send bound is operator-tunable.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux net.ipv4.tcp_wmem[1] (operator-tunable default).
        """

        session = self._make_active_session(iss=1000)
        sysctl_module.set("tcp.wmem.default", 300000)
        self.assertEqual(
            session._socket._effective_sndbuf(),
            300000,
            msg="A raised tcp.wmem.default must raise the TCP send-buffer floor.",
        )

    def test__datagram_default__unaffected_by_tcp_knob(self) -> None:
        """
        Ensure a datagram socket sources its buffer defaults from the
        generic 'net.core.*_default' stand-ins, not the TCP-specific
        knobs — overriding 'tcp.rmem.default' / 'tcp.wmem.default' must
        not move a UDP socket's effective buffers.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: Linux net.core.rmem_default / wmem_default (datagram
        default, distinct from tcp_rmem / tcp_wmem).
        """

        sysctl_module.set("tcp.rmem.default", 131072)
        sysctl_module.set("tcp.wmem.default", 300000)
        sock = UdpSocket(family=AddressFamily.INET4)
        self.addCleanup(sock.close)

        self.assertEqual(
            sock._effective_rcvbuf(),
            SOCKET__SO_RCVBUF__DEFAULT,
            msg="A datagram socket's rcvbuf default must be the generic net.core stand-in.",
        )
        self.assertEqual(
            sock._effective_sndbuf(),
            SOCKET__SO_SNDBUF__DEFAULT,
            msg="A datagram socket's sndbuf default must be the generic net.core stand-in.",
        )
