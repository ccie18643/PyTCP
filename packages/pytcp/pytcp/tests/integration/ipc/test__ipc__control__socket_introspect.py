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
Integration tests for the out-of-process socket introspection API.

These open real sockets on the daemon through 'ClientStack.socket()' and
then list them via 'ClientStack.ss' over the live IPC server, verifying
the 'SocketSnapshot' tuple (with its 'FsmState' enum) round-trips and the
filters select correctly — the out-of-process 'ss' surface.

pytcp/tests/integration/ipc/test__ipc__control__socket_introspect.py

ver 3.0.8
"""

from typing import cast

from pytcp.client import ClientTcpSocket, ClientUdpSocket
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcControlSocketIntrospect(IpcControlTestCase):
    """
    The out-of-process socket introspection integration tests.
    """

    def test__ss__lists_a_listening_tcp_socket(self) -> None:
        """
        Ensure a listening TCP socket opened on the daemon is reported by
        'ss' with its address family and LISTEN state, round-tripping the
        snapshot over IPC.

        Reference: RFC 9293 §3.3.2 (LISTEN state).
        """

        client = self._connect()
        sock = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)
        sock.bind(("0.0.0.0", 18020))
        sock.listen(backlog=8)

        listeners = [
            snapshot
            for snapshot in client.ss.list_sockets(socket_type=SocketType.STREAM)
            if snapshot.local_port == 18020
        ]

        self.assertEqual(
            len(listeners),
            1,
            msg="ss must report exactly one TCP socket on the bound listening port.",
        )
        self.assertEqual(
            (listeners[0].address_family, listeners[0].state),
            (AddressFamily.INET4, FsmState.LISTEN),
            msg="The listening TCP snapshot must carry AF_INET and the LISTEN state over IPC.",
        )

    def test__ss__reports_udp_socket_with_no_state(self) -> None:
        """
        Ensure a bound UDP socket is reported by 'ss' with the DGRAM type
        and no FSM state.

        Reference: RFC 768 (UDP — connectionless datagram socket).
        """

        client = self._connect()
        sock = cast(ClientUdpSocket, client.socket(AddressFamily.INET4, SocketType.DGRAM))
        self.addCleanup(sock.close)
        sock.bind(("0.0.0.0", 18022))

        matches = [
            snapshot
            for snapshot in client.ss.list_sockets(socket_type=SocketType.DGRAM)
            if snapshot.local_port == 18022
        ]

        self.assertEqual(
            len(matches),
            1,
            msg="ss must report exactly one UDP socket on the bound port.",
        )
        self.assertEqual(
            (matches[0].socket_type, matches[0].state),
            (SocketType.DGRAM, None),
            msg="The UDP snapshot must carry the DGRAM type and no FSM state.",
        )

    def test__ss__listening_only_includes_the_listener(self) -> None:
        """
        Ensure the listening-only filter includes a listening TCP socket.

        Reference: RFC 9293 §3.3.2 (LISTEN state).
        """

        client = self._connect()
        sock = cast(ClientTcpSocket, client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)
        sock.bind(("0.0.0.0", 18021))
        sock.listen(backlog=8)

        listening_ports = {
            snapshot.local_port
            for snapshot in client.ss.list_sockets(listening_only=True)
            if snapshot.socket_type is SocketType.STREAM
        }

        self.assertIn(
            18021,
            listening_ports,
            msg="The listening-only filter must include the listening TCP socket.",
        )
