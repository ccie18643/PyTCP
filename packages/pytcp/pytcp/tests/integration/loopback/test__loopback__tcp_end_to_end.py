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
End-to-end TCP handshake integration tests over the loopback interface.

pytcp/tests/integration/loopback/test__loopback__tcp_end_to_end.py

ver 3.0.10
"""

from typing import cast, override

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.socket_id import SocketId
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import STACK__IP4_HOST
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOOPBACK_IP = Ip4Address("127.0.0.1")
_OWN_IP = STACK__IP4_HOST.address  # 10.0.1.7 — the host's own routable address

_LISTEN_PORT = 80
_CLIENT_PORT = 49152
_SERVER_ISS = 0x0000_3000
_CLIENT_ISS = 0x0000_4000
_PUMP_MAX_CYCLES = 8


class TestLoopbackTcpEndToEnd(TcpTestCase):
    """
    The end-to-end TCP-over-loopback acceptance tests: a listener and a
    client on the same stack complete the three-way handshake with no
    traffic on the wire.
    """

    @override
    def setUp(self) -> None:
        """
        Bring up the boot interface and register a loopback interface.
        """

        super().setUp()
        self._lo = self._register_loopback()

    def _make_listener(self, *, ip: Ip4Address, port: int, iss: int) -> TcpSocket:
        """
        Build a listening 'TcpSocket' bound to '(ip, port)' the way
        'TcpSocket.listen()' would wire it, register it in
        'stack.sockets', and drive it into LISTEN. Returns the socket.
        """

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = ip
        sock._local_port = port
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=ip,
            local_port=port,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def _child_session(self, *, ip: Ip4Address) -> TcpSession | None:
        """
        Resolve the server's forked child session for the connection from
        '(ip, _CLIENT_PORT)' to '(ip, _LISTEN_PORT)', or None if not yet
        spawned.
        """

        child_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=ip,
            local_port=_LISTEN_PORT,
            remote_address=ip,
            remote_port=_CLIENT_PORT,
        )
        child_sock = stack.sockets.get(child_id)
        if child_sock is None:
            return None
        return cast(TcpSocket, child_sock)._tcp_session

    def _pump_loopback(self) -> None:
        """
        Drive the loopback conversation forward: alternate a one-ms timer
        tick (which emits any tick-gated segment — the active-open SYN and
        the passive-open SYN-ACK) with a synchronous ring drain, until the
        conversation quiesces.
        """

        for _ in range(_PUMP_MAX_CYCLES):
            self._advance(ms=1)
            self.drive_loopback(lo=self._lo)

    def test__loopback__tcp_handshake_over_loopback_address(self) -> None:
        """
        Ensure a client connecting to 127.0.0.1 completes the three-way
        handshake against a listener on the same stack entirely over the
        loopback interface — both endpoints reach ESTABLISHED and nothing
        is emitted on the wire.

        Reference: RFC 9293 §3.5 (Connection Establishment).
        """

        listen_sock = self._make_listener(ip=_LOOPBACK_IP, port=_LISTEN_PORT, iss=_SERVER_ISS)

        client = self._make_active_session(
            iss=_CLIENT_ISS,
            local_ip=_LOOPBACK_IP,
            local_port=_CLIENT_PORT,
            remote_ip=_LOOPBACK_IP,
            remote_port=_LISTEN_PORT,
        )
        client.tcp_fsm(syscall=SysCall.CONNECT)

        self._pump_loopback()

        child = self._child_session(ip=_LOOPBACK_IP)
        self.assertIsNotNone(child, msg="The listener must fork a child session for the loopback connection.")
        assert child is not None  # narrowed for mypy
        self.assertIs(client.state, FsmState.ESTABLISHED, msg="The client session must reach ESTABLISHED over lo.")
        self.assertIs(child.state, FsmState.ESTABLISHED, msg="The server child session must reach ESTABLISHED over lo.")
        self.assertEqual(self._frames_tx, [], msg="A loopback handshake must not emit any wire frame.")
        # The listening socket stays registered, ready for more connections.
        self.assertIn(listen_sock.socket_id, stack.sockets, msg="The listening socket must remain registered.")

    def test__loopback__tcp_handshake_over_own_ip(self) -> None:
        """
        Ensure a client connecting to the host's own routable address
        (10.0.1.7) loops internally: the handshake completes against a
        same-stack listener, nothing reaches the wire, and no ARP
        resolution of the host's own address is attempted (the old own-IP
        path dropped on DROPPED__ETHERNET__DST_ARP_CACHE_MISS).

        Reference: RFC 9293 §3.5 (Connection Establishment).
        """

        self._make_listener(ip=_OWN_IP, port=_LISTEN_PORT, iss=_SERVER_ISS)

        client = self._make_active_session(
            iss=_CLIENT_ISS,
            local_ip=_OWN_IP,
            local_port=_CLIENT_PORT,
            remote_ip=_OWN_IP,
            remote_port=_LISTEN_PORT,
        )
        client.tcp_fsm(syscall=SysCall.CONNECT)

        self._pump_loopback()

        child = self._child_session(ip=_OWN_IP)
        self.assertIsNotNone(child, msg="The listener must fork a child session for the own-IP connection.")
        assert child is not None  # narrowed for mypy
        self.assertIs(client.state, FsmState.ESTABLISHED, msg="The client session must reach ESTABLISHED over own-IP.")
        self.assertIs(child.state, FsmState.ESTABLISHED, msg="The server child session must reach ESTABLISHED.")
        self.assertEqual(self._frames_tx, [], msg="An own-IP loop must not emit any wire frame.")
        # No ARP resolution of the host's own address — the diversion
        # bypasses the wire path entirely.
        self._arp_cache.find_entry.assert_not_called()
