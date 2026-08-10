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
This module contains integration tests for the RFC 9293 §3.9.1
STATUS user/TCP interface call: 'TcpSocket.status()' returns a
read-only snapshot of the connection's internal state suitable
for diagnostics.

Reference RFC:
    RFC 9293 §3.9.1   User/TCP Interface (STATUS)

pytcp/tests/integration/protocols/tcp/test__tcp__session__status_api.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpStatusApi(TcpTestCase):
    """
    Integration tests for 'TcpSocket.status()' per RFC 9293
    §3.9.1 STATUS user/TCP interface.
    """

    def test__status__fresh_socket_returns_state_closed(self) -> None:
        """
        Ensure a fresh TcpSocket with no associated session
        returns 'TcpStatus(state=CLOSED)' from status() without
        raising.

        Reference: RFC 9293 §3.9.1 (STATUS on non-bound endpoint).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        status = sock.status()

        self.assertIs(
            status.state,
            FsmState.CLOSED,
            msg=(
                "Fresh socket: status().state MUST be FsmState.CLOSED "
                "per RFC 9293 §3.9.1 STATUS on a non-bound endpoint."
            ),
        )

    def test__status__established_socket_returns_handshake_seq_numbers(self) -> None:
        """
        Ensure status() on an ESTABLISHED socket returns the
        canonical post-handshake sequence numbers and addresses.

        Reference: RFC 9293 §3.9.1 (STATUS user call).
        Reference: RFC 9293 §3.4 (SND/RCV state).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        status = sock.status()

        self.assertIs(status.state, FsmState.ESTABLISHED)
        self.assertEqual(status.local_address, STACK__IP)
        self.assertEqual(status.local_port, STACK__PORT)
        self.assertEqual(status.remote_address, PEER__IP)
        self.assertEqual(status.remote_port, PEER__PORT)
        self.assertEqual(
            status.snd_una,
            LOCAL__ISS + 1,
            msg=f"snd_una MUST be ISS+1 post-handshake. Got {status.snd_una}.",
        )
        self.assertEqual(
            status.snd_nxt,
            LOCAL__ISS + 1,
            msg=f"snd_nxt MUST be ISS+1 post-handshake (no data sent). Got {status.snd_nxt}.",
        )
        self.assertEqual(
            status.rcv_nxt,
            PEER__ISS + 1,
            msg=f"rcv_nxt MUST be peer_ISS+1 post-handshake. Got {status.rcv_nxt}.",
        )
        self.assertEqual(
            status.snd_wnd,
            PEER__WIN,
            msg=f"snd_wnd MUST equal peer's advertised window. Got {status.snd_wnd}.",
        )
        self.assertEqual(
            status.tx_buffer_len,
            0,
            msg="tx_buffer_len MUST be 0 (no data sent).",
        )
        self.assertEqual(
            status.rx_buffer_len,
            0,
            msg="rx_buffer_len MUST be 0 (no data received).",
        )

    def test__status__reflects_current_buffer_occupancy(self) -> None:
        """
        Ensure status() reflects CURRENT buffer state. Drive
        peer data and assert rx_buffer_len updates.

        Reference: RFC 9293 §3.9.1 (STATUS reports current state).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"hello world",
        )
        self._drive_rx(frame=peer_data)

        status = sock.status()
        self.assertEqual(
            status.rx_buffer_len,
            len(b"hello world"),
            msg=(
                f"rx_buffer_len MUST reflect current buffer occupancy "
                f"({len(b'hello world')}). Got {status.rx_buffer_len}."
            ),
        )
        self.assertEqual(
            status.rcv_nxt,
            PEER__ISS + 1 + len(b"hello world"),
            msg="rcv_nxt MUST advance past received data.",
        )

    def test__status__listening_socket_returns_state_listen(self) -> None:
        """
        Ensure status() on a session in LISTEN state returns
        state=LISTEN. Pins the listening-socket diagnostic
        path.

        Reference: RFC 9293 §3.9.1 (STATUS on LISTEN endpoint).
        """

        from net_addr import Ip4Address as _Ip4Address

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = _Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=_Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)

        status = sock.status()

        self.assertIs(
            status.state,
            FsmState.LISTEN,
            msg=f"Listening socket: status().state MUST be LISTEN. Got {status.state}.",
        )
        self.assertEqual(
            status.local_port,
            STACK__PORT,
            msg="Listening socket's local_port MUST reflect the bind port.",
        )

    def test__status__reflects_state_through_fin_wait_1(self) -> None:
        """
        Ensure status().state tracks the FSM through close():
        ESTABLISHED -> FIN_WAIT_1 after close() + 2 ticks.

        Reference: RFC 9293 §3.9.1 (STATUS user call).
        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        self.assertIs(sock.status().state, FsmState.ESTABLISHED)

        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        self.assertIs(
            sock.status().state,
            FsmState.FIN_WAIT_1,
            msg="status() MUST reflect state transitions through close().",
        )

    def test__status__reflects_wscale_post_handshake(self) -> None:
        """
        Ensure status().rcv_wsc / .snd_wsc reflect the bilateral
        WSCALE negotiation result. PyTCP advertises rcv_wsc=7 by
        default; if peer's SYN+ACK echoes WSCALE the snd_wsc is
        set to peer's value.

        Reference: RFC 9293 §3.9.1 (STATUS user call).
        Reference: RFC 7323 §2 (WSCALE bilateral negotiation).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=8,
        )
        self._drive_rx(frame=peer_syn_ack)

        status = sock.status()
        self.assertEqual(
            status.snd_wsc,
            8,
            msg=f"snd_wsc MUST reflect peer's wscale (8). Got {status.snd_wsc}.",
        )
        self.assertEqual(
            status.rcv_wsc,
            7,
            msg=f"rcv_wsc MUST reflect our advertised wscale (7). Got {status.rcv_wsc}.",
        )

    def test__status__after_close_completes_returns_state_closed(self) -> None:
        """
        Ensure status() on a fully-closed session (post-LAST_ACK
        / TIME_WAIT expiry) reflects state=CLOSED.

        Reference: RFC 9293 §3.9.1 (STATUS on CLOSED endpoint).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        # Force-transition to CLOSED (simpler than driving the
        # full TIME_WAIT timeout).
        session._change_state(FsmState.CLOSED)

        status = sock.status()
        self.assertIs(
            status.state,
            FsmState.CLOSED,
            msg="status().state MUST be CLOSED after the FSM transitions to CLOSED.",
        )
