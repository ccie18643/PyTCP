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
This module contains integration tests for the SO_REUSEPORT cohort
demux on the inbound TCP path: several listening sockets bound to the
identical (ip, port) form a cohort, and inbound SYNs round-robin
across them (one connection lands on one listener). The round-robin
selection lives transparently in 'SocketTable.get'; this file pins
the end-to-end behaviour through the real RX handler.

pytcp/tests/integration/protocols/tcp/test__tcp__session__reuseport_cohort.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 80

# Fixed listen-side ISS (patched onto every session via
# '_force_iss', so each forked child shares it and third-leg ACKs
# can carry a single 'ack=LOCAL__ISS + 1').
LOCAL__ISS: int = 0x0000_3000

# Peer's advertised receive window / MSS on its SYN.
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpReusePortCohort(TcpTestCase):
    """
    Integration tests for the SO_REUSEPORT listener-cohort demux.
    """

    def _make_cohort(self, *, size: int) -> list[TcpSocket]:
        """
        Build 'size' SO_REUSEPORT listening sockets, all bound to the
        identical (STACK__IP, LISTEN__PORT) listen 4-tuple and
        registered into the shared cohort via 'stack.sockets.register'.
        Each is driven into LISTEN, ready for '_tcp_fsm_listen' to fork
        a child per inbound SYN.
        """

        self._force_iss(LOCAL__ISS)
        listeners: list[TcpSocket] = []
        for _ in range(size):
            sock = TcpSocket(family=AddressFamily.INET4)
            sock._so_reuseport = True
            sock._local_ip_address = STACK__IP
            sock._local_port = LISTEN__PORT
            sock._remote_ip_address = Ip4Address()
            sock._remote_port = 0
            session = TcpSession(
                local_ip_address=STACK__IP,
                local_port=LISTEN__PORT,
                remote_ip_address=Ip4Address(),
                remote_port=0,
                socket=sock,
            )
            sock._tcp_session = session
            stack.sockets.register(sock)
            session.tcp_fsm(syscall=SysCall.LISTEN)
            listeners.append(sock)
        return listeners

    def _complete_handshake(self, *, peer_port: int, peer_iss: int) -> None:
        """
        Complete a passive handshake for a peer: the SYN forks a child
        on the round-robin-selected listener; '_advance' fires the
        child's SYN+ACK; the third-leg ACK drives the child to
        ESTABLISHED, appending it to its parent listener's accept
        queue.
        """

        self._drive_rx(
            frame=build_tcp4(
                sport=peer_port,
                dport=LISTEN__PORT,
                seq=peer_iss,
                ack=0,
                flags=("SYN",),
                win=PEER__WIN,
                mss=PEER__MSS,
            )
        )
        self._advance(ms=1)
        self._drive_rx(
            frame=build_tcp4(
                sport=peer_port,
                dport=LISTEN__PORT,
                seq=peer_iss + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
        )

    def test__reuseport__syns_round_robin_one_child_per_listener(self) -> None:
        """
        Ensure four inbound SYNs to a four-member SO_REUSEPORT cohort
        each land on a distinct listener — round-robin distribution —
        so every listener accepts exactly one connection.

        Reference: socket(7) SO_REUSEPORT (load-balanced demux).
        """

        listeners = self._make_cohort(size=4)
        peers = [
            (33000, 0x0000_4000),
            (33001, 0x0000_4100),
            (33002, 0x0000_4200),
            (33003, 0x0000_4300),
        ]

        for peer_port, peer_iss in peers:
            self._complete_handshake(peer_port=peer_port, peer_iss=peer_iss)

        for index, listener in enumerate(listeners):
            self.assertEqual(
                len(listener._tcp_accept),
                1,
                msg=(
                    f"Listener {index} must accept exactly one connection — "
                    "the cohort demux must spread four SYNs one-per-listener."
                ),
            )

    def test__reuseport__fifth_syn_wraps_to_first_listener(self) -> None:
        """
        Ensure a fifth SYN into a four-member cohort wraps the
        round-robin cursor back to the first listener, which then
        accepts a second connection while the others still hold one.

        Reference: socket(7) SO_REUSEPORT (load-balanced demux).
        """

        listeners = self._make_cohort(size=4)
        peers = [
            (33000, 0x0000_4000),
            (33001, 0x0000_4100),
            (33002, 0x0000_4200),
            (33003, 0x0000_4300),
            (33004, 0x0000_4400),
        ]

        for peer_port, peer_iss in peers:
            self._complete_handshake(peer_port=peer_port, peer_iss=peer_iss)

        self.assertEqual(
            [len(listener._tcp_accept) for listener in listeners],
            [2, 1, 1, 1],
            msg=(
                "The fifth SYN must wrap to the first listener, giving it "
                "two accepted connections and the rest one each."
            ),
        )

    def test__reuseport__retransmitted_syn_stays_on_same_child(self) -> None:
        """
        Ensure a retransmitted SYN (same 4-tuple) routes to the
        already-forked child via the exact-5-tuple active match rather
        than re-entering the cohort demux — so it never forks a second
        half-open connection on a different listener.

        Reference: RFC 9293 §3.10.7.4 (SYN to an existing connection);
        socket(7) SO_REUSEPORT.
        """

        self._make_cohort(size=4)

        # One SYN forks exactly one child (registered under its full
        # 5-tuple in SYN-RCVD). The registry then holds two ids: the
        # shared listening cohort and the one child.
        syn = build_tcp4(
            sport=33000,
            dport=LISTEN__PORT,
            seq=0x0000_4000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=syn)
        self.assertEqual(
            len(stack.sockets),
            2,
            msg="One SYN must register exactly one child id beside the listening cohort.",
        )

        # Retransmit the identical SYN. The exact-5-tuple match must
        # route it to the existing SYN-RCVD child — no second child id.
        self._drive_rx(frame=syn)
        self.assertEqual(
            len(stack.sockets),
            2,
            msg=(
                "A retransmitted SYN must hit the exact-match child, not the "
                "cohort demux — it must not fork a second child on another listener."
            ),
        )
