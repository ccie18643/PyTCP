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
This module contains integration tests for per-socket DSCP marking on
outbound TCP segments: a socket IP_TOS / IPV6_TCLASS option threads its
DSCP (high 6 bits) onto every emitted segment's IP header, while the
ECN (low 2 bits) stays RFC-3168 stack-driven.

pytcp/tests/integration/protocols/tcp/test__tcp__session__ip_dscp.py

ver 3.0.8
"""

from typing import cast

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import (
    IP_TOS,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_TCLASS,
    AddressFamily,
)
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.tcp_segment_factory import build_tcp4, build_tcp6
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__PORT: int = 12345
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000
PEER__WIN: int = 64240

# DSCP 46 (Expedited Forwarding) — a recognizable, non-zero value.
_DSCP: int = 46


class TestTcpIpDscp(TcpTestCase):
    """
    Integration tests for per-socket DSCP marking on outbound TCP.
    """

    def test__tcp__ip_tos_dscp__marks_outbound_ipv4_segments(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IP, IP_TOS, dscp<<2)' marks the DSCP
        on the outbound IPv4 SYN and on a subsequent data segment.

        Reference: RFC 2474 §3 (DS field — DSCP marking on transmit).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)
        sock.setsockopt(IPPROTO_IP, IP_TOS, _DSCP << 2)

        # Active-open SYN.
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        syn = self._parse_tx(self._frames_tx[0])
        self.assertIn("SYN", syn.flags, msg="First outbound segment must be the SYN.")
        self.assertEqual(
            syn.ip_dscp,
            _DSCP,
            msg="setsockopt(IP_TOS) DSCP must mark the outbound IPv4 SYN's header.",
        )

        # Complete the handshake.
        peer_syn_ack = build_tcp4(
            src_ip=cast(Ip4Address, session._remote_ip_address),
            dst_ip=cast(Ip4Address, session._local_ip_address),
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED

        # Data segment.
        before = len(self._frames_tx)
        session.send(data=b"hello")
        self._advance(ms=1)
        data_segs = [self._parse_tx(f) for f in self._frames_tx[before:] if self._parse_tx(f).payload]
        self.assertGreaterEqual(len(data_segs), 1, msg="A data segment must be emitted.")
        self.assertEqual(
            data_segs[0].ip_dscp,
            _DSCP,
            msg="setsockopt(IP_TOS) DSCP must mark outbound IPv4 data segments.",
        )

    def test__tcp__ipv6_tclass_dscp__marks_outbound_ipv6_segments(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IPV6, IPV6_TCLASS, dscp<<2)' marks
        the DSCP on the outbound IPv6 SYN and on a subsequent data
        segment.

        Reference: RFC 2474 §3 (DS field — DSCP marking on transmit).
        """

        session = self._make_active_session(iss=LOCAL__ISS, family=AddressFamily.INET6)
        sock = session._socket
        assert isinstance(sock, TcpSocket)
        sock.setsockopt(IPPROTO_IPV6, IPV6_TCLASS, _DSCP << 2)

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        syn = self._parse_tx(self._frames_tx[0])
        self.assertIn("SYN", syn.flags, msg="First outbound segment must be the SYN.")
        self.assertEqual(
            syn.ip_dscp,
            _DSCP,
            msg="setsockopt(IPV6_TCLASS) DSCP must mark the outbound IPv6 SYN's header.",
        )

        peer_syn_ack = build_tcp6(
            src_ip=cast(Ip6Address, session._remote_ip_address),
            dst_ip=cast(Ip6Address, session._local_ip_address),
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED

        before = len(self._frames_tx)
        session.send(data=b"hello")
        self._advance(ms=1)
        data_segs = [self._parse_tx(f) for f in self._frames_tx[before:] if self._parse_tx(f).payload]
        self.assertGreaterEqual(len(data_segs), 1, msg="A data segment must be emitted.")
        self.assertEqual(
            data_segs[0].ip_dscp,
            _DSCP,
            msg="setsockopt(IPV6_TCLASS) DSCP must mark outbound IPv6 data segments.",
        )
