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
Integration tests for the ICMPv6 Parameter Problem → TCP demux path.

pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__param_problem__ip6.py

ver 3.0.8
"""

from net_addr import Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6MessageParameterProblem,
    Icmp6ParameterProblemCode,
    Ip6Assembler,
    TcpAssembler,
)
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip6Address = STACK__IP6_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip6Address = HOST_A__IP6_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000


def _build_icmp6_parameter_problem_frame(
    *,
    code: Icmp6ParameterProblemCode,
    pointer: int,
    embedded_seq: int,
) -> bytes:
    """
    Build an Ethernet/IPv6/ICMPv6 Parameter Problem frame whose
    embedded data is an IPv6+TCP SYN segment for the
    (STACK → PEER) flow with seq=embedded_seq.
    """

    embedded_tcp = bytes(
        Ip6Assembler(
            ip6__src=STACK__IP,
            ip6__dst=PEER__IP,
            ip6__payload=TcpAssembler(
                tcp__sport=STACK__PORT,
                tcp__dport=PEER__PORT,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )
    icmp = Icmp6Assembler(
        icmp6__message=Icmp6MessageParameterProblem(
            code=code,
            pointer=pointer,
            data=embedded_tcp,
        ),
    )
    ip6 = bytes(
        Ip6Assembler(
            ip6__src=PEER__IP,
            ip6__dst=STACK__IP,
            ip6__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd" + ip6


class TestTcpOnParameterProblemIp6(TcpTestCase):
    """
    Integration tests for the ICMPv6 Parameter Problem → TCP demux
    path.
    """

    def _make_syn_sent_session(self) -> TcpSession:
        """
        Build a SYN_SENT-state IPv6 session.
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET6)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        assert session.state is FsmState.SYN_SENT
        return session

    def test__icmp6__parameter_problem__no_fsm_transition(self) -> None:
        """
        Ensure an ICMPv6 Parameter Problem matching a SYN_SENT session
        is recorded as a diagnostic but does NOT abort the connection
        or transition the FSM.

        Reference: RFC 4443 §3.4 (Parameter Problem soft-error semantics).
        Reference: RFC 5927 §6 (Parameter Problem MUST NOT cause connection abort).
        """

        session = self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp6_parameter_problem_frame(
                code=Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
                pointer=40,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="Parameter Problem must NOT mutate the connection-error state.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Parameter Problem must NOT transition the session FSM.",
        )

    def test__icmp6__parameter_problem__bumps_tcp_notify_counter(self) -> None:
        """
        Ensure an in-window ICMPv6 Parameter Problem matched to an
        active session bumps the v6 tcp__notify counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp6_parameter_problem_frame(
                code=Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
                pointer=40,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp6__parameter_problem__tcp__notify,
            1,
            msg="In-window Parameter Problem must bump the v6 tcp__notify counter.",
        )

    def test__icmp6__parameter_problem__seq_out_of_window__drops(self) -> None:
        """
        Ensure that an out-of-window embedded sequence number causes
        the acceptability guard to drop the message.

        Reference: RFC 5927 §4 (off-path attacker sequence-in-window guard).
        """

        self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp6_parameter_problem_frame(
                code=Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
                pointer=40,
                embedded_seq=LOCAL__ISS + 0x10_0000,
            )
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp6__parameter_problem__tcp__seq_out_of_window__drop,
            1,
            msg="Out-of-window Parameter Problem must bump the seq_out_of_window counter.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp6__parameter_problem__tcp__notify,
            0,
            msg="Out-of-window Parameter Problem must NOT reach the session-level notify path.",
        )
