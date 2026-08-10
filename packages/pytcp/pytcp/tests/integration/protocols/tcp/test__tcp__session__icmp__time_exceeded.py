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
Integration tests for the ICMP Time Exceeded → TCP demux path.
Time Exceeded is a soft error per RFC 5927 §6 — the session must
record the diagnostic but MUST NOT abort the connection nor mutate
any FSM state.

pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__time_exceeded.py

ver 3.0.9
"""

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageTimeExceeded,
    Icmp4TimeExceededCode,
    Ip4Assembler,
    TcpAssembler,
)
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000


def _build_icmp4_time_exceeded_frame(
    *,
    code: Icmp4TimeExceededCode,
    embedded_seq: int,
) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Time Exceeded frame whose embedded
    data is an IPv4+TCP SYN segment for the
    (STACK → PEER : STACK__PORT → PEER__PORT) flow with seq=embedded_seq.
    """

    embedded_tcp = bytes(
        Ip4Assembler(
            ip4__src=STACK__IP,
            ip4__dst=PEER__IP,
            ip4__payload=TcpAssembler(
                tcp__sport=STACK__PORT,
                tcp__dport=PEER__PORT,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )
    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageTimeExceeded(
            code=code,
            data=embedded_tcp,
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP,
            ip4__dst=STACK__IP,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


class TestTcpOnTimeExceeded(TcpTestCase):
    """
    Integration tests for the ICMP Time Exceeded → TCP demux path.
    """

    def _make_syn_sent_session(self) -> TcpSession:
        """
        Build a SYN_SENT-state session — same pattern as
        test__tcp__session__icmp__dest_unreachable.py.
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
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

    def test__icmp4__time_exceeded__ttl_in_transit__no_fsm_transition(self) -> None:
        """
        Ensure an ICMPv4 Time Exceeded (code 0 — TTL Exceeded in
        Transit) matching a SYN_SENT session is recorded as a
        diagnostic but does NOT abort the connection or transition
        the FSM. Soft-error semantics: existing SYN-RTO timer
        machinery continues to handle the actual recovery.

        Reference: RFC 1122 §3.2.2.4 (Time Exceeded MUST be passed to
        transport layer).
        Reference: RFC 5927 §6 (Time Exceeded is a soft error and
        MUST NOT abort the connection).
        """

        session = self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_time_exceeded_frame(
                code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="Time Exceeded must NOT mutate the connection-error state.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Time Exceeded must NOT transition the session FSM.",
        )

    def test__icmp4__time_exceeded__fragment_reassembly__no_fsm_transition(self) -> None:
        """
        Ensure an ICMPv4 Time Exceeded (code 1 — Fragment Reassembly
        Time Exceeded) matching a SYN_SENT session is recorded as a
        diagnostic but does NOT abort the connection.

        Reference: RFC 1122 §3.2.2.4 (Time Exceeded MUST be passed to
        transport layer).
        Reference: RFC 5927 §6 (Time Exceeded is a soft error).
        """

        session = self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_time_exceeded_frame(
                code=Icmp4TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="Time Exceeded must NOT mutate the connection-error state.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Time Exceeded must NOT transition the session FSM.",
        )

    def test__icmp4__time_exceeded__bumps_tcp_notify_counter(self) -> None:
        """
        Ensure that an in-window Time Exceeded matched to an active
        session bumps the TCP-side notify counter, exposing the event
        for observability.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_time_exceeded_frame(
                code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__time_exceeded__tcp__notify,
            1,
            msg="In-window Time Exceeded must bump the tcp__notify counter.",
        )

    def test__icmp4__time_exceeded__seq_out_of_window__drops(self) -> None:
        """
        Ensure that an out-of-window embedded sequence number causes
        the acceptability guard to drop the message before it reaches
        the TCP session — the seq-out-of-window counter bumps and the
        notify counter does not.

        Reference: RFC 5927 §4 (off-path attacker mitigation —
        sequence-in-window guard).
        """

        self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_time_exceeded_frame(
                code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                embedded_seq=LOCAL__ISS + 0x10_0000,  # well outside the window
            )
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__time_exceeded__tcp__seq_out_of_window__drop,
            1,
            msg="Out-of-window Time Exceeded must bump the seq_out_of_window counter.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__time_exceeded__tcp__notify,
            0,
            msg="Out-of-window Time Exceeded must NOT reach the session-level notify path.",
        )
