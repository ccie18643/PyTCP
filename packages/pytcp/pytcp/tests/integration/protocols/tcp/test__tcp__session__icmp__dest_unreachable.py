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
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
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
Integration tests for the ICMP Destination Unreachable → TCP demux
path added in Phase 5 of the ICMP demux + PMTUD refactor. Drives
a SYN_SENT-state session through:
  * RFC 5927 §4 sequence-in-window guard.
  * Per-code routing (Net / Host / Port).
  * ConnError surfacing on TcpSession.

pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__dest_unreachable.py

ver 3.0.9
"""

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
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


def _build_icmp4_unreachable_frame(*, code: Icmp4DestinationUnreachableCode, embedded_seq: int) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Destination Unreachable frame whose
    embedded data is an IPv4+TCP SYN segment for the
    (PEER → STACK : PEER__PORT → STACK__PORT) flow with seq=embedded_seq.
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
        icmp4__message=Icmp4MessageDestinationUnreachable(
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


class TestTcpOnUnreachable(TcpTestCase):
    """
    Integration tests for the ICMP Destination Unreachable → TCP
    demux path.
    """

    def _make_syn_sent_session(self) -> TcpSession:
        """
        Build a SYN_SENT-state session: open the active connect
        and let the SYN go on the wire.
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

    def test__icmp4__port_unreachable__on_syn_sent__refused_and_closed(self) -> None:
        """
        Ensure an ICMPv4 Port Unreachable matching a SYN_SENT
        session sets ConnError.REFUSED and transitions the FSM to
        CLOSED, releasing the blocked CONNECT caller.

        Reference: RFC 9293 §3.10.7.3 (RST in SYN-SENT triggers connection refused).
        """

        session = self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.PORT,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg="Port Unreachable on SYN_SENT must surface ConnError.REFUSED.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="Port Unreachable on SYN_SENT must transition the session to CLOSED.",
        )

    def test__icmp4__host_unreachable__sets_host_unreachable_error(self) -> None:
        """
        Ensure an ICMPv4 Host Unreachable surfaces
        ConnError.HOST_UNREACHABLE without altering the FSM state —
        ICMP errors are advisory.

        Reference: RFC 1122 §4.2.3.9 (TCP MUST react to ICMP).
        """

        session = self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.HOST,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.HOST_UNREACHABLE,
            msg="Host Unreachable must surface ConnError.HOST_UNREACHABLE.",
        )

    def test__icmp4__net_unreachable__sets_net_unreachable_error(self) -> None:
        """
        Ensure an ICMPv4 Net Unreachable surfaces
        ConnError.NET_UNREACHABLE.

        Reference: RFC 1122 §4.2.3.9 (TCP MUST react to ICMP).
        """

        session = self._make_syn_sent_session()

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.NETWORK,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.NET_UNREACHABLE,
            msg="Net Unreachable must surface ConnError.NET_UNREACHABLE.",
        )

    def test__icmp4__seq_out_of_window__drops(self) -> None:
        """
        Ensure an ICMPv4 error whose embedded TCP seq does not lie
        in SND.UNA..SND.NXT is silently dropped. The session's
        connection_error must remain NONE and the matching counter
        must bump.

        Reference: RFC 5927 §4 (sequence-in-window check).
        """

        session = self._make_syn_sent_session()
        before = self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__tcp__seq_out_of_window__drop

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.PORT,
                embedded_seq=LOCAL__ISS + 0x4000_0000,
            )
        )

        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="Out-of-window ICMP error must NOT surface a connection error.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__tcp__seq_out_of_window__drop,
            before + 1,
            msg="Out-of-window ICMP error must bump the seq-out-of-window drop counter.",
        )

    def test__icmp4__bumps_tcp_notify_counter(self) -> None:
        """
        Ensure a successful ICMPv4 → TCP demux bumps the
        'icmp4__destination_unreachable__tcp__notify' counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._make_syn_sent_session()
        before = self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__tcp__notify

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.PORT,
                embedded_seq=LOCAL__ISS,
            )
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__destination_unreachable__tcp__notify,
            before + 1,
            msg="Successful ICMP→TCP demux must bump the 'tcp__notify' counter.",
        )
