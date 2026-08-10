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
This module contains unit tests for the 'TcpRxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__tcp__rx.py

ver 3.0.10
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address
from net_proto import Ip4Assembler, Ip4Parser, TcpAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__tcp__rx import TcpRxHandler

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the RX-stat counters, the TX marshal seam, and the
    '_phtx_tcp' entry the TCP RX sub-handler reaches through 'self._if'
    to emit a RST to an unmatched segment, recording each call. A
    purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self.tcp_tx_calls: list[dict[str, object]] = []

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # RST replies marshal '_phtx_tcp' through '_marshal_tx'; with no
        # TX worker under test, run the callable inline so the recorded
        # '_phtx_tcp' call still fires.
        return run()

    def _phtx_tcp(self, **kwargs: object) -> TxStatus:
        self.tcp_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _packet_rx_from_ip4_tcp(
    *,
    src: Ip4Address = HOST_A__IP4,
    dst: Ip4Address = STACK__IP4_ADDRESS,
    sport: int = 12345,
    dport: int = 80,
    flag_syn: bool = False,
    flag_ack: bool = False,
    flag_rst: bool = False,
    flag_fin: bool = False,
    seq: int = 0,
    ack: int = 0,
    payload: bytes = b"",
) -> PacketRx:
    """
    Build a 'PacketRx' parsed through Ip4Parser with a TCP segment
    payload matching the provided header fields.
    """

    tcp = TcpAssembler(
        tcp__sport=sport,
        tcp__dport=dport,
        tcp__seq=seq,
        tcp__ack=ack,
        tcp__flag_syn=flag_syn,
        tcp__flag_ack=flag_ack,
        tcp__flag_rst=flag_rst,
        tcp__flag_fin=flag_fin,
        tcp__payload=payload,
    )
    frame = bytes(Ip4Assembler(ip4__src=src, ip4__dst=dst, ip4__payload=tcp))
    packet_rx = PacketRx(frame)
    Ip4Parser(packet_rx)
    return packet_rx


class _TcpRxTestBase(TestCase):
    """
    Common setUp for the TCP RX tests.
    """

    @override
    def setUp(self) -> None:
        self._if = _StubInterface()
        self._tcp_rx = TcpRxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", self._if))
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()

    @override
    def tearDown(self) -> None:
        self._sockets_patch.stop()


class TestPacketHandlerTcpRxParse(_TcpRxTestBase):
    """
    The parse-failure tests.
    """

    def test__stack__packet_handler__tcp__rx__parse_fail_drops(self) -> None:
        """
        Ensure a TCP segment with a corrupt checksum is counted in
        'tcp__failed_parse__drop'.

        Reference: RFC 9293 §3.10 (TCP RX segment processing).
        """

        # Build a valid IP+TCP frame then corrupt the TCP cksum field.
        frame = bytearray(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=TcpAssembler(tcp__sport=12345, tcp__dport=80),
            )
        )
        # TCP cksum is at offset IP4_header_len + 16. Minimum IP header is 20.
        frame[20 + 16] = 0xDE
        frame[20 + 17] = 0xAD

        packet_rx = PacketRx(bytes(frame))
        Ip4Parser(packet_rx)
        self._tcp_rx._phrx_tcp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.tcp__pre_parse,
            1,
            msg="tcp__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.tcp__failed_parse__drop,
            1,
            msg="Malformed TCP must be counted in tcp__failed_parse__drop.",
        )


class TestPacketHandlerTcpRxDispatch(_TcpRxTestBase):
    """
    The socket-match and RST-response tests.
    """

    def test__stack__packet_handler__tcp__rx__active_socket_match_forwards(self) -> None:
        """
        Ensure a TCP segment matching an active socket is forwarded to
        the socket's 'process_tcp_packet'.

        Reference: RFC 9293 §3.10 (TCP RX segment processing).
        """

        fake_socket = MagicMock()

        class _MatchAllDict(dict[object, object]):
            @override
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", _MatchAllDict())
        self._sockets_patch.start()

        packet_rx = _packet_rx_from_ip4_tcp(flag_ack=True, payload=b"x")
        self._tcp_rx._phrx_tcp(packet_rx)

        fake_socket.process_tcp_packet.assert_called_once()
        self.assertEqual(
            self._if._packet_stats_rx.tcp__socket_match_active__forward_to_socket,
            1,
            msg="Active-socket forward must increment tcp__socket_match_active__forward_to_socket.",
        )
        self.assertEqual(
            self._if.tcp_tx_calls,
            [],
            msg="Active-socket forward must not send any RST.",
        )

    def test__stack__packet_handler__tcp__rx__rst_no_match_silently_dropped(self) -> None:
        """
        Ensure a TCP RST that doesn't match any socket is silently
        dropped and no RST is sent back (would be an amplification).

        Reference: RFC 9293 §3.10 (TCP RX segment processing).
        """

        packet_rx = _packet_rx_from_ip4_tcp(flag_rst=True, flag_ack=True)
        self._tcp_rx._phrx_tcp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.tcp__no_socket_match__rst__drop,
            1,
            msg="Unmatched RST must be counted in tcp__no_socket_match__rst__drop.",
        )
        self.assertEqual(
            self._if.tcp_tx_calls,
            [],
            msg="Unmatched RST must NOT trigger a reply.",
        )

    def test__stack__packet_handler__tcp__rx__no_match_ack_less_sends_rst_ack(self) -> None:
        """
        Ensure an ACK-LESS TCP segment that matches no socket elicits
        a 'RST+ACK' reply: '<SEQ=0> <ACK=SEG.SEQ+SEG.LEN>
        <CTL=RST,ACK>'. The 'SEG.LEN' term covers SYN, FIN, and the
        payload length, so an ACK-less segment with seq=100 and
        payload b"hi" (2 bytes) yields ACK=102.

        Reference: RFC 9293 §3.10.7.1 (no-socket-match RST+ACK reply).
        """

        packet_rx = _packet_rx_from_ip4_tcp(flag_syn=True, seq=100, payload=b"hi")
        self._tcp_rx._phrx_tcp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.tcp__no_socket_match__respond_rst,
            1,
            msg="Unmatched non-RST segment must be counted in tcp__no_socket_match__respond_rst.",
        )
        self.assertEqual(len(self._if.tcp_tx_calls), 1)
        call = self._if.tcp_tx_calls[0]
        self.assertEqual(call["ip__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip__dst"], HOST_A__IP4)
        self.assertEqual(call["tcp__sport"], 80)
        self.assertEqual(call["tcp__dport"], 12345)
        self.assertTrue(call["tcp__flag_rst"], msg="RFC 9293 §3.10.7.1 requires RST flag set.")
        self.assertTrue(
            call["tcp__flag_ack"],
            msg="ACK-less offending segment requires the 'RST,ACK' response form per RFC 9293 §3.10.7.1.",
        )
        self.assertEqual(call["tcp__seq"], 0, msg="RFC 9293 §3.10.7.1 ACK-less form: '<SEQ=0>'.")
        self.assertEqual(
            call["tcp__ack"],
            103,
            msg=(
                "RFC 9293 §3.10.7.1 ACK-less form: ACK = SEG.SEQ + " "SEG.LEN (100 + 1 SYN + 0 FIN + 2 payload = 103)."
            ),
        )

    def test__stack__packet_handler__tcp__rx__no_match_ack_bearing_sends_bare_rst(self) -> None:
        """
        Ensure an ACK-BEARING TCP segment that matches no socket
        elicits a bare 'RST' reply: '<SEQ=SEG.ACK><CTL=RST>' - the
        ACK flag is intentionally NOT set on the response, and the
        response's SEQ echoes the offending segment's ACK so the
        sender's acceptability check accepts the RST.

        Reference: RFC 9293 §3.10.7.1 (no-socket-match bare-RST reply).
        """

        packet_rx = _packet_rx_from_ip4_tcp(flag_ack=True, seq=100, ack=0xCAFE, payload=b"hi")
        self._tcp_rx._phrx_tcp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.tcp__no_socket_match__respond_rst,
            1,
            msg="Unmatched non-RST segment must be counted in tcp__no_socket_match__respond_rst.",
        )
        self.assertEqual(len(self._if.tcp_tx_calls), 1)
        call = self._if.tcp_tx_calls[0]
        self.assertEqual(call["ip__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip__dst"], HOST_A__IP4)
        self.assertEqual(call["tcp__sport"], 80)
        self.assertEqual(call["tcp__dport"], 12345)
        self.assertTrue(call["tcp__flag_rst"], msg="RFC 9293 §3.10.7.1 requires RST flag set.")
        self.assertFalse(
            call["tcp__flag_ack"],
            msg=(
                "ACK-bearing offending segment requires the bare 'RST' "
                "response form (no ACK flag) per RFC 9293 §3.10.7.1."
            ),
        )
        self.assertEqual(
            call["tcp__seq"],
            0xCAFE,
            msg="RFC 9293 §3.10.7.1 ACK-bearing form: '<SEQ=SEG.ACK>' echoes the offending segment's ACK number.",
        )
        self.assertEqual(call["tcp__ack"], 0, msg="Bare RST carries no ACK number.")


class TestPacketHandlerTcpRxDualStack(_TcpRxTestBase):
    """
    H3 Phase 3b dual-stack listener dispatch tests — an IPv4 SYN
    must find an AF_INET6 'V6ONLY = 0' listener bound to '::' but
    skip a 'V6ONLY = 1' listener on the same key.
    """

    def _install_dual_stack_listener(self, *, v6only: bool) -> MagicMock:
        """
        Stage a mock socket at the AF_INET6 wildcard listening
        key — the 3rd entry in 'listening_socket_ids' for an
        IPv4 inbound on STACK port 80.
        """

        from net_addr import Ip6Address
        from pytcp.runtime.socket import AddressFamily, SocketType
        from pytcp.runtime.socket.socket_id import SocketId

        key = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=Ip6Address(),
            local_port=80,
            remote_address=Ip6Address(),
            remote_port=0,
        )
        socket = MagicMock()
        socket.address_family = AddressFamily.INET6
        socket.ipv6_v6only = v6only
        cast(dict[object, object], stack.sockets)[key] = socket
        return socket

    def test__tcp_rx__ipv4_syn_dispatches_to_af_inet6_v6only_off_listener(self) -> None:
        """
        Ensure an IPv4 inbound SYN with no matching AF_INET
        listener finds an AF_INET6 'V6ONLY = 0' listener via the
        wildcard pattern and dispatches to it — the canonical
        Linux dual-stack accept flow.

        Reference: Linux IPV6_V6ONLY = 0 (dual-stack accept).
        """

        socket = self._install_dual_stack_listener(v6only=False)
        packet_rx = _packet_rx_from_ip4_tcp(flag_syn=True)
        self._tcp_rx._phrx_tcp(packet_rx)

        socket.process_tcp_packet.assert_called_once()
        self.assertEqual(
            self._if._packet_stats_rx.tcp__socket_match_listening__forward_to_socket,
            1,
            msg="Dual-stack match must increment tcp__socket_match_listening__forward_to_socket.",
        )

    def test__tcp_rx__ipv4_syn_skips_af_inet6_v6only_on_listener(self) -> None:
        """
        Ensure an IPv4 inbound SYN whose only candidate match is
        an AF_INET6 'V6ONLY = 1' listener is NOT dispatched —
        the strict-IPv6 listener keeps its single-family
        namespace and the unmatched SYN falls through to the
        no-listener drop path (no-socket-match RST-ACK).

        Reference: Linux IPV6_V6ONLY = 1 (strict-IPv6 namespace).
        """

        socket = self._install_dual_stack_listener(v6only=True)
        packet_rx = _packet_rx_from_ip4_tcp(flag_syn=True)
        self._tcp_rx._phrx_tcp(packet_rx)

        socket.process_tcp_packet.assert_not_called()
        self.assertEqual(
            self._if._packet_stats_rx.tcp__socket_match_listening__forward_to_socket,
            0,
            msg="V6ONLY=1 listener must NOT match an IPv4 SYN.",
        )
        # The SYN with no listener match elicits a SYN-RST-ACK reply
        # via the canonical no-socket-match path — confirm via the
        # 'tcp__no_socket_match__respond_rst' stat to pin the
        # fall-through behaviour.
        self.assertEqual(
            self._if._packet_stats_rx.tcp__no_socket_match__respond_rst,
            1,
            msg="A SYN with no listener match must fall through to the no-match RST path.",
        )
