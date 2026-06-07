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
This module contains unit tests for the 'UdpRxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__udp__rx.py

ver 3.0.8
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip6Address
from net_proto import (
    Icmp4MessageDestinationUnreachable,
    Icmp6MessageDestinationUnreachable,
    Ip4Assembler,
    Ip4Parser,
    Ip6Assembler,
    Ip6Parser,
    UdpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__udp__rx import UdpRxHandler
from pytcp.runtime.socket.socket_table import SocketTable

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# Snapshot stack globals so 'setUpModule' can silence output and disable
# the UDP echo fastpath for the duration of this module's tests, and
# 'tearDownModule' can restore them.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL
_ORIGINAL_UDP_ECHO_NATIVE: bool = stack.UDP__ECHO_NATIVE


def setUpModule() -> None:
    """
    Silence log output and force UDP__ECHO_NATIVE=False for this
    module's tests. The 'TestPacketHandlerUdpRxEcho' class re-enables
    it per-test via 'unittest.mock.patch'.
    """

    stack.LOG__CHANNEL = set()
    stack.UDP__ECHO_NATIVE = False


def tearDownModule() -> None:
    """
    Restore the snapshots after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL
    stack.UDP__ECHO_NATIVE = _ORIGINAL_UDP_ECHO_NATIVE


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")
IP4__UNSPEC = Ip4Address()
STACK__IP6_ADDRESS = Ip6Address("2001:db8::7")
HOST_A__IP6 = Ip6Address("2001:db8::91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the RX-stat counters, the TX marshal seam, and the
    cross-protocol TX entry points ('_phtx_udp' echo reply,
    '_phtx_icmp4' / '_phtx_icmp6' port-unreachable) the UDP RX
    sub-handler reaches through 'self._if', recording each call for
    assertions. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # Marshaled TX entry points route '_phtx_*' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        return run()

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self._ifindex = 1
        self.udp_tx_calls: list[dict[str, object]] = []
        self.icmp4_tx_calls: list[dict[str, object]] = []
        self.icmp6_tx_calls: list[dict[str, object]] = []

    def _phtx_udp(self, **kwargs: object) -> TxStatus:
        self.udp_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_icmp4(self, **kwargs: object) -> TxStatus:
        self.icmp4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_icmp6(self, **kwargs: object) -> TxStatus:
        self.icmp6_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _packet_rx_from_ip4_udp(
    *,
    src: Ip4Address = HOST_A__IP4,
    dst: Ip4Address = STACK__IP4_ADDRESS,
    sport: int = 12345,
    dport: int = 54321,
    payload: bytes = b"",
) -> PacketRx:
    """
    Build a 'PacketRx' parsed through Ip4Parser carrying a UDP payload.
    """

    udp = UdpAssembler(udp__sport=sport, udp__dport=dport, udp__payload=payload)
    frame = bytes(Ip4Assembler(ip4__src=src, ip4__dst=dst, ip4__payload=udp))
    packet_rx = PacketRx(frame)
    Ip4Parser(packet_rx)
    return packet_rx


def _packet_rx_from_ip6_udp(
    *,
    src: Ip6Address = HOST_A__IP6,
    dst: Ip6Address = STACK__IP6_ADDRESS,
    sport: int = 12345,
    dport: int = 54321,
    payload: bytes = b"",
) -> PacketRx:
    """
    Build a 'PacketRx' parsed through Ip6Parser carrying a UDP payload.
    """

    udp = UdpAssembler(udp__sport=sport, udp__dport=dport, udp__payload=payload)
    frame = bytes(Ip6Assembler(ip6__src=src, ip6__dst=dst, ip6__payload=udp))
    packet_rx = PacketRx(frame)
    Ip6Parser(packet_rx)
    return packet_rx


class _UdpRxTestBase(TestCase):
    """
    Common setUp for the UDP RX tests.
    """

    @override
    def setUp(self) -> None:
        self._if = _StubInterface()
        self._udp_rx = UdpRxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", self._if))
        self._sockets_patch = patch.object(stack, "sockets", SocketTable())
        self._sockets_patch.start()

    @override
    def tearDown(self) -> None:
        self._sockets_patch.stop()


class TestPacketHandlerUdpRxParse(_UdpRxTestBase):
    """
    The parse-failure tests.
    """

    def test__stack__packet_handler__udp__rx__parse_fail_drops(self) -> None:
        """
        Ensure a UDP segment with a bad checksum is counted in
        'udp__failed_parse__drop'.

        Reference: RFC 768 (UDP RX dispatch).
        """

        frame = bytearray(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=UdpAssembler(udp__sport=12345, udp__dport=54321),
            )
        )
        # UDP cksum is at offset IP4_header_len + 6. Minimum IP header is 20.
        frame[20 + 6] = 0xDE
        frame[20 + 7] = 0xAD

        packet_rx = PacketRx(bytes(frame))
        Ip4Parser(packet_rx)
        self._udp_rx._phrx_udp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.udp__pre_parse,
            1,
            msg="udp__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.udp__failed_parse__drop,
            1,
            msg="Malformed UDP must be counted in udp__failed_parse__drop.",
        )


class TestPacketHandlerUdpRxDispatch(_UdpRxTestBase):
    """
    The socket-match and unreachable-response tests.
    """

    def test__stack__packet_handler__udp__rx__socket_match_forwards(self) -> None:
        """
        Ensure a UDP datagram matching a listening socket is forwarded
        to the socket's 'process_udp_packet'.

        Reference: RFC 768 (UDP RX dispatch).
        """

        fake_socket = MagicMock()

        class _MatchAllDict(dict[object, object]):
            @override
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

            def get_for_ingress(self, key: object, *, ifindex: int, default: object = None) -> object:
                del ifindex
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", cast(SocketTable, _MatchAllDict()))
        self._sockets_patch.start()

        packet_rx = _packet_rx_from_ip4_udp(payload=b"hello")
        self._udp_rx._phrx_udp(packet_rx)

        fake_socket.process_udp_packet.assert_called_once()
        self.assertEqual(
            self._if._packet_stats_rx.udp__socket_match,
            1,
            msg="Matched UDP socket must increment udp__socket_match.",
        )
        self.assertEqual(self._if.icmp4_tx_calls, [])

    def test__stack__packet_handler__udp__rx__unspecified_src_silently_dropped(self) -> None:
        """
        Ensure a UDP datagram with an unspecified source IP is silently
        dropped (no ICMP unreachable, no echo, no socket match).

        Reference: RFC 768 (UDP RX dispatch).
        """

        packet_rx = _packet_rx_from_ip4_udp(src=IP4__UNSPEC, payload=b"hi")
        self._udp_rx._phrx_udp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.udp__ip_source_unspecified,
            1,
            msg="Unspecified-src UDP must be counted in udp__ip_source_unspecified.",
        )
        self.assertEqual(self._if.icmp4_tx_calls, [])
        self.assertEqual(self._if.udp_tx_calls, [])

    def test__stack__packet_handler__udp__rx__no_match_ip4_responds_icmp4_unreachable(self) -> None:
        """
        Ensure an IPv4 UDP datagram with no matching socket elicits an
        ICMPv4 Port Unreachable reply with the original IP packet in
        the message data.

        Reference: RFC 768 (UDP RX dispatch).
        """

        packet_rx = _packet_rx_from_ip4_udp(payload=b"hi")
        self._udp_rx._phrx_udp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.udp__no_socket_match__respond_icmp4_unreachable,
            1,
            msg="Unmatched IPv4 UDP must be counted in udp__no_socket_match__respond_icmp4_unreachable.",
        )
        self.assertEqual(len(self._if.icmp4_tx_calls), 1)
        call = self._if.icmp4_tx_calls[0]
        self.assertEqual(call["ip4__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip4__dst"], HOST_A__IP4)
        self.assertIsInstance(call["icmp4__message"], Icmp4MessageDestinationUnreachable)

    def test__stack__packet_handler__udp__rx__no_match_ip6_responds_icmp6_unreachable(self) -> None:
        """
        Ensure an IPv6 UDP datagram with no matching socket elicits an
        ICMPv6 Port Unreachable reply.

        Reference: RFC 768 (UDP RX dispatch).
        """

        packet_rx = _packet_rx_from_ip6_udp(payload=b"hi")
        self._udp_rx._phrx_udp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.udp__no_socket_match__respond_icmp6_unreachable,
            1,
            msg="Unmatched IPv6 UDP must be counted in udp__no_socket_match__respond_icmp6_unreachable.",
        )
        self.assertEqual(len(self._if.icmp6_tx_calls), 1)
        call = self._if.icmp6_tx_calls[0]
        self.assertEqual(call["ip6__src"], STACK__IP6_ADDRESS)
        self.assertEqual(call["ip6__dst"], HOST_A__IP6)
        self.assertIsInstance(call["icmp6__message"], Icmp6MessageDestinationUnreachable)


class TestPacketHandlerUdpRxEcho(_UdpRxTestBase):
    """
    The UDP Echo (port 7) native-reply tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._echo_patch = patch.object(stack, "UDP__ECHO_NATIVE", True)
        self._echo_patch.start()

    @override
    def tearDown(self) -> None:
        self._echo_patch.stop()
        super().tearDown()

    def test__stack__packet_handler__udp__rx__echo_port_7_responds_udp_echo(self) -> None:
        """
        Ensure a UDP datagram to port 7 with UDP__ECHO_NATIVE=True
        triggers a native UDP echo reply back to the sender.

        Reference: RFC 768 (UDP RX dispatch).
        """

        packet_rx = _packet_rx_from_ip4_udp(sport=54321, dport=7, payload=b"echo")
        self._udp_rx._phrx_udp(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.udp__echo_native__respond_udp,
            1,
            msg="UDP echo port 7 must be counted in udp__echo_native__respond_udp.",
        )
        self.assertEqual(len(self._if.udp_tx_calls), 1)
        call = self._if.udp_tx_calls[0]
        self.assertEqual(call["ip__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip__dst"], HOST_A__IP4)
        self.assertEqual(call["udp__sport"], 7)
        self.assertEqual(call["udp__dport"], 54321)
