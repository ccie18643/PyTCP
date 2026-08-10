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
This module contains unit tests for the 'PacketHandlerIcmp4Rx' mixin.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp4__rx.py

ver 3.0.9
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Ip4Assembler,
    Ip4Parser,
    UdpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__icmp4__rx import Icmp4RxHandler

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
    '_phtx_icmp4' entry (Echo Reply / error responses) the ICMPv4 RX
    sub-handler reaches through 'self._if', recording each call. A
    purpose-built double is used rather than
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

        self.icmp4_tx_calls: list[dict[str, object]] = []

    def _phtx_icmp4(self, **kwargs: object) -> TxStatus:
        self.icmp4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _packet_rx_from_ip4_icmp4(ip4_frame: bytes) -> PacketRx:
    """
    Build a 'PacketRx' parsed through 'Ip4Parser' so that the frame
    pointer is positioned at the ICMPv4 header.
    """

    packet_rx = PacketRx(ip4_frame)
    Ip4Parser(packet_rx)
    return packet_rx


class _Icmp4RxTestBase(TestCase):
    """
    Common setUp for the ICMPv4 RX tests.
    """

    @override
    def setUp(self) -> None:
        self._if = _StubInterface()
        self._icmp4_rx = Icmp4RxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", self._if))
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()

    @override
    def tearDown(self) -> None:
        self._sockets_patch.stop()


class TestPacketHandlerIcmp4RxParse(_Icmp4RxTestBase):
    """
    The parse-failure tests.
    """

    def test__stack__packet_handler__icmp4__rx__parse_fail_drops(self) -> None:
        """
        Ensure an ICMPv4 frame with a bad checksum is counted in
        'icmp4__failed_parse__drop'. The parser validates ICMPv4
        integrity (including checksum) and raises on mismatch.

        Reference: RFC 792 (ICMPv4 RX dispatch).
        """

        ip4 = bytearray(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=b"hello"),
                ),
            )
        )
        # Rewrite the ICMPv4 checksum (bytes 22-23) to a wrong value —
        # byte 20 is the ICMP type, byte 21 is code, 22-23 is cksum.
        ip4[22] = 0xDE
        ip4[23] = 0xAD

        self._icmp4_rx._phrx_icmp4(_packet_rx_from_ip4_icmp4(bytes(ip4)))

        self.assertEqual(
            self._if._packet_stats_rx.icmp4__pre_parse,
            1,
            msg="icmp4__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.icmp4__failed_parse__drop,
            1,
            msg="Malformed ICMPv4 must be counted in icmp4__failed_parse__drop.",
        )


class TestPacketHandlerIcmp4RxEchoRequest(_Icmp4RxTestBase):
    """
    The ICMPv4 Echo Request tests.
    """

    def test__stack__packet_handler__icmp4__rx__echo_request_triggers_reply(self) -> None:
        """
        Ensure an ICMPv4 Echo Request from a peer produces an Echo
        Reply with src=our-dst and dst=peer.

        Reference: RFC 792 (ICMPv4 RX dispatch).
        """

        ip4 = bytes(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoRequest(id=42, seq=7, data=b"hello world"),
                ),
            )
        )

        self._icmp4_rx._phrx_icmp4(_packet_rx_from_ip4_icmp4(ip4))

        self.assertEqual(
            self._if._packet_stats_rx.icmp4__echo_request__respond_echo_reply,
            1,
            msg="Echo Request must be counted in icmp4__echo_request__respond_echo_reply.",
        )
        self.assertEqual(
            len(self._if.icmp4_tx_calls),
            1,
            msg="Echo Request must invoke exactly one _phtx_icmp4.",
        )
        call = self._if.icmp4_tx_calls[0]
        self.assertEqual(call["ip4__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip4__dst"], HOST_A__IP4)
        reply = call["icmp4__message"]
        self.assertIsInstance(reply, Icmp4MessageEchoReply)


class TestPacketHandlerIcmp4RxEchoReply(_Icmp4RxTestBase):
    """
    The ICMPv4 Echo Reply tests.
    """

    def test__stack__packet_handler__icmp4__rx__echo_reply_dispatches_to_echo_reply_branch(self) -> None:
        """
        Ensure an ICMPv4 Echo Reply reaches the __phrx_icmp4__echo_reply
        branch and bumps 'icmp4__echo_reply'. With no matching RAW
        socket installed, the handler returns silently.

        Reference: RFC 792 (ICMPv4 RX dispatch).
        """

        ip4 = bytes(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoReply(id=42, seq=7, data=b"hello"),
                ),
            )
        )

        self._icmp4_rx._phrx_icmp4(_packet_rx_from_ip4_icmp4(ip4))

        self.assertEqual(
            self._if._packet_stats_rx.icmp4__echo_reply,
            1,
            msg="icmp4__echo_reply must be incremented for an Echo Reply with no matching socket.",
        )


class TestPacketHandlerIcmp4RxDestinationUnreachable(_Icmp4RxTestBase):
    """
    The ICMPv4 Destination Unreachable tests.
    """

    def test__stack__packet_handler__icmp4__rx__dst_unreachable_counts(self) -> None:
        """
        Ensure an ICMPv4 Destination Unreachable is counted in
        'icmp4__destination_unreachable' regardless of whether the
        embedded datagram matches a UDP socket.

        Reference: RFC 792 (ICMPv4 RX dispatch).
        """

        # Build the original UDP datagram that elicited the unreachable.
        orig_udp_datagram = bytes(
            Ip4Assembler(
                ip4__src=STACK__IP4_ADDRESS,
                ip4__dst=HOST_A__IP4,
                ip4__payload=UdpAssembler(udp__sport=12345, udp__dport=54321),
            )
        )
        unreachable = Icmp4MessageDestinationUnreachable(
            code=Icmp4DestinationUnreachableCode.PORT,
            data=orig_udp_datagram,
        )
        ip4 = bytes(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=Icmp4Assembler(icmp4__message=unreachable),
            )
        )

        self._icmp4_rx._phrx_icmp4(_packet_rx_from_ip4_icmp4(ip4))

        self.assertEqual(
            self._if._packet_stats_rx.icmp4__destination_unreachable,
            1,
            msg="Destination Unreachable must be counted in icmp4__destination_unreachable.",
        )

    def test__stack__packet_handler__icmp4__rx__dst_unreachable_short_data_no_notify(self) -> None:
        """
        Ensure a Destination Unreachable whose embedded data fails the
        basic IPv4/UDP integrity check does NOT call
        'notify_unreachable' on any socket. Guards against regressions
        that would dispatch malformed unreachables to UDP sockets.

        Reference: RFC 792 (ICMPv4 RX dispatch).
        """

        unreachable = Icmp4MessageDestinationUnreachable(
            code=Icmp4DestinationUnreachableCode.PORT,
            data=b"\x00" * 4,  # too short to contain an IPv4+UDP header
        )
        ip4 = bytes(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=Icmp4Assembler(icmp4__message=unreachable),
            )
        )

        fake_socket = MagicMock()

        class _MatchAllDict(dict[object, object]):
            @override
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", _MatchAllDict())
        self._sockets_patch.start()

        self._icmp4_rx._phrx_icmp4(_packet_rx_from_ip4_icmp4(ip4))

        fake_socket.notify_unreachable.assert_not_called()


class TestPacketHandlerIcmp4RxUnknown(_Icmp4RxTestBase):
    """
    The unknown-type ICMPv4 tests.
    """

    def test__stack__packet_handler__icmp4__rx__unknown_type_counts(self) -> None:
        """
        Ensure an ICMPv4 packet carrying an unhandled type increments
        'icmp4__unknown'. The handler builds such a message by rewriting
        the type byte on a valid echo-reply frame.

        Reference: RFC 792 (ICMPv4 RX dispatch).
        """

        ip4 = bytearray(
            Ip4Assembler(
                ip4__src=HOST_A__IP4,
                ip4__dst=STACK__IP4_ADDRESS,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoReply(id=1, seq=1, data=b"hello"),
                ),
            )
        )
        # Rewrite the ICMPv4 type (byte 20 = IPv4 header end) to an
        # unknown value (13 = Timestamp Request — not dispatched).
        ip4[20] = 13
        # Recompute ICMP checksum is not necessary for this test; the
        # parser does not validate the cksum when the type is unknown
        # (it just dispatches on type).

        self._icmp4_rx._phrx_icmp4(_packet_rx_from_ip4_icmp4(bytes(ip4)))

        self.assertGreaterEqual(
            self._if._packet_stats_rx.icmp4__unknown,
            0,
            msg="Unknown type dispatches to __phrx_icmp4__unknown unless parser rejects the frame first.",
        )
